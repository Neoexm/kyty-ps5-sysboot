#include "graphics/host_gpu/renderer/renderContext.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "common/timer.h"
#include "graphics/guest_gpu/graphicsRun.h"
#include "graphics/presentation/videoOut.h"
#include "libs/errno.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>

namespace Libs::Graphics {

RenderContext::RenderContext(GraphicContext& graphics)
    : m_graphics(graphics), m_render_executor(*this), m_command_scheduler(*this, graphics),
      m_descriptor_heap(graphics, m_command_scheduler.GetMasterSemaphore()),
      m_pipeline_cache(graphics), m_sampler_cache(graphics),
      m_buffer_cache(graphics, m_command_scheduler, m_page_manager, m_texture_cache),
      m_texture_cache(graphics, m_command_scheduler, m_page_manager, m_buffer_cache) {
	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
}

RenderContext::~RenderContext() {
	ShutdownGpu();
	m_command_scheduler.Shutdown();
}

void RenderContext::InitializeGpu(VideoOut::VideoOutDriver* video_out) {
	EXIT_IF(m_gpu != nullptr);
	m_video_out = video_out;
	m_gpu       = std::make_unique<GuestGpu>(*this);
}

void RenderContext::ShutdownGpu() {
	if (m_gpu != nullptr) {
		m_gpu->Shutdown();
		m_gpu.reset();
	}
	if (m_video_out != nullptr) {
		if (m_command_scheduler.Active()) {
			m_command_scheduler.Finish();
		}
		m_command_scheduler.DrainPriorityOperations();
		m_video_out = nullptr;
	}
}

GuestGpu& RenderContext::GetGpu() const {
	EXIT_IF(m_gpu == nullptr);
	return *m_gpu;
}

VideoOut::VideoOutDriver& RenderContext::GetVideoOut() const {
	EXIT_IF(m_video_out == nullptr);
	return *m_video_out;
}

bool RenderContext::HandleFault(PageFaultAccess access, uint64_t fault_vaddr) noexcept {
	// The host reports the faulting byte, not the instruction's access width. Both caches
	// resolve its page; guessing a width can cross the end of a valid guest mapping.
	constexpr uint64_t fault_size = 1;
	if (!IsMapped(fault_vaddr, fault_size)) {
		return false;
	}
	if (access == PageFaultAccess::Write) {
		m_buffer_cache.InvalidateMemory(fault_vaddr, fault_size);
		m_texture_cache.InvalidateMemory(fault_vaddr, fault_size);
	} else {
		m_buffer_cache.ReadMemory(fault_vaddr, fault_size);
	}
	return true;
}

bool RenderContext::InvalidateMemory(uint64_t vaddr, uint64_t size) {
	if (!IsMapped(vaddr, size)) {
		return false;
	}
	m_buffer_cache.InvalidateMemory(vaddr, size);
	m_texture_cache.InvalidateMemory(vaddr, size);
	return true;
}

bool RenderContext::IsMapped(uint64_t vaddr, uint64_t size) const noexcept {
	if (!GuestRange {vaddr, size}.Valid()) {
		return false;
	}
	std::shared_lock lock(m_mapped_ranges_mutex);
	return m_mapped_ranges.Contains(vaddr, size);
}

void RenderContext::MapMemory(uint64_t vaddr, uint64_t size, bool cross_process) {
	{
		std::lock_guard lock(m_mapped_ranges_mutex);
		m_mapped_ranges.Add(vaddr, size);
		m_mapped_ranges_snapshot_dirty = true;
	}
	if (cross_process) {
		m_buffer_cache.RegisterCrossProcessMemory(vaddr, size);
	}
}

void RenderContext::UnmapMemory(uint64_t vaddr, uint64_t size) {
	if (CommandScheduler::InDeferredOperation()) {
		EXIT("unsupported memory unmap from an asynchronous GPU completion, "
		     "addr=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
		     vaddr, size);
	}
	const auto unmap = [this, vaddr, size] {
		// Check cache ownership on the GPU thread. Guest-memory callbacks can still
		// access a range with no cached data, so they must finish before it is unmapped.
		if (m_command_scheduler.Active() &&
		    (m_buffer_cache.IsRegionRegistered(vaddr, size) ||
		     m_texture_cache.IsRegionRegistered(vaddr, size) ||
		     m_command_scheduler.HasPendingPriorityOperations())) {
			const auto tick = m_command_scheduler.CurrentTick();
			m_command_scheduler.Finish();
			m_command_scheduler.WaitPriorityOperations(tick);
		}
		m_buffer_cache.InvalidateMemory(vaddr, size);
		m_texture_cache.UnmapMemory(vaddr, size);
		m_buffer_cache.UnregisterCrossProcessMemory(vaddr, size);
		std::lock_guard lock(m_mapped_ranges_mutex);
		m_mapped_ranges.Subtract(vaddr, size);
		m_mapped_ranges_snapshot_dirty = true;
	};
	// Shutdown still owns the GPU while queued rendering drains, but its command lane no
	// longer accepts external work. Use the guest GPU's state for the teardown route.
	if (m_gpu == nullptr || m_gpu->IsStopping()) {
		unmap();
		return;
	}
	m_gpu->SendCommandSync(unmap);
}

void RenderContext::SetCrossProcessMemory(uint64_t vaddr, uint64_t size, bool cross_process) {
	const auto update = [this, vaddr, size, cross_process] {
		if (cross_process) {
			m_buffer_cache.RegisterCrossProcessMemory(vaddr, size);
		} else {
			m_buffer_cache.UnregisterCrossProcessMemory(vaddr, size);
		}
	};
	if (m_gpu == nullptr || m_gpu->IsStopping()) {
		update();
		return;
	}
	m_gpu->SendCommandSync(update);
}

void RenderContext::AdvanceCrossProcessEpoch() {
	m_buffer_cache.AdvanceCrossProcessEpoch();
}

void RenderContext::PrepareBda() {
	if (!m_bda_logged) {
		Log::WriteToConsoleAndLog("GPU: using buffer device address (BDA) shader memory access.\n");
		m_bda_logged = true;
	}
	m_buffer_cache.EnsureBdaResources();
	static const bool timing = std::getenv("KYTY_DIAGNOSTIC_GPU_SLICE_TIMING") != nullptr;
	const auto        begin  = timing ? Common::Timer::QueryPerformanceCounter() : 0;
	{
		std::lock_guard lock(m_mapped_ranges_mutex);
		if (m_mapped_ranges_snapshot_dirty) {
			m_mapped_ranges_snapshot.clear();
			m_mapped_ranges.ForEach([&](uint64_t start, uint64_t end) {
				m_mapped_ranges_snapshot.push_back({start, end - start});
			});
			m_mapped_ranges_snapshot_dirty = false;
		}
	}
	for (const auto& range: m_mapped_ranges_snapshot) {
		m_buffer_cache.SynchronizeBuffersInRange(range.address, range.size);
	}
	m_fault_process_pending = true;
	if (timing) {
		static std::atomic_uint logged = 0;
		const auto us = (Common::Timer::QueryPerformanceCounter() - begin) * 1000000 /
		                Common::Timer::QueryPerformanceFrequency();
		if (us >= 500 && logged.fetch_add(1) < 4000) {
			LOGF("FIRST_FRAME_AUDIT GPU_SLICE_TIMING prepare_bda us=%" PRIu64 " ranges=%zu\n", us,
			     m_mapped_ranges_snapshot.size());
		}
	}
}

void RenderContext::RunGarbageCollector() {
	static const bool timing = std::getenv("KYTY_DIAGNOSTIC_GPU_SLICE_TIMING") != nullptr;
	const auto        begin  = timing ? Common::Timer::QueryPerformanceCounter() : 0;
	const bool        faults = m_fault_process_pending;
	if (m_fault_process_pending) {
		m_fault_process_pending = false;
		m_buffer_cache.ProcessFaultBuffer();
	}
	const auto mid = timing ? Common::Timer::QueryPerformanceCounter() : 0;
	m_texture_cache.ProcessDownloadImages();
	m_texture_cache.RunGarbageCollector();
	m_buffer_cache.RunGarbageCollector();
	if (timing) {
		static std::atomic_uint logged = 0;
		const auto freq = Common::Timer::QueryPerformanceFrequency();
		const auto end  = Common::Timer::QueryPerformanceCounter();
		const auto us   = (end - begin) * 1000000 / freq;
		if (us >= 500 && logged.fetch_add(1) < 4000) {
			LOGF("FIRST_FRAME_AUDIT GPU_SLICE_TIMING gc us=%" PRIu64 " fault_us=%" PRIu64
			     " faults=%u\n",
			     us, (mid - begin) * 1000000 / freq, faults ? 1u : 0u);
		}
	}
}

void RenderContext::AddInterruptEq(LibKernel::EventQueue::KernelEqueue eq, int event_id) {
	Common::LockGuard lock(m_interrupt_mutex);

	auto it = std::find_if(
	    m_interrupt_eqs.begin(), m_interrupt_eqs.end(),
	    [eq, event_id](const auto& entry) { return entry.eq == eq && entry.event_id == event_id; });
	if (it != m_interrupt_eqs.end()) {
		return;
	}

	m_interrupt_eqs.push_back({eq, event_id});
	if (std::getenv("KYTY_DIAGNOSTIC_GPU_EOP_AUDIT") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT GPU_EOP_REGISTER queue=0x%016" PRIx64 " event_id=%d total=%zu\n",
		     static_cast<uint64_t>(eq), event_id, m_interrupt_eqs.size());
	}
}

void RenderContext::DeleteInterruptEq(LibKernel::EventQueue::KernelEqueue eq, int event_id) {
	Common::LockGuard lock(m_interrupt_mutex);

	auto it = std::find_if(
	    m_interrupt_eqs.begin(), m_interrupt_eqs.end(),
	    [eq, event_id](const auto& entry) { return entry.eq == eq && entry.event_id == event_id; });
	if (it == m_interrupt_eqs.end()) {
		return;
	}

	m_interrupt_eqs.erase(it);
}

void RenderContext::TriggerInterrupt(int event_id, uint32_t context_id) {
	std::vector<InterruptEqRegistration> registrations;
	{
		Common::LockGuard lock(m_interrupt_mutex);
		for (const auto& registration: m_interrupt_eqs) {
			if (registration.event_id == event_id) {
				registrations.push_back(registration);
			}
		}
	}

	if (std::getenv("KYTY_DIAGNOSTIC_GPU_EOP_AUDIT") != nullptr) {
		static std::atomic_uint logged = 0;
		if (logged.fetch_add(1) < 36) {
			LOGF("FIRST_FRAME_AUDIT GPU_EOP_TRIGGER event_id=%d ctx=%u matching_queues=%zu\n",
			     event_id, context_id, registrations.size());
		}
	}
	for (const auto& registration: registrations) {
		const auto result = LibKernel::EventQueue::KernelTriggerEvent(
		    registration.eq, static_cast<uintptr_t>(registration.event_id),
		    LibKernel::EventQueue::KERNEL_EVFILT_GRAPHICS,
		    reinterpret_cast<void*>(static_cast<uintptr_t>(context_id)));
		if (result == LibKernel::KERNEL_ERROR_EBADF || result == LibKernel::KERNEL_ERROR_ENOENT) {
			DeleteInterruptEq(registration.eq, registration.event_id);
			continue;
		}
		EXIT_NOT_IMPLEMENTED(result != OK);
	}
}

} // namespace Libs::Graphics
