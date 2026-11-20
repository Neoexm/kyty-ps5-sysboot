#include "graphics/host_gpu/renderer/cache/bufferCache.h"

#include "common/alignment.h"
#include "common/assert.h"
#include "common/logging/log.h"
#include "common/profiler.h"
#include "common/timer.h"
#include "graphics/guest_gpu/graphicsRun.h"
#include "graphics/host_gpu/graphicContext.h"
#include "graphics/host_gpu/renderer/cache/textureCache.h"
#include "graphics/host_gpu/renderer/commandScheduler.h"
#include "graphics/host_gpu/renderer/render.h"
#include "graphics/host_gpu/renderer/renderContext.h"
#include "graphics/host_gpu/vulkanCommon.h"
#include "kernel/memory.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include <xxhash.h>

namespace Libs::Graphics {

namespace {

constexpr uint64_t MiB           = 1024 * 1024;
constexpr uint64_t GdsBufferSize = 64 * 1024;

} // namespace

void BufferCache::WriteDataBuffer(Buffer& buffer, uint64_t address, const void* source,
                                  uint64_t size) {
	auto* bytes   = static_cast<const uint8_t*>(source);
	auto& staging = GetUtilityBuffer(MemoryUsage::Upload);
	while (size != 0) {
		const auto chunk  = std::min(size, staging.Size());
		const auto offset = staging.Copy(bytes, chunk, 4);
		buffer.CopyFrom(m_scheduler.Current(), staging, offset, buffer.Offset(address),
		                chunk, vk::AccessFlagBits::eHostWrite);
		bytes += chunk;
		address += chunk;
		size -= chunk;
	}
}

void BufferCache::Register(BufferId id) {
	ChangeRegister<true>(id);
}

void BufferCache::Unregister(BufferId id) {
	ChangeRegister<false>(id);
}

template <bool insert>
void BufferCache::ChangeRegister(BufferId id) {
	auto& buffer = m_slot_buffers[id];
	PageTable::PageRange pages {};
	EXIT_IF(!(GuestRange {buffer.CpuAddress(), buffer.Size()}.Valid()) ||
	        !PageTable::TryGetPageRange(buffer.CpuAddress(), buffer.Size(), pages));
	for (size_t page = pages.first; page < pages.last_exclusive; ++page) {
		if constexpr (insert) {
			m_page_table[page] = id;
		} else {
			m_page_table[page] = {};
		}
	}
	const auto size_pages = pages.last_exclusive - pages.first;
	const auto table_offset = PageIndex(buffer.CpuAddress()) * sizeof(vk::DeviceAddress);
	if constexpr (insert) {
		const auto [it, inserted] = m_buffers.emplace(buffer.CpuAddress(), id);
		(void)it;
		EXIT_IF(!inserted);
		m_total_used_memory += buffer.Size();
		buffer.lru_id = m_lru_cache.Insert(id, m_gc_tick);
		std::vector<vk::DeviceAddress> addresses;
		addresses.reserve(size_pages);
		for (uint64_t i = 0; i < size_pages; ++i) {
			addresses.push_back(buffer.BufferDeviceAddress() + (i << CACHING_PAGEBITS));
		}
		if (m_bda_pagetable_buffer) {
			WriteDataBuffer(*m_bda_pagetable_buffer, table_offset,
			                addresses.data(), addresses.size() * sizeof(vk::DeviceAddress));
		}
	} else {
		const auto found = m_buffers.find(buffer.CpuAddress());
		EXIT_IF(found == m_buffers.end() || found->second != id);
		m_buffers.erase(found);
		EXIT_IF(buffer.Size() > m_total_used_memory);
		m_total_used_memory -= buffer.Size();
		m_lru_cache.Free(buffer.lru_id);
		if (m_bda_pagetable_buffer) {
			m_bda_pagetable_buffer->Fill(table_offset,
			                             size_pages * sizeof(vk::DeviceAddress), 0);
		}
		buffer.is_deleted = true;
	}
}

void BufferCache::TouchBuffer(const Buffer& buffer) {
	if (!buffer.is_deleted) {
		m_lru_cache.Touch(buffer.lru_id, m_gc_tick);
	}
}

std::vector<GuestRange> BufferCache::CrossProcessRangesIn(uint64_t vaddr, uint64_t size) const {
	std::vector<GuestRange> ranges;
	if (!m_cross_process_ranges_present.load(std::memory_order_acquire) ||
	    !GuestRange {vaddr, size}.Valid()) {
		return ranges;
	}
	std::shared_lock lock(m_cross_process_mutex);
	m_cross_process_ranges.ForEachInRange(
	    vaddr, size, [&](uint64_t begin, uint64_t end) { ranges.push_back({begin, end - begin}); });
	return ranges;
}

void BufferCache::RegisterCrossProcessMemory(uint64_t vaddr, uint64_t size) {
	if (!GuestRange {vaddr, size}.Valid()) {
		return;
	}
	{
		std::lock_guard lock(m_cross_process_mutex);
		m_cross_process_ranges.Add(vaddr, size);
		m_cross_process_ranges_present.store(true, std::memory_order_release);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SHARED_REFRESH") != nullptr) {
		static std::atomic_uint64_t registrations = 0;
		const auto                  ordinal       = registrations.fetch_add(1) + 1;
		if (ordinal <= 128 || (ordinal & (ordinal - 1)) == 0) {
			LOGF("FIRST_FRAME_AUDIT SHARED_REFRESH_REGISTERED addr=0x%016" PRIx64
			     " size=0x%016" PRIx64 " ordinal=%" PRIu64 "\n",
			     vaddr, size, ordinal);
		}
	}
}

void BufferCache::UnregisterCrossProcessMemory(uint64_t vaddr, uint64_t size) {
	if (!GuestRange {vaddr, size}.Valid()) {
		return;
	}
	const auto begin = Common::AlignDown(vaddr, TRACKER_PAGE_SIZE);
	const auto end   = Common::AlignUp(vaddr + size, TRACKER_PAGE_SIZE);
	{
		std::lock_guard range_lock(m_cross_process_mutex);
		m_cross_process_ranges.Subtract(vaddr, size);
		m_cross_process_ranges_present.store(!m_cross_process_ranges.Empty(),
		                                     std::memory_order_release);
	}
	std::lock_guard  page_lock(m_cross_process_page_mutex);
	std::shared_lock range_lock(m_cross_process_mutex);
	for (auto page = begin; page < end; page += TRACKER_PAGE_SIZE) {
		if (!m_cross_process_ranges.Intersects(page, TRACKER_PAGE_SIZE)) {
			m_cross_process_pages.erase(page);
		}
	}
}

void BufferCache::AdvanceCrossProcessEpoch() {
	std::lock_guard lock(m_cross_process_page_mutex);
	if (++m_cross_process_epoch == 0) {
		m_cross_process_epoch = 1;
		for (auto& [page, state]: m_cross_process_pages) {
			(void)page;
			state.validated_epoch = 0;
		}
	}
}

uint64_t BufferCache::CrossProcessGeneration(uint64_t vaddr, uint64_t size) const {
	uint64_t        generation = 0;
	const auto      ranges     = CrossProcessRangesIn(vaddr, size);
	std::lock_guard lock(m_cross_process_page_mutex);
	for (const auto& range: ranges) {
		const auto begin = Common::AlignDown(range.address, TRACKER_PAGE_SIZE);
		const auto end   = Common::AlignUp(range.End(), TRACKER_PAGE_SIZE);
		for (auto page = begin; page < end; page += TRACKER_PAGE_SIZE) {
			if (const auto it = m_cross_process_pages.find(page);
			    it != m_cross_process_pages.end() && it->second.valid) {
				generation = std::max(generation, it->second.generation);
			}
		}
	}
	return generation;
}

struct CrossProcessHashJob {
	uint64_t page = 0;
	uint64_t hash = 0;
	bool     read = false;
};

// Hashes straight from the backing view and takes the address-space locks once per run of pages instead of copying each page out.
static void HashCrossProcessPages(std::vector<CrossProcessHashJob>& jobs) {
	constexpr size_t chunk_pages = 64;
	for (size_t i = 0; i < jobs.size();) {
		size_t n = 1;
		while (n < chunk_pages && i + n < jobs.size() &&
		       jobs[i + n].page == jobs[i].page + n * TRACKER_PAGE_SIZE) {
			n++;
		}
		auto* chunk = jobs.data() + i;
		i += n;
		if (Libs::LibKernel::Memory::TryVisitSparseBackingPages(
		        chunk->page, n, TRACKER_PAGE_SIZE,
		        [](void* context, uint64_t index, const uint8_t* bytes) {
			        auto& job = static_cast<CrossProcessHashJob*>(context)[index];
			        job.hash  = XXH3_64bits(bytes, TRACKER_PAGE_SIZE);
			        job.read  = true;
		        },
		        chunk)) {
			continue;
		}
		std::array<uint8_t, TRACKER_PAGE_SIZE> bytes {};
		for (size_t k = 0; k < n; k++) {
			if (Libs::LibKernel::Memory::TryReadSparseBacking(chunk[k].page, bytes.data(), bytes.size())) {
				chunk[k].hash = XXH3_64bits(bytes.data(), bytes.size());
				chunk[k].read = true;
			}
		}
	}
}

BufferCache::CrossProcessValidation
BufferCache::ValidateCrossProcessMemory(uint64_t vaddr, uint64_t size, bool force) {
	static std::atomic_uint64_t changes       = 0;
	static std::atomic_uint64_t conflicts     = 0;
	static std::atomic_uint64_t resolved      = 0;
	static std::atomic_uint64_t read_failures = 0;
	CrossProcessValidation      result {};
	const auto                  ranges = CrossProcessRangesIn(vaddr, size);
	if (ranges.empty()) {
		return result;
	}
	const bool audit          = std::getenv("KYTY_DIAGNOSTIC_SHARED_REFRESH") != nullptr;
	result.intersects         = true;
	uint64_t        last_page = UINT64_MAX;
	static const bool timing  = std::getenv("KYTY_DIAGNOSTIC_GPU_SLICE_TIMING") != nullptr;
	const auto      t_begin   = timing ? Common::Timer::QueryPerformanceCounter() : 0;
	uint64_t        visited   = 0;
	uint64_t        gpu_pages = 0;
	uint64_t        changed   = 0;
	std::vector<CrossProcessHashJob> jobs;
	std::vector<std::pair<CrossProcessPage*, bool>> job_states;
	std::lock_guard lock(m_cross_process_page_mutex);
	for (const auto& range: ranges) {
		const auto begin = Common::AlignDown(range.address, TRACKER_PAGE_SIZE);
		const auto end   = Common::AlignUp(range.End(), TRACKER_PAGE_SIZE);
		for (auto page = begin; page < end; page += TRACKER_PAGE_SIZE) {
			if (page == last_page) {
				continue;
			}
			last_page   = page;
			visited++;
			auto& state = m_cross_process_pages[page];
			if (state.valid) {
				result.generation = std::max(result.generation, state.generation);
			}
			const bool gpu_modified = m_memory_tracker.IsRegionGpuModified(page, TRACKER_PAGE_SIZE);
			gpu_pages += gpu_modified ? 1 : 0;
			if (state.pending_cpu_refresh && !gpu_modified) {
				state.pending_cpu_refresh = false;
				m_memory_tracker.MarkRegionAsCpuModified(page, TRACKER_PAGE_SIZE);
				const auto ordinal = resolved.fetch_add(1) + 1;
				if (audit && (ordinal <= 32 || (ordinal & (ordinal - 1)) == 0)) {
					LOGF("FIRST_FRAME_AUDIT SHARED_REFRESH_GPU_RESOLVED addr=0x%016" PRIx64
					     " generation=%" PRIu64 " ordinal=%" PRIu64 "\n",
					     page, state.generation, ordinal);
				}
			}
			if (!force && state.validated_epoch == m_cross_process_epoch) {
				result.gpu_conflict |= gpu_modified;
				continue;
			}
			jobs.push_back({page});
			job_states.emplace_back(&state, gpu_modified);
		}
	}
	HashCrossProcessPages(jobs);
	for (size_t i = 0; i < jobs.size(); i++) {
		const auto page               = jobs[i].page;
		auto& state                   = *job_states[i].first;
		const bool gpu_modified       = job_states[i].second;
		if (!jobs[i].read) {
			bool registered = false;
			{
				std::shared_lock range_lock(m_cross_process_mutex);
				registered = m_cross_process_ranges.Intersects(page, TRACKER_PAGE_SIZE);
			}
			if (!registered) {
				m_cross_process_pages.erase(page);
				continue;
			}
			const auto ordinal = read_failures.fetch_add(1) + 1;
			if (ordinal <= 32 || (ordinal & (ordinal - 1)) == 0) {
				LOGF("FIRST_FRAME_AUDIT SHARED_REFRESH_READ_FAILED addr=0x%016" PRIx64
				     " epoch=%" PRIu64 " ordinal=%" PRIu64 "\n",
				     page, m_cross_process_epoch, ordinal);
			}
			continue;
		}
		const auto hash       = jobs[i].hash;
		state.validated_epoch = m_cross_process_epoch;
		if (state.valid && state.hash == hash) {
			result.gpu_conflict |= gpu_modified;
			continue;
		}
		const bool first  = !state.valid;
		changed++;
		state.hash        = hash;
		state.valid       = true;
		state.generation  = ++m_cross_process_generation;
		result.generation = std::max(result.generation, state.generation);
		if (gpu_modified) {
			state.pending_cpu_refresh = true;
			result.gpu_conflict       = true;
			const auto ordinal        = conflicts.fetch_add(1) + 1;
			if (ordinal <= 32 || (ordinal & (ordinal - 1)) == 0) {
				LOGF("FIRST_FRAME_AUDIT SHARED_REFRESH_GPU_CONFLICT addr=0x%016" PRIx64
				     " generation=%" PRIu64 " ordinal=%" PRIu64 "\n",
				     page, state.generation, ordinal);
			}
			continue;
		}
		state.pending_cpu_refresh = false;
		m_memory_tracker.MarkRegionAsCpuModified(page, TRACKER_PAGE_SIZE);
		const auto ordinal = changes.fetch_add(1) + 1;
		if (audit && (ordinal <= 128 || (ordinal & (ordinal - 1)) == 0)) {
			LOGF("FIRST_FRAME_AUDIT SHARED_REFRESH_CHANGED addr=0x%016" PRIx64
			     " first=%d generation=%" PRIu64 " epoch=%" PRIu64 " ordinal=%" PRIu64 "\n",
			     page, first ? 1 : 0, state.generation, m_cross_process_epoch, ordinal);
		}
	}
	if (timing) {
		static std::atomic_uint logged = 0;
		const auto us = (Common::Timer::QueryPerformanceCounter() - t_begin) * 1000000 /
		                Common::Timer::QueryPerformanceFrequency();
		if (us >= 500 && logged.fetch_add(1) < 4000) {
			LOGF("FIRST_FRAME_AUDIT GPU_SLICE_TIMING xproc_validate us=%" PRIu64 " visited=%" PRIu64
			     " hashed=%zu changed=%" PRIu64 " gpu_pages=%" PRIu64 " force=%d addr=0x%016" PRIx64
			     " size=0x%" PRIx64 "\n",
			     us, visited, jobs.size(), changed, gpu_pages, force ? 1 : 0, vaddr, size);
		}
	}
	return result;
}

void BufferCache::StampCrossProcessMemory(uint64_t vaddr, uint64_t size) {
	const auto      ranges = CrossProcessRangesIn(vaddr, size);
	std::lock_guard lock(m_cross_process_page_mutex);
	for (const auto& range: ranges) {
		const auto begin = Common::AlignDown(range.address, TRACKER_PAGE_SIZE);
		const auto end   = Common::AlignUp(range.End(), TRACKER_PAGE_SIZE);
		for (auto page = begin; page < end; page += TRACKER_PAGE_SIZE) {
			std::array<uint8_t, TRACKER_PAGE_SIZE> bytes {};
			if (!Libs::LibKernel::Memory::TryReadSparseBacking(page, bytes.data(), bytes.size())) {
				continue;
			}
			auto& state               = m_cross_process_pages[page];
			state.hash                = XXH3_64bits(bytes.data(), bytes.size());
			state.valid               = true;
			state.validated_epoch     = m_cross_process_epoch;
			state.pending_cpu_refresh = false;
		}
	}
}

void BufferCache::AcknowledgeCrossProcessWrite(uint64_t vaddr, uint64_t size) {
	if (GuestRange {vaddr, size}.Valid()) {
		StampCrossProcessMemory(vaddr, size);
	}
}

void BufferCache::DeleteBuffer(BufferId id) {
	if (IsBufferInvalid(id)) {
		return;
	}
	Unregister(id);
	if (m_scheduler.Active()) {
		m_scheduler.DeferOperation([this, id] { m_slot_buffers.erase(id); });
	} else {
		m_slot_buffers.erase(id);
	}
}

template <bool async>
bool BufferCache::DownloadBufferMemory(Buffer& buffer, uint64_t vaddr, uint64_t size) {
	std::vector<vk::BufferCopy> copies;
	uint64_t                    total_size     = 0;
	const auto                  buffer_address = buffer.CpuAddress();
	m_memory_tracker.ForEachDownloadRange<false>(
	    vaddr, size, [&](uint64_t address, uint64_t bytes) noexcept {
		    m_memory_tracker.ValidateGpuDirtyPages(m_gpu_modified_ranges, address, bytes,
		                                           "buffer download");
		    m_gpu_modified_ranges.ForEachInRange(address, bytes, [&](uint64_t start, uint64_t end) {
			    copies.emplace_back(start - buffer_address, total_size, end - start);
			    // Keep packed ranges on separate cache lines, as in shadPS4.
			    total_size += Common::AlignUp(end - start, 64);
		    });
		    m_gpu_modified_ranges.Subtract(address, bytes);
	    });
	if (copies.empty()) {
		return false;
	}

	auto& ring            = GetUtilityBuffer(MemoryUsage::Download);
	auto [mapped, offset] = ring.Map(total_size, 64);
	std::unique_ptr<Buffer> temporary;
	if (mapped == nullptr) {
		temporary = std::make_unique<Buffer>(m_graphics, m_scheduler, MemoryUsage::Download, 0,
		                                     vk::BufferUsageFlagBits::eTransferDst, total_size);
		mapped = temporary->Mapped().data();
	} else {
		ring.Commit();
	}
	const auto& download = temporary ? *temporary : ring;
	for (auto& copy: copies) {
		copy.dstOffset += offset;
	}

	auto& command = m_scheduler.Current();
	command.EndRendering();
	const auto              native = command.Handle();
	vk::BufferMemoryBarrier before {};
	before.srcAccessMask       = vk::AccessFlagBits::eMemoryRead | vk::AccessFlagBits::eMemoryWrite;
	before.dstAccessMask       = vk::AccessFlagBits::eTransferRead;
	before.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
	before.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
	before.buffer              = buffer.Handle();
	before.offset              = 0;
	before.size                = buffer.Size();
	native.pipelineBarrier(vk::PipelineStageFlagBits::eAllCommands,
	                       vk::PipelineStageFlagBits::eTransfer, {}, 0, nullptr, 1, &before, 0,
	                       nullptr);
	native.copyBuffer(buffer.Handle(), download.Handle(),
	                  static_cast<uint32_t>(copies.size()), copies.data());

	auto after          = before;
	after.srcAccessMask = vk::AccessFlagBits::eTransferWrite;
	after.dstAccessMask = vk::AccessFlagBits::eHostRead;
	after.buffer        = download.Handle();
	after.offset        = offset;
	after.size          = total_size;
	native.pipelineBarrier(vk::PipelineStageFlagBits::eTransfer,
	                       vk::PipelineStageFlagBits::eAllCommands |
	                           vk::PipelineStageFlagBits::eHost,
	                       {}, 0, nullptr, 1, &after, 0, nullptr);
	auto publish = [this, &ring, mapped, offset, total_size, buffer_address,
	                copies = std::move(copies), owner = std::move(temporary)] {
		(owner ? *owner : ring).Invalidate(offset, total_size);
		for (const auto& copy: copies) {
			Libs::LibKernel::Memory::WriteBacking(buffer_address + copy.srcOffset,
			                                      mapped + (copy.dstOffset - offset), copy.size);
			AcknowledgeCrossProcessWrite(buffer_address + copy.srcOffset, copy.size);
		}
	};
	if constexpr (async) {
		m_scheduler.DeferPriorityOperation(std::move(publish));
	} else {
		const auto tick = m_scheduler.CurrentTick();
		m_scheduler.Wait(tick);
		m_scheduler.WaitPriorityOperations(tick);
		publish();
	}
	return true;
}

BufferCache::BufferCache(GraphicContext& graphics, CommandScheduler& scheduler,
                         PageManager& page_manager, TextureCache& texture_cache)
    : m_graphics(graphics), m_scheduler(scheduler),
      m_gds_buffer(graphics, scheduler, MemoryUsage::Stream, 0, AllFlags, GdsBufferSize),
      m_memory_tracker(page_manager),
      m_texture_cache(texture_cache) {
	std::memset(m_gds_buffer.Mapped().data(), 0, static_cast<size_t>(m_gds_buffer.Size()));
	m_gds_buffer.Flush(0, m_gds_buffer.Size());
	const auto null_id =
	    m_slot_buffers.insert(m_graphics, m_scheduler, MemoryUsage::DeviceLocal, 0, AllFlags, 16);
	EXIT_IF(null_id != NULL_BUFFER_ID);
	SetVulkanObjectNameF(m_graphics.device, GetBuffer(null_id).Handle(), "Kyty.NullBuffer");
	if (!m_graphics.CanReportMemoryUsage()) {
		return;
	}
	constexpr int64_t GiB              = 1024ll * 1024 * 1024;
	constexpr int64_t target_threshold = 8 * GiB;
	const auto        budget =
	    static_cast<int64_t>(std::min<uint64_t>(m_graphics.GetTotalMemoryBudget(), INT64_MAX));
	const auto threshold = std::min(budget, target_threshold);
	const auto expected  = std::min(budget - 6 * threshold / 10, budget - GiB);
	const auto critical  = std::min(budget - 2 * threshold / 10, budget - GiB / 2);
	m_trigger_gc_memory  = static_cast<uint64_t>(std::max<int64_t>(expected, GiB));
	m_critical_gc_memory = static_cast<uint64_t>(std::max<int64_t>(critical, 2 * GiB));
}

BufferCache::~BufferCache() {
	if (!m_gpu_modified_ranges.Empty()) {
		EXIT("BufferCache: destroyed with pending GPU-modified ranges\n");
	}
	for (const auto& [vaddr, id]: m_buffers) {
		(void)vaddr;
		const auto& buffer = m_slot_buffers[id];
		if (m_memory_tracker.IsRegionGpuModified(buffer.CpuAddress(), buffer.Size())) {
			EXIT("BufferCache: destroyed with GPU-modified buffer\n");
		}
	}
	m_buffers.clear();
}

void BufferCache::InvalidateMemory(uint64_t vaddr, uint64_t size) {
	if (!GuestRange {vaddr, size}.Valid()) {
		EXIT("BufferCache: invalid memory-invalidation range\n");
	}
	m_memory_tracker.InvalidateRegion(vaddr, size,
	                                  [this, vaddr, size] { ReadMemory(vaddr, size, true); });
}

void BufferCache::ReadMemory(uint64_t vaddr, uint64_t size, bool is_write) {
	if (!GuestGpu::IsGpuThread() && CommandScheduler::InDeferredOperation()) {
		EXIT("unsupported buffer readback from an asynchronous GPU completion, "
		     "addr=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
		     vaddr, size);
	}
	m_scheduler.Context().GetGpu().SendCommandSync([this, vaddr, size, is_write] {
		if (is_write && !IsRegionRegistered(vaddr, size)) {
			return;
		}
		auto& buffer = m_slot_buffers[FindBuffer(vaddr, size)];

		if (DownloadBufferMemory<false>(buffer, vaddr, size)) {
			m_memory_tracker.UnmarkRegionAsGpuModified(vaddr, size);
		}
		if (is_write) {
			m_memory_tracker.MarkRegionAsCpuModified(vaddr, size);
		}
	});
}

void BufferCache::WritebackGpuMemory() {
	EXIT_IF(!GuestGpu::IsGpuThread());
	std::vector<BufferId> dirty_buffers;
	auto                  remaining = m_gpu_modified_ranges;
	for (const auto& [address, id]: m_buffers) {
		auto&      buffer          = m_slot_buffers[id];
		const bool has_dirty_bytes = m_gpu_modified_ranges.Intersects(address, buffer.Size());
		const bool has_dirty_pages = m_memory_tracker.IsRegionGpuModified(address, buffer.Size());
		if (has_dirty_bytes != has_dirty_pages) {
			EXIT("NATIVE_RELEASE_MEM_REJECTED reason=buffer_ownership address=%016" PRIx64 "\n",
			     address);
		}
		if (!has_dirty_bytes) {
			continue;
		}
		m_gpu_modified_ranges.ForEachInRange(
		    address, buffer.Size(), [this](uint64_t begin, uint64_t end) {
			    if (!m_scheduler.Context().IsMapped(begin, end - begin) ||
				    !LibKernel::Memory::CanWriteGpuBacking(begin, end - begin)) {
				    EXIT("NATIVE_RELEASE_MEM_REJECTED reason=buffer_backing address=%016" PRIx64
					     " size=%016" PRIx64 "\n",
					     begin, end - begin);
			    }
		    });
		remaining.Subtract(address, buffer.Size());
		dirty_buffers.push_back(id);
	}
	if (!remaining.Empty()) {
		EXIT("NATIVE_RELEASE_MEM_REJECTED reason=buffer_ownership unbound_dirty_bytes\n");
	}

	for (const auto id: dirty_buffers) {
		auto& buffer = m_slot_buffers[id];
		if (!DownloadBufferMemory<true>(buffer, buffer.CpuAddress(), buffer.Size())) {
			EXIT("NATIVE_RELEASE_MEM_REJECTED reason=writeback buffer_download\n");
		}
	}
	const auto tick = m_scheduler.CurrentTick();
	m_scheduler.Wait(tick);
	m_scheduler.WaitPriorityOperations(tick);
	for (const auto id: dirty_buffers) {
		auto& buffer = m_slot_buffers[id];
		m_memory_tracker.UnmarkRegionAsGpuModified(buffer.CpuAddress(), buffer.Size());
		if (m_memory_tracker.IsRegionGpuModified(buffer.CpuAddress(), buffer.Size()) ||
		    m_gpu_modified_ranges.Intersects(buffer.CpuAddress(), buffer.Size())) {
			EXIT("NATIVE_RELEASE_MEM_REJECTED reason=writeback retained_buffer_ownership\n");
		}
	}
}

BufferId BufferCache::FindBuffer(uint64_t vaddr, uint64_t size) {
	if (vaddr == 0) {
		return NULL_BUFFER_ID;
	}
	if (!GuestRange {vaddr, size}.Valid()) {
		EXIT("BufferCache: invalid buffer discovery request\n");
	}
	const auto* owner = m_page_table.Find(vaddr >> PageTable::kPageBits);
	if (owner != nullptr && *owner) {
		auto& buffer = m_slot_buffers[*owner];
		if (buffer.IsInBounds(vaddr, size)) {
			return *owner;
		}
	}
	return CreateBuffer(vaddr, size);
}

BufferCache::OverlapResult BufferCache::ResolveOverlaps(uint64_t vaddr, uint64_t size) {
	static constexpr int      StreamLeapThreshold = 16;
	static constexpr uint64_t StreamLeapSize      = CACHING_PAGESIZE * 128;

	auto       begin      = vaddr;
	auto       end        = vaddr + size;
	const auto find_first = [&](uint64_t address) {
		auto first = m_buffers.lower_bound(address);
		if (first != m_buffers.begin()) {
			const auto  previous = std::prev(first);
			const auto& buffer   = m_slot_buffers[previous->second];
			if (buffer.CpuAddress() + buffer.Size() > address) {
				first = previous;
			}
		}
		return first;
	};
	auto first           = find_first(begin);
	auto last            = first;
	int  stream_score    = 0;
	bool has_stream_leap = false;
	for (; last != m_buffers.end() && last->first < end; ++last) {
		const auto& buffer        = m_slot_buffers[last->second];
		const auto  buffer_begin  = buffer.CpuAddress();
		const auto  buffer_end    = buffer_begin + buffer.Size();
		const bool  expands_left  = buffer_begin < begin;
		const bool  expands_right = buffer_end > end;
		begin                     = std::min(begin, buffer_begin);
		end                       = std::max(end, buffer_end);
		if (!has_stream_leap && (stream_score += buffer.StreamScore()) > StreamLeapThreshold) {
			has_stream_leap = true;
			// Reserve space in the incoming stream's direction of growth.
			// The old buffer extending left of the request predicts growth to the right, and vice versa.
			if (expands_left) {
				end += std::min(StreamLeapSize, (vaddr < LOWER_ADDRESS_SIZE ? LOWER_ADDRESS_SIZE
				                                       : LibKernel::Memory::kExtendedMemoryBase +
				                                             LibKernel::Memory::kExtendedMemorySize) - end);
			}
			if (expands_right) {
				const auto minimum = vaddr < LOWER_ADDRESS_SIZE
				                         ? CACHING_PAGESIZE * 2
				                         : LibKernel::Memory::kExtendedMemoryBase;
				if (begin > minimum) {
					begin -= std::min(StreamLeapSize, begin - minimum);
				}
				first = find_first(begin);
				begin = std::min(begin, first->first);
			}
		}
	}
	return {first, last, begin, end, has_stream_leap};
}

void BufferCache::JoinOverlap(BufferId new_id, BufferId overlap_id, bool accumulate_stream_score) {
	auto& new_buffer = m_slot_buffers[new_id];
	auto& overlap    = m_slot_buffers[overlap_id];
	if (accumulate_stream_score) {
		new_buffer.IncreaseStreamScore(overlap.StreamScore() + 1);
	}
	new_buffer.CopyFrom(m_scheduler.Current(), overlap, 0,
	                    overlap.CpuAddress() - new_buffer.CpuAddress(), overlap.Size());
	DeleteBuffer(overlap_id);
}

BufferId BufferCache::CreateBuffer(uint64_t vaddr, uint64_t size) {
	EXIT_IF(m_scheduler.Current().IsInvalid());
	const auto end = Common::AlignUp(vaddr + size, CACHING_PAGESIZE);
	vaddr = Common::AlignDown(vaddr, CACHING_PAGESIZE);
	size               = end - vaddr;
	const auto overlap = ResolveOverlaps(vaddr, size);

	const auto id = m_slot_buffers.insert(
	    m_graphics, m_scheduler, MemoryUsage::DeviceLocal, overlap.begin,
	    AllFlags | vk::BufferUsageFlagBits::eShaderDeviceAddress, overlap.end - overlap.begin);
	const auto& buffer = m_slot_buffers[id];
	SetVulkanObjectNameF(m_graphics.device, buffer.Handle(),
	                     "Kyty.GameBuffer[guest=0x{:016x} size=0x{:x}]", overlap.begin,
	                     overlap.end - overlap.begin);
	for (auto it = overlap.first; it != overlap.last;) {
		const auto old_id = (it++)->second;
		JoinOverlap(id, old_id, !overlap.has_stream_leap);
	}
	Register(id);
	return id;
}

bool BufferCache::SynchronizeBuffer(Buffer& buffer, uint64_t vaddr, uint64_t size, bool is_written,
                                    bool is_texel_buffer, bool cross_process_prevalidated) {
	if (!cross_process_prevalidated) {
		(void)ValidateCrossProcessMemory(vaddr, size);
	}
	std::vector<vk::BufferCopy> copies;
	uint64_t                    total_size = 0;
	vk::Buffer                  source;
	m_memory_tracker.ForEachUploadRange(
	    vaddr, size, is_written,
	    [&](uint64_t address, uint64_t bytes) noexcept {
		    copies.emplace_back(total_size, buffer.Offset(address), bytes);
		    total_size += bytes;
	    },
	    [&]() noexcept { source = UploadCopies(buffer, copies, total_size); });
	if (source) {
		auto& command = m_scheduler.Current();
		command.EndRendering();
		const auto native = command.Handle();
		vk::BufferMemoryBarrier before {};
		before.srcAccessMask = vk::AccessFlagBits::eMemoryRead | vk::AccessFlagBits::eMemoryWrite |
		                       vk::AccessFlagBits::eTransferRead |
		                       vk::AccessFlagBits::eTransferWrite;
		before.dstAccessMask       = vk::AccessFlagBits::eTransferWrite;
		before.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
		before.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
		before.buffer              = buffer.Handle();
		before.offset              = 0;
		before.size                = buffer.Size();
		native.pipelineBarrier(vk::PipelineStageFlagBits::eAllCommands,
		                       vk::PipelineStageFlagBits::eTransfer,
		                       vk::DependencyFlagBits::eByRegion, 0, nullptr, 1, &before, 0, nullptr);
		native.copyBuffer(source, buffer.Handle(), static_cast<uint32_t>(copies.size()),
		                  copies.data());
		auto after          = before;
		after.srcAccessMask = vk::AccessFlagBits::eTransferWrite;
		after.dstAccessMask = vk::AccessFlagBits::eMemoryRead | vk::AccessFlagBits::eMemoryWrite;
		native.pipelineBarrier(vk::PipelineStageFlagBits::eTransfer,
		                       vk::PipelineStageFlagBits::eAllCommands,
		                       vk::DependencyFlagBits::eByRegion, 0, nullptr, 1, &after, 0, nullptr);
	}
	if (is_texel_buffer && !is_written) {
		return SynchronizeBufferFromImage(buffer, vaddr, size);
	}
	return false;
}

vk::Buffer BufferCache::UploadCopies(Buffer& buffer, std::span<vk::BufferCopy> copies,
                                     uint64_t total_size) {
	if (copies.empty()) {
		return nullptr;
	}

	auto& staging              = GetUtilityBuffer(MemoryUsage::Upload);
	auto [mapped, base_offset] = staging.Map(total_size, 4);
	if (mapped != nullptr) {
		for (auto& copy: copies) {
			const auto address = buffer.CpuAddress() + copy.dstOffset;
			std::memcpy(mapped + copy.srcOffset, reinterpret_cast<const void*>(address), copy.size);
			copy.srcOffset += base_offset;
		}
		staging.Commit();
		return staging.Handle();
	}

	auto temporary = std::make_unique<Buffer>(m_graphics, m_scheduler, MemoryUsage::Upload, 0,
	                                         vk::BufferUsageFlagBits::eTransferSrc, total_size);
	for (const auto& copy: copies) {
		const auto address = buffer.CpuAddress() + copy.dstOffset;
		std::memcpy(temporary->Mapped().data() + copy.srcOffset,
		            reinterpret_cast<const void*>(address), copy.size);
	}
	temporary->Flush(0, total_size);
	const auto handle = temporary->Handle();
	m_scheduler.DeferOperation([owner = std::move(temporary)]() mutable { owner.reset(); });
	return handle;
}

std::pair<Buffer*, uint64_t> BufferCache::ObtainBuffer(uint64_t vaddr, uint64_t size,
                                                       bool is_written, bool is_texel_buffer,
                                                       BufferId id,
                                                       bool     cross_process_prevalidated) {
	auto& command = m_scheduler.Current();
	if (command.IsInvalid() || !GuestRange {vaddr, size}.Valid()) {
		EXIT("BufferCache: buffer request requires a recording command buffer\n");
	}

	if (!is_written && size <= CACHING_PAGESIZE &&
	    !m_memory_tracker.IsRegionGpuModified(vaddr, size) &&
	    m_memory_tracker.IsRegionCpuModified(vaddr, size)) {
		const auto alignment = std::max<uint64_t>(
		    m_graphics.physical_device_properties.limits.minUniformBufferOffsetAlignment, 1);
		auto& stream          = GetUtilityBuffer(MemoryUsage::Stream);
		auto [mapped, offset] = stream.Map(size, alignment, false);
		if (mapped != nullptr) {
			std::memcpy(mapped, reinterpret_cast<const void*>(vaddr), size);
			stream.Commit();
			return {&stream, offset};
		}
	}

	if (IsBufferInvalid(id) || !m_slot_buffers[id].IsInBounds(vaddr, size)) {
		id = FindBuffer(vaddr, size);
	}
	auto& buffer = m_slot_buffers[id];
	TouchBuffer(buffer);
	(void)SynchronizeBuffer(buffer, vaddr, size, is_written, is_texel_buffer,
	                        cross_process_prevalidated);
	if (is_written) {
		m_gpu_modified_ranges.Add(vaddr, size);
	}
	return {&buffer, buffer.Offset(vaddr)};
}

BufferCache::ImageBufferSource BufferCache::ObtainBufferForImage(uint64_t vaddr, uint64_t size) {
	if (!GuestRange {vaddr, size}.Valid()) {
		EXIT("BufferCache: invalid image source\n");
	}
	const auto  validation = ValidateCrossProcessMemory(vaddr, size, true);
	const auto* owner = m_page_table.Find(vaddr >> PageTable::kPageBits);
	if (owner != nullptr && *owner) {
		auto& buffer = m_slot_buffers[*owner];
		if (buffer.IsInBounds(vaddr, size)) {
			TouchBuffer(buffer);
			(void)SynchronizeBuffer(buffer, vaddr, size, false, false, true);
			return {&buffer, buffer.Offset(vaddr), validation.generation, validation.intersects,
			        validation.gpu_conflict};
		}
	}
	if (IsRegionGpuModified(vaddr, size)) {
		const auto [buffer, offset] = ObtainBuffer(vaddr, size, false, false, {}, true);
		return {buffer, offset, validation.generation, validation.intersects, true};
	}

	auto& ring                   = GetUtilityBuffer(MemoryUsage::Upload);
	auto [staging, stage_offset] = ring.Map(size, 16);
	if (staging == nullptr || !Libs::LibKernel::Memory::TryReadSparseBacking(vaddr, staging, size)) {
		EXIT("BufferCache: failed to read mapped guest image backing\n");
	}
	ring.Commit();
	return {&ring, stage_offset, validation.generation, validation.intersects,
	        validation.gpu_conflict};
}

void BufferCache::FillBuffer(uint64_t vaddr, uint64_t size, uint32_t value, bool is_gds) {
	if ((vaddr & 3u) != 0 || size == 0 || (size & 3u) != 0 || size > UINT64_MAX - vaddr) {
		EXIT("BufferCache: fill range must be dword aligned\n");
	}
	if (is_gds) {
		if (vaddr > m_gds_buffer.Size() || size > m_gds_buffer.Size() - vaddr) {
			EXIT("BufferCache: GDS fill range is out of bounds\n");
		}
		m_gds_buffer.Fill(vaddr, size, value);
		return;
	}
	if (vaddr == 0) {
		EXIT("BufferCache: invalid fill memory address\n");
	}
	(void)m_texture_cache.ClearMeta(vaddr);
	if (!IsRegionGpuModified(vaddr, size)) {
		// Access the guest mapping so write faults invalidate cached buffers and images.
		auto* destination = reinterpret_cast<uint32_t*>(vaddr);
		std::fill(destination, destination + size / sizeof(uint32_t), value);
		return;
	}

	m_texture_cache.InvalidateMemoryFromGPU(vaddr, size);
	auto [dst, dst_offset] = ObtainBuffer(vaddr, size, true, true);
	dst->Fill(dst_offset, size, value);
}

void BufferCache::CopyBuffer(uint64_t dst_vaddr, uint64_t src_vaddr, uint64_t size, bool dst_gds,
                             bool src_gds) {
	const bool dst_memory = !dst_gds;
	const bool src_memory = !src_gds;
	if ((dst_memory && dst_vaddr == 0) || (src_memory && src_vaddr == 0) || size == 0 ||
	    ((dst_gds || src_gds) && ((dst_vaddr | src_vaddr | size) & 3u) != 0) ||
	    size > UINT64_MAX - dst_vaddr || size > UINT64_MAX - src_vaddr || (dst_gds && src_gds) ||
	    (dst_gds && (dst_vaddr > m_gds_buffer.Size() || size > m_gds_buffer.Size() - dst_vaddr)) ||
	    (src_gds && (src_vaddr > m_gds_buffer.Size() || size > m_gds_buffer.Size() - src_vaddr))) {
		EXIT("BufferCache: invalid copy range, src=0x%016" PRIx64 " dst=0x%016" PRIx64
		     " size=0x%016" PRIx64 " src_gds=%d dst_gds=%d\n",
		     src_vaddr, dst_vaddr, size, static_cast<int>(src_gds), static_cast<int>(dst_gds));
	}
	if (src_memory && dst_memory && !IsRegionGpuModified(dst_vaddr, size) &&
	    !IsRegionGpuModified(src_vaddr, size) && !m_texture_cache.FindImageFromRange(src_vaddr, size)) {
		std::memcpy(reinterpret_cast<void*>(dst_vaddr), reinterpret_cast<const void*>(src_vaddr),
		            size);
		return;
	}

	auto& command = m_scheduler.Current();
	if (dst_memory) {
		m_texture_cache.InvalidateMemoryFromGPU(dst_vaddr, size);
	}
	const auto src_id      = src_memory ? FindBuffer(src_vaddr, size) : BufferId {};
	const auto dst_id      = dst_memory ? FindBuffer(dst_vaddr, size) : BufferId {};
	auto [src, src_offset] = src_memory ? ObtainBuffer(src_vaddr, size, false, true, src_id)
	                                    : std::pair {&m_gds_buffer, src_vaddr};
	auto [dst, dst_offset] = dst_memory ? ObtainBuffer(dst_vaddr, size, true, true, dst_id)
	                                    : std::pair {&m_gds_buffer, dst_vaddr};
	dst->CopyFrom(command, *src, src_offset, dst_offset, size);
}

bool BufferCache::IsRegionRegistered(uint64_t vaddr, uint64_t size) {
	if (!GuestRange {vaddr, size}.Valid()) {
		EXIT("BufferCache: invalid registered-region query\n");
	}
	// Cached buffers are ordered and non-overlapping. The last buffer beginning before the query
	// end is therefore the only possible intersection.
	const auto candidate = m_buffers.lower_bound(vaddr + size);
	if (candidate == m_buffers.begin()) {
		return false;
	}
	const auto& [address, id] = *std::prev(candidate);
	return address + m_slot_buffers[id].Size() > vaddr;
}

bool BufferCache::IsRegionGpuModified(uint64_t vaddr, uint64_t size) {
	return m_memory_tracker.IsRegionGpuModified(vaddr, size);
}

bool BufferCache::HasGpuDirtyBytes(uint64_t vaddr, uint64_t size) {
	return m_gpu_modified_ranges.Intersects(vaddr, size);
}

bool BufferCache::IsRegionCpuModified(uint64_t vaddr, uint64_t size) {
	return m_memory_tracker.IsRegionCpuModified(vaddr, size);
}

void BufferCache::RunGarbageCollector() {
	const auto tick = m_gc_tick++;
	if (m_graphics.CanReportMemoryUsage()) {
		m_total_used_memory = m_graphics.GetDeviceMemoryUsage();
	}
	if (m_total_used_memory < m_trigger_gc_memory) {
		return;
	}

	const bool     aggressive = m_total_used_memory >= m_critical_gc_memory;
	const uint64_t age        = std::min<uint64_t>(aggressive ? 80 : 160, tick);
	const size_t   limit      = aggressive ? 64 : 32;

	std::vector<BufferId> dirty_buffers;
	size_t                retire_count = 0;
	m_lru_cache.ForEachItemBelow(tick - age, [&](BufferId id) {
		auto& buffer = m_slot_buffers[id];
		EXIT_IF(buffer.is_deleted);
		m_memory_tracker.ValidateGpuDirtyOwnership(m_gpu_modified_ranges, buffer.CpuAddress(),
		                                           buffer.Size(), "garbage collection");
		const bool dirty = m_memory_tracker.IsRegionGpuModified(buffer.CpuAddress(), buffer.Size());
		if (dirty && !aggressive) {
			return false;
		}
		if (dirty) {
			EXIT_NOT_IMPLEMENTED(!DownloadBufferMemory<true>(buffer, buffer.CpuAddress(), buffer.Size()));
			dirty_buffers.push_back(id);
		} else {
			m_memory_tracker.UntrackMemory(buffer.CpuAddress(), buffer.Size());
			DeleteBuffer(id);
		}
		return ++retire_count == limit;
	});
	if (dirty_buffers.empty()) {
		return;
	}

	// Publish all queued downloads before releasing their tracked pages and owners.
	const auto completion_tick = m_scheduler.CurrentTick();
	m_scheduler.Wait(completion_tick);
	m_scheduler.WaitPriorityOperations(completion_tick);
	for (const auto id: dirty_buffers) {
		auto& buffer = m_slot_buffers[id];
		m_memory_tracker.UnmarkRegionAsGpuModified(buffer.CpuAddress(), buffer.Size());
		if (m_memory_tracker.IsRegionGpuModified(buffer.CpuAddress(), buffer.Size()) ||
		    m_gpu_modified_ranges.Intersects(buffer.CpuAddress(), buffer.Size())) {
			EXIT("BufferCache: garbage collection retained GPU ownership\n");
		}
		m_memory_tracker.UntrackMemory(buffer.CpuAddress(), buffer.Size());
		Unregister(id);
		m_slot_buffers.erase(id);
	}
}

StreamBuffer& BufferCache::GetUtilityBuffer(MemoryUsage usage) {
	auto& utility = m_utility_buffers[static_cast<size_t>(usage)];
	// The present thread reaches the download ring for diagnostic readback, so creation has to be once-only.
	std::call_once(utility.once, [&] {
		uint64_t size = 0;
		switch (usage) {
			case MemoryUsage::Upload: size = 512 * MiB; break;
			case MemoryUsage::Stream: size = 64 * MiB; break;
			case MemoryUsage::Download: size = 64 * MiB; break;
			case MemoryUsage::DeviceLocal: size = 128 * MiB; break;
		}
		EXIT_IF(size == 0);
		utility.buffer = std::make_unique<StreamBuffer>(m_graphics, m_scheduler, usage, size);
	});
	return *utility.buffer;
}

void BufferCache::EnsureBdaResources() {
	if (m_bda_pagetable_buffer) {
		return;
	}
	m_fault_manager = std::make_unique<FaultManager>(m_graphics, m_scheduler, *this);
	m_fault_manager->GetFaultBuffer()->Fill(0, m_fault_manager->GetFaultBuffer()->Size(), 0);
	m_bda_pagetable_buffer = std::make_unique<Buffer>(m_graphics, m_scheduler, MemoryUsage::DeviceLocal, 0, AllFlags, BDA_PAGETABLE_SIZE);
	SetVulkanObjectNameF(m_graphics.device, m_bda_pagetable_buffer->Handle(), "BDA Page Table Buffer");
	m_bda_pagetable_buffer->Fill(0, BDA_PAGETABLE_SIZE, 0);
	std::vector<vk::DeviceAddress> addresses;
	for (const auto& [vaddr, id]: m_buffers) {
		const auto& buffer = m_slot_buffers[id];
		PageTable::PageRange pages {};
		EXIT_IF(!PageTable::TryGetPageRange(vaddr, buffer.Size(), pages));
		addresses.clear();
		for (uint64_t i = 0; i < pages.last_exclusive - pages.first; ++i) {
			addresses.push_back(buffer.BufferDeviceAddress() + (i << CACHING_PAGEBITS));
		}
		WriteDataBuffer(*m_bda_pagetable_buffer, PageIndex(vaddr) * sizeof(vk::DeviceAddress),
		                addresses.data(), addresses.size() * sizeof(vk::DeviceAddress));
	}
}

void BufferCache::ProcessFaultBuffer() {
	m_fault_manager->ProcessFaultBuffer();
}

void BufferCache::SynchronizeBuffersInRange(uint64_t vaddr, uint64_t size) {
	const auto end = vaddr + size;
	auto       it  = m_buffers.upper_bound(vaddr);
	if (it != m_buffers.begin()) {
		--it;
	}
	for (; it != m_buffers.end() && it->first < end; ++it) {
		auto&      buffer = m_slot_buffers[it->second];
		const auto start  = std::max(buffer.CpuAddress(), vaddr);
		const auto finish = std::min(buffer.CpuAddress() + buffer.Size(), end);
		if (start < finish) {
			(void)SynchronizeBuffer(buffer, start, finish - start, false, false);
		}
	}
}

} // namespace Libs::Graphics
