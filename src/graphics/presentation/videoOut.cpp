#include "graphics/presentation/videoOut.h"

#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/emulatorConfig.h"
#include "common/logging/log.h"
#include "common/profiler.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/timer.h"
#include "graphics/guest_gpu/gpu_defs.h"
#include "graphics/guest_gpu/graphicsRun.h"
#include "graphics/guest_gpu/tile.h"
#include "graphics/host_gpu/renderer/image/imageInfo.h"
#include "graphics/host_gpu/renderer/render.h"
#include "graphics/host_gpu/renderer/renderContext.h"
#include "graphics/presentation/presenter.h"
#include "graphics/presentation/renderDoc.h"
#include "kernel/pthread.h"
#include "kernel/memory.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/systemContent.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <fmt/format.h>
#include <limits>
#include <list>
#include <span>
#include <thread>
#include <vector>

namespace Libs::Graphics {
struct GraphicContext;
} // namespace Libs::Graphics

namespace Libs::VideoOut {

LIB_NAME("VideoOut", "VideoOut");

namespace EventQueue = LibKernel::EventQueue;

constexpr int      VIDEO_OUT_EVENT_FLIP                                 = 0;
constexpr int      VIDEO_OUT_EVENT_VBLANK                               = 1;
constexpr int      VIDEO_OUT_EVENT_PRE_VBLANK_START                     = 2;
constexpr int      VIDEO_OUT_EVENT_SET_MODE                             = 8;
constexpr int      VIDEO_OUT_EVENT_SET_MODE_INTERNAL                     = 0x10008;
constexpr int      VIDEO_OUT_TRUE                                       = 1;
constexpr int      VIDEO_OUT_FALSE                                      = 0;
constexpr int      VIDEO_OUT_BUS_TYPE_MAIN                              = 0;
constexpr int      VIDEO_OUT_BUS_TYPE_OVERLAY                           = 1;
constexpr int      VIDEO_OUT_BUS_TYPE_SUB                               = 2;
constexpr int      VIDEO_OUT_BUS_TYPE_SYSTEM                             = 0x100;
constexpr int      VIDEO_OUT_FLIP_MODE_VSYNC                            = 1;
constexpr int      VIDEO_OUT_FLIP_MODE_VSYNC_MULTI                      = 4;
constexpr int      VIDEO_OUT_FLIP_MODE_SLAVE                            = 8;
constexpr int      VIDEO_OUT_FLIP_MODE_MASTER                           = 9;
constexpr int      VIDEO_OUT_BUFFER_INDEX_BLACK                         = -2;
constexpr int      VIDEO_OUT_BUFFER_INDEX_BLANK                         = -1;
constexpr int      VIDEO_OUT_BUFFER_NUM_MAX                             = 16;
constexpr size_t   VIDEO_OUT_FLIP_QUEUE_CAPACITY                        = 16;
constexpr int      VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX                   = 4;
constexpr uint64_t VIDEO_OUT_OUTPUT_MODE_DEFAULT                        = 0x0000000000000001ULL;
constexpr uint64_t VIDEO_OUT_OUTPUT_MODE_119_88HZ                       = 0x000000000000000FULL;
constexpr uint64_t VIDEO_OUT_REFRESH_RATE_59_94HZ                       = 3;
constexpr uint64_t VIDEO_OUT_REFRESH_RATE_119_88HZ                      = 13;
constexpr int      VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_UNCOMPRESSED     = 0;
constexpr int      VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_COMPRESSED       = 1;
constexpr uint64_t VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_STRICT_COLORIMETRY = 8;
constexpr uint64_t VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED = 32;

enum class VideoOutEventKind : uintptr_t {
	Flip           = VIDEO_OUT_EVENT_FLIP,
	Vblank         = VIDEO_OUT_EVENT_VBLANK,
	PreVblankStart = VIDEO_OUT_EVENT_PRE_VBLANK_START,
	OutputMode     = VIDEO_OUT_EVENT_SET_MODE,
	SetMode        = VIDEO_OUT_EVENT_SET_MODE_INTERNAL,
};

enum class FlipRequestSource { Cpu, GpuEop };

struct DcePrivacyMaskState {
	static constexpr uint16_t RESERVED_BIT = 1;
	uint16_t                  occupied_ids = RESERVED_BIT;

	[[nodiscard]] uint64_t Query() const noexcept { return occupied_ids; }
};

struct VideoOutEventState;

struct VideoOutEventRegistration {
	EventQueue::KernelEqueue            handle = EventQueue::KERNEL_EQUEUE_INVALID;
	std::shared_ptr<VideoOutEventState> state;
	uint64_t                            generation = 0;
	VideoOutEventKind                   kind       = VideoOutEventKind::Flip;
	uintptr_t                           original_native_ident = 0;
};

using VideoOutEventRegistrationRef = std::shared_ptr<VideoOutEventRegistration>;
using VideoOutEventQueues          = std::vector<VideoOutEventRegistrationRef>;

struct VideoOutEventState {
	Common::Mutex       mutex;
	VideoOutEventQueues flip;
	VideoOutEventQueues pre_vblank;
	VideoOutEventQueues vblank;
	VideoOutEventQueues output_mode;
	VideoOutEventQueues set_mode;
};

struct VideoOutBufferAttribute2 {
	uint32_t reserved0;
	uint32_t tiling_mode;
	uint32_t aspect_ratio;
	uint32_t width;
	uint32_t height;
	uint32_t pitch_in_pixel;
	uint64_t option;
	uint64_t pixel_format;
	uint64_t dcc_cb_register_clear_color;
	uint32_t dcc_control;
	uint32_t pad0;
	uint64_t reserved1[3];
};

static_assert(sizeof(VideoOutBufferAttribute2) == 0x50);
static_assert(offsetof(VideoOutBufferAttribute2, tiling_mode) == 0x04);
static_assert(offsetof(VideoOutBufferAttribute2, width) == 0x0c);
static_assert(offsetof(VideoOutBufferAttribute2, height) == 0x10);
static_assert(offsetof(VideoOutBufferAttribute2, option) == 0x18);
static_assert(offsetof(VideoOutBufferAttribute2, pixel_format) == 0x20);
static_assert(offsetof(VideoOutBufferAttribute2, dcc_cb_register_clear_color) == 0x28);
static_assert(offsetof(VideoOutBufferAttribute2, dcc_control) == 0x30);

// PS5 layout
struct VideoOutFlipStatus {
	uint64_t count                    = 0;
	uint64_t processTime              = 0;
	uint64_t reserved0                = 0;
	int64_t  flipArg                  = 0;
	uint64_t reserved1                = 0;
	uint64_t processTimeCounter       = 0;
	int32_t  gcQueueNum               = 0;
	int32_t  flipPendingNum           = 0;
	int32_t  currentBuffer            = 0;
	uint32_t reserved2                = 0;
	uint64_t submitProcessTimeCounter = 0;
	uint64_t reserved3[7]             = {};
};

// PS5 layout
struct VideoOutVblankStatus {
	uint64_t count              = 0;
	uint64_t processTime        = 0;
	uint64_t reserved           = 0;
	uint64_t processTimeCounter = 0;
	uint8_t  flags              = 0;
	uint8_t  phase              = 0;
	uint8_t  pad1[6]            = {};
};

struct VideoOutOutputStatus {
	uint32_t resolution   = 0;
	uint32_t dynamicRange = 0;
	uint64_t refreshRate  = 0;
	uint64_t flags        = 0;
	uint64_t reserved[3]  = {};
};

struct VideoOutResolutionStatus {
	uint32_t fullWidth        = 0;
	uint32_t fullHeight       = 0;
	uint32_t paneWidth        = 0;
	uint32_t paneHeight       = 0;
	uint64_t refreshRate      = 0;
	float    screenSizeInInch = 0.0f;
	uint16_t flags            = 0;
	uint16_t reserved0        = 0;
	uint32_t reserved1[4]     = {};
};

struct VideoOutOutputOptions {
	uint32_t internalData[16] = {};
};

struct VideoOutColorSettings {
	float    gamma       = 1.0f;
	uint32_t reserved[3] = {};
};

struct VideoOutBuffers {
	const void* data;
	const void* metadata;
	const void* reserved[2];
};

struct VideoOutBuffer {
	int      group_index      = -1;
	uint64_t data_address     = 0;
	uint64_t metadata_address = 0;

	[[nodiscard]] bool Occupied() const noexcept { return group_index >= 0; }
};

struct BufferAttributeGroup {
	VideoOutBufferAttribute2 attribute {};
	int                      category = VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_UNCOMPRESSED;
	bool                     occupied = false;

	[[nodiscard]] Graphics::ImageInfo ImageInfo(const VideoOutBuffer& buffer) const;
};

struct VideoOutConfig {
	Common::Mutex                       mutex;
	Common::CondVar                     vblank_cond;
	std::shared_ptr<VideoOutEventState> events      = std::make_shared<VideoOutEventState>();
	uint32_t                            width       = 0;
	uint32_t                            height      = 0;
	uint64_t                            generation  = 0;
	bool                                opened      = false;
	bool                                closing     = false;
	int                                 bus         = 0;
	VideoOutConfig*                     master      = nullptr;
	uint32_t                            slave_count = 0;
	int                                 flip_rate   = 0;
	bool                                blank_after_resume = false;
	uint64_t                            output_mode = VIDEO_OUT_OUTPUT_MODE_DEFAULT;
	// DCE signal timing, not the 1920x1080 logo surface size
	uint32_t                            native_signal_width             = 0;
	uint32_t                            native_signal_height            = 0;
	uint32_t                            native_signal_h_total           = 0;
	uint32_t                            native_signal_v_total           = 0;
	float                               native_signal_refresh_hz        = 0.0f;
	uint32_t                            native_signal_pixel_clock_10khz = 0;
	bool                                native_signal_pending           = false;
	bool                                native_signal_active            = false;
	uint32_t                            native_signal_ppll_100hz        = 0;
	uint64_t                            native_timing_generation        = 0;
	bool                                native_scanout_bound            = false;
	bool                                native_scanout_enabled          = false;
	std::array<uint64_t, 12>            native_splash_attribute_record {};
	bool                                native_splash_attributes_programmed = false;
	float                               gamma       = 1.0f;
	VideoOutFlipStatus                  flip_status;
	VideoOutVblankStatus                pre_vblank_status;
	VideoOutVblankStatus                vblank_status;
	std::array<VideoOutBuffer, VIDEO_OUT_BUFFER_NUM_MAX>                 buffers;
	std::array<BufferAttributeGroup, VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX> groups;
};

struct VideoOutVblankPhase {
	VideoOutConfig* config            = nullptr;
	uint64_t        generation        = 0;
	uint64_t        timing_generation = 0;
	bool            due               = false;
	bool            flip_available    = false;
};

enum class VideoOutCloseMode { Direct, User, Native, NativeClient };

static bool IsVblankPhaseCurrentLocked(const VideoOutVblankPhase& phase) {
	const auto& config = *phase.config;
	return phase.due && config.opened && !config.closing && config.generation == phase.generation &&
	       config.native_timing_generation == phase.timing_generation &&
	       (!config.native_scanout_bound ||
	        (config.native_signal_active && config.native_scanout_enabled));
}

static bool NativeVblankPeriod(uint64_t frequency, uint32_t h_total, uint32_t v_total,
                               uint32_t ppll_rate_100hz, uint64_t& numerator,
                               uint64_t& denominator) {
	if (frequency == 0 || h_total == 0 || v_total == 0 || ppll_rate_100hz == 0) return false;
	const uint64_t pixels = uint64_t {h_total} * v_total;
	if (frequency > std::numeric_limits<uint64_t>::max() / pixels) return false;
	numerator   = frequency * pixels;
	denominator = uint64_t {ppll_rate_100hz} * 100u;
	return numerator >= denominator;
}

class FlipQueue {
public:
	explicit FlipQueue(Graphics::Presenter& presenter): m_presenter(presenter) {
		EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
	}
	~FlipQueue();
	KYTY_CLASS_NO_COPY(FlipQueue);

	bool Reserve(VideoOutConfig& cfg, int index, int64_t flip_arg, FlipRequestSource source,
	             uint64_t& request_id);
	void Cancel(VideoOutConfig& cfg);
	void Prepare(uint64_t request_id, Graphics::CommandBuffer& buffer);
	void Complete(uint64_t request_id);
	void WaitForSubmitSlot(VideoOutConfig& cfg);
	bool Flip(std::span<VideoOutVblankPhase> phases);
	void GetFlipStatus(VideoOutConfig& cfg, VideoOutFlipStatus& out);
	void Wait(VideoOutConfig& cfg, int index, uint64_t generation = 0);

private:
	enum class RequestState { Reserved, Recording, Ready, Presenting };

	struct Request {
		uint64_t                    id;
		uint64_t                    group;
		VideoOutConfig*             cfg;
		VideoOutConfig*             master;
		uint64_t                    generation;
		int                         index;
		int64_t                     flip_arg;
		uint64_t                    submit_ptc;
		FlipRequestSource           source;
		RequestState                state;
		Graphics::Presenter::Frame* frame;
		bool                        premultiplied_alpha;
	};

	Graphics::Presenter& m_presenter;
	Common::Mutex        m_mutex;
	Common::CondVar      m_submit_cond_var;
	Common::CondVar      m_submit_slot_cond_var;
	Common::CondVar      m_done_cond_var;
	std::list<Request>   m_requests;
	std::list<Request>   m_cpu_requests;
	std::list<Request>   m_cancelled_requests;
	bool                 m_processing      = false;
	uint64_t             m_next_request_id = 1;
};

struct VideoOutDriver::Impl {
public:
	static constexpr std::array VIDEO_OUT_BUSES {VIDEO_OUT_BUS_TYPE_MAIN,
	                                             VIDEO_OUT_BUS_TYPE_OVERLAY, VIDEO_OUT_BUS_TYPE_SUB,
	                                             VIDEO_OUT_BUS_TYPE_SYSTEM};
	static constexpr int VIDEO_OUT_NUM_MAX = VIDEO_OUT_BUSES.size() + 1;

	Impl(uint32_t width, uint32_t height, Graphics::Presenter& presenter)
	    : m_renderer(presenter.Renderer()), m_presenter(presenter), m_flip_queue(presenter) {
		EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
		Init(width, height);
		m_present_thread = std::jthread([this](std::stop_token token) { PresentThread(token); });
	}
	~Impl();
	KYTY_CLASS_NO_COPY(Impl);

	int  Open(int bus_type, int index, bool native_adapter = false, uint64_t* generation = nullptr);
	bool Close(int handle, uint64_t expected_generation = 0,
	           VideoOutCloseMode mode = VideoOutCloseMode::Direct);
	VideoOutConfig* Get(int handle);
	VideoOutConfig* Get(int handle, uint64_t& generation);
	bool            IsOpened(int handle);
	int             SetFlipMaster(int slave_handle, int master_handle);
	int             AddSysSetModeEvent(EventQueue::KernelEqueue eq, uint32_t head, void* udata);
	size_t          SysSetModeRegistrationCountForTest(uint32_t head);
	int             AddSysVblankEvent(EventQueue::KernelEqueue eq, uint32_t head, void* udata);
	size_t          SysVblankRegistrationCountForTest(uint32_t head);
	void            GetSysVblankStatus(uint32_t head, VideoOutVblankStatus* status);

	void                     Init(uint32_t width, uint32_t height);
	FlipQueue&               GetFlipQueue() { return m_flip_queue; }
	Graphics::RenderContext& Renderer() const noexcept { return m_renderer; }
	[[nodiscard]] uint64_t   OccupiedPrivacyMask() const noexcept { return m_privacy_mask.Query(); }

	void VblankBegin(std::span<VideoOutVblankPhase> phases);
	void VblankEnd(std::span<const VideoOutVblankPhase> phases, bool fallback_due);
	void PresentThread(std::stop_token token);

private:
	Common::Mutex            m_mutex;
	VideoOutConfig           m_video_out_ctx[VIDEO_OUT_NUM_MAX];
	Graphics::RenderContext& m_renderer;
	Graphics::Presenter&     m_presenter;
	FlipQueue                m_flip_queue;
	std::jthread             m_present_thread;
	DcePrivacyMaskState      m_privacy_mask;
	// Sys vblank registrations are per head and belong to no handle.
	std::array<std::shared_ptr<VideoOutEventState>, 2> m_sys_events {
	    std::make_shared<VideoOutEventState>(), std::make_shared<VideoOutEventState>()};
	std::array<VideoOutVblankStatus, 2> m_sys_vblank_status;
};

static std::unique_ptr<VideoOutDriver> g_video_out_driver;
static std::atomic_bool                                g_video_out_ready {false};
static std::atomic_bool                                g_native_dce_owns_main_head {false};
static std::atomic_uint32_t                            g_native_splash_shared_main_leases {0};
static std::atomic_uint32_t                            g_native_virtual_display_clock {0};
static Common::Mutex                                   g_native_controller_mutex;
static std::array<VideoOutNativeControllerSnapshot, 2> g_native_controllers {};

bool VideoOutIsInitialized() noexcept {
	return g_video_out_ready.load(std::memory_order_acquire);
}

static VideoOutDriver::Impl& DriverState() {
	EXIT_IF(g_video_out_driver == nullptr);
	return g_video_out_driver->State();
}

bool VideoOutNativeCanAttachOriginalDceClient() {
	if (!VideoOutIsInitialized() || !g_native_dce_owns_main_head.load(std::memory_order_acquire)) {
		return false;
	}
	auto* const ctx = DriverState().Get(1);
	if (ctx == nullptr) return false;
	Common::LockGuard lock(ctx->mutex);
	return ctx->opened && !ctx->closing &&
	       (ctx->native_signal_active || ctx->native_signal_pending) &&
	       ((ctx->native_signal_width == 3840 && ctx->native_signal_height == 2160) ||
	        (ctx->native_signal_width == 1920 && ctx->native_signal_height == 1080));
}

static uintptr_t VideoOutEventId(VideoOutEventKind kind) {
	return static_cast<uintptr_t>(kind);
}

// Same layout as the set-mode kevent in VideoOutSysAddSetModeEvent2, with dce event type 0x70.
static uintptr_t VideoOutSysVblankEventId(uint32_t head) {
	return (uint64_t {0x70} << 48u) | (uint64_t {head} << 40u) | 0x100000000ULL;
}

static uintptr_t VideoOutSysSetModeEventId(uint32_t head) {
	return (uint64_t {0x73} << 48u) | (uint64_t {head} << 40u) | 0x100000000ULL;
}

static VideoOutEventQueues& VideoOutEventQueuesFor(VideoOutEventState& state,
                                                   VideoOutEventKind   kind) {
	switch (kind) {
		case VideoOutEventKind::Flip: return state.flip;
		case VideoOutEventKind::Vblank: return state.vblank;
		case VideoOutEventKind::PreVblankStart: return state.pre_vblank;
		case VideoOutEventKind::OutputMode: return state.output_mode;
		case VideoOutEventKind::SetMode: return state.set_mode;
	}
	EXIT("unsupported video-out event kind\n");
	return state.flip;
}

static intptr_t MakeVideoOutEventData(intptr_t current_data, void* trigger_data) {
	const uint64_t old_data = static_cast<uint64_t>(current_data);
	uint64_t       counter  = (old_data >> 12u) & 0xfu;
	if (counter != 0xfu) {
		counter++;
	}

	const uint64_t time    = LibKernel::KernelReadTsc() & 0xfffu;
	const uint64_t payload = static_cast<uint64_t>(reinterpret_cast<intptr_t>(trigger_data));

	return static_cast<intptr_t>(time | (counter << 12u) |
	                             ((payload & 0x0000ffffffffffffULL) << 16u));
}

static void ResetVideoOutEvent(EventQueue::KernelEqueueEvent* event) {
	EXIT_IF(event == nullptr);
	event->triggered    = false;
	event->event.fflags = 0;
	event->event.data   = 0;
}

static void TriggerVideoOutEvent(EventQueue::KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);

	auto triggered_event = event->event;
	triggered_event.fflags =
	    triggered_event.fflags < 0xfu ? triggered_event.fflags + 1u : triggered_event.fflags;
	triggered_event.data = MakeVideoOutEventData(triggered_event.data, trigger_data);
	if (event->triggered) {
		event->pending_events.push_back(triggered_event);
		return;
	}
	event->event     = triggered_event;
	event->triggered = true;
}

static void TriggerVideoOutSysVblank(EventQueue::KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);

	// coalesce, libScePsm drains one event per wait
	if (event->event.fflags < 0xfu) {
		event->event.fflags++;
	}
	event->event.data = MakeVideoOutEventData(event->event.data, trigger_data);
	event->triggered  = true;
}

static void RemoveVideoOutEventQueue(EventQueue::KernelEqueue       eq,
                                     EventQueue::KernelEqueueEvent* event) {
	if (event == nullptr || event->filter.data == nullptr) {
		return;
	}

	auto* registration = static_cast<VideoOutEventRegistration*>(event->filter.data);
	auto  state        = registration->state;
	if (registration->handle != eq || !state) {
		return;
	}
	auto&             queues = VideoOutEventQueuesFor(*state, registration->kind);
	Common::LockGuard lock(state->mutex);
	const auto        entry =
	    std::find_if(queues.begin(), queues.end(), [registration](const auto& candidate) {
		    return candidate.get() == registration;
	    });
	if (entry != queues.end()) {
		queues.erase(entry);
	}
}

static void TriggerVideoOutEvents(VideoOutConfig& video_out, VideoOutEventKind kind,
                                  void* trigger_data) {
	VideoOutEventQueues queues;
	{
		Common::LockGuard lock(video_out.events->mutex);
		queues = VideoOutEventQueuesFor(*video_out.events, kind);
	}
	for (const auto& registration: queues) {
		if (!registration || registration->generation != video_out.generation) {
			continue;
		}
		const auto result = EventQueue::KernelTriggerEvent(
		    registration->handle,
		    registration->original_native_ident != 0 ? registration->original_native_ident
			                                         : VideoOutEventId(kind),
		    EventQueue::KERNEL_EVFILT_VIDEO_OUT, trigger_data);
		EXIT_NOT_IMPLEMENTED(result != OK && result != LibKernel::KERNEL_ERROR_EBADF &&
		                     result != LibKernel::KERNEL_ERROR_ENOENT);
	}
}

static void DeleteVideoOutEvents(const VideoOutEventQueues& queues, VideoOutEventKind kind) {
	for (const auto& registration: queues) {
		if (!registration) {
			continue;
		}
		const auto result = EventQueue::KernelDeleteEvent(registration->handle,
		                                                  registration->original_native_ident != 0
		                                                      ? registration->original_native_ident
		                                                      : VideoOutEventId(kind),
		                                                  EventQueue::KERNEL_EVFILT_VIDEO_OUT);
		EXIT_NOT_IMPLEMENTED(result != OK && result != LibKernel::KERNEL_ERROR_EBADF &&
		                     result != LibKernel::KERNEL_ERROR_ENOENT);
	}
}

static int RegisterVideoOutEvent(int handle, EventQueue::KernelEqueue eq, VideoOutEventKind kind,
                                 void* udata, uintptr_t original_native_ident = 0,
                                 uint64_t expected_generation = 0) {
	uint64_t generation = 0;
	auto*    video_out  = DriverState().Get(handle, generation);
	if (video_out == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	Common::LockGuard lock(video_out->mutex);
	if (!video_out->opened || video_out->closing || video_out->generation != generation ||
	    (expected_generation != 0 && generation != expected_generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (kind == VideoOutEventKind::OutputMode) {
		LOGF("\t eq     = 0x%016" PRIx64 "\n"
		     "\t handle = %d\n"
		     "\t udata  = 0x%016" PRIx64 "\n",
		     static_cast<uint64_t>(eq), handle, reinterpret_cast<uint64_t>(udata));
	}
	if (eq == EventQueue::KERNEL_EQUEUE_INVALID) {
		return VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE;
	}
	if (!EventQueue::KernelPinEqueue(eq)) {
		return VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE;
	}
	auto        event_state         = video_out->events;
	auto&       queues              = VideoOutEventQueuesFor(*event_state, kind);
	const bool  initially_triggered = kind == VideoOutEventKind::OutputMode;
	void* const initial_trigger_data =
	    initially_triggered ? reinterpret_cast<void*>(video_out->output_mode) : nullptr;

	EventQueue::KernelEqueueEvent event {};
	event.triggered    = initially_triggered;
	event.event.ident  = original_native_ident != 0 ? original_native_ident : VideoOutEventId(kind);
	event.event.filter = EventQueue::KERNEL_EVFILT_VIDEO_OUT;
	event.event.flags  = original_native_ident != 0 ? 1u : 0u;
	event.event.udata  = udata;
	event.event.fflags = initially_triggered ? 1u : 0u;
	event.event.data   = initially_triggered ? MakeVideoOutEventData(0, initial_trigger_data) : 0;
	event.filter.delete_event_func = RemoveVideoOutEventQueue;
	event.filter.reset_func        = ResetVideoOutEvent;
	event.filter.trigger_func      = TriggerVideoOutEvent;

	VideoOutEventRegistrationRef registration;
	bool                         add_queue = false;
	{
		Common::LockGuard event_lock(event_state->mutex);
		const auto        existing =
		    std::find_if(queues.begin(), queues.end(), [&](const auto& candidate) {
			    return candidate->handle == eq && candidate->generation == generation &&
				       candidate->original_native_ident == original_native_ident;
		    });
		if (existing != queues.end()) {
			registration = *existing;
		} else {
			registration = std::make_shared<VideoOutEventRegistration>(
			    VideoOutEventRegistration {.handle                = eq,
				                           .state                 = event_state,
				                           .generation            = generation,
				                           .kind                  = kind,
				                           .original_native_ident = original_native_ident});
			queues.push_back(registration);
			add_queue = true;
		}
	}
	event.filter.data  = registration.get();
	event.filter.owner = registration;
	const int result   = EventQueue::KernelAddEvent(eq, event);
	if (result != OK && add_queue) {
		Common::LockGuard event_lock(event_state->mutex);
		const auto        added = std::find(queues.begin(), queues.end(), registration);
		if (added != queues.end()) {
			queues.erase(added);
		}
	}
	return result == LibKernel::KERNEL_ERROR_EBADF ? VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE : result;
}

static int DeleteVideoOutEvent(int handle, EventQueue::KernelEqueue eq, VideoOutEventKind kind) {
	uint64_t generation = 0;
	auto*    video_out  = DriverState().Get(handle, generation);
	if (video_out == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	Common::LockGuard lock(video_out->mutex);
	if (!video_out->opened || video_out->closing || video_out->generation != generation) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (!EventQueue::KernelPinEqueue(eq)) {
		return VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE;
	}
	const int result = EventQueue::KernelDeleteEvent(eq, VideoOutEventId(kind),
	                                                 EventQueue::KERNEL_EVFILT_VIDEO_OUT);
	if (result == LibKernel::KERNEL_ERROR_EBADF) {
		return VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE;
	}
	return result == LibKernel::KERNEL_ERROR_ENOENT ? OK : result;
}

static bool IsFlipDueLocked(const VideoOutConfig& cfg, uint64_t generation) {
	if (!cfg.opened || cfg.closing || cfg.generation != generation) {
		return false;
	}
	const int interval = cfg.flip_rate + 1;

	return interval <= 1 || (cfg.vblank_status.count % static_cast<uint64_t>(interval)) == 0;
}

static bool IsValidBufferIndex(int index) {
	return index >= VIDEO_OUT_BUFFER_INDEX_BLACK && index < VIDEO_OUT_BUFFER_NUM_MAX;
}

static bool IsSpecialBufferIndex(int index) {
	return index == VIDEO_OUT_BUFFER_INDEX_BLANK || index == VIDEO_OUT_BUFFER_INDEX_BLACK;
}

static bool IsValidFlipMode(int mode) {
	return (mode >= VIDEO_OUT_FLIP_MODE_VSYNC && mode <= VIDEO_OUT_FLIP_MODE_VSYNC_MULTI) ||
	       mode == VIDEO_OUT_FLIP_MODE_SLAVE || mode == VIDEO_OUT_FLIP_MODE_MASTER;
}

static int ReserveFlipRequest(VideoOutDriver::Impl& driver, int handle, int index, int flip_mode,
                              int64_t flip_arg, FlipRequestSource source, uint64_t& request_id,
                              uint64_t expected_generation = 0) {
	uint64_t generation = 0;
	auto*    video_out  = driver.Get(handle, generation);
	if (video_out == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (!IsValidFlipMode(flip_mode)) {
		return VIDEO_OUT_ERROR_INVALID_FLIP_MODE;
	}
	if (!IsValidBufferIndex(index)) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}

	Common::LockGuard lock(video_out->mutex);
	if (!video_out->opened || video_out->closing || video_out->generation != generation ||
	    (expected_generation != 0 && generation != expected_generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if ((video_out->master != nullptr) != (flip_mode == VIDEO_OUT_FLIP_MODE_SLAVE) ||
	    (video_out->slave_count != 0) != (flip_mode == VIDEO_OUT_FLIP_MODE_MASTER)) {
		return VIDEO_OUT_ERROR_INVALID_FLIP_MODE;
	}
	if (video_out->closing ||
	    (!IsSpecialBufferIndex(index) && !video_out->buffers[index].Occupied())) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}
	if (!driver.GetFlipQueue().Reserve(*video_out, index, flip_arg, source, request_id)) {
		return VIDEO_OUT_ERROR_FLIP_QUEUE_FULL;
	}
	return OK;
}

Graphics::ImageInfo BufferAttributeGroup::ImageInfo(const VideoOutBuffer& buffer) const {
	// splash logo is CPU-written row by row (stride 0x1e00), reading it as tiled scrambles it
	const bool linear_scanout = attribute.tiling_mode == 1;
	const auto compression = Graphics::ClassifyVideoOutCompression(
	    category == VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_COMPRESSED, buffer.metadata_address,
	    attribute.dcc_control, attribute.dcc_cb_register_clear_color);
	if (attribute.reserved0 != 0 || attribute.aspect_ratio != 0 || attribute.width == 0 ||
	    attribute.height == 0 || attribute.width > 16384 || attribute.height > 16384 ||
	    attribute.pitch_in_pixel != 0 ||
	    (attribute.option & ~(VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_STRICT_COLORIMETRY |
	                          VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED)) != 0 ||
	    (attribute.tiling_mode != 0 && attribute.tiling_mode != 1 && attribute.tiling_mode != 4) ||
	    attribute.pad0 != 0 || attribute.reserved1[0] != 0 || attribute.reserved1[1] != 0 ||
	    attribute.reserved1[2] != 0 || buffer.data_address == 0 ||
	    compression == Graphics::VideoOutCompression::Unsupported) {
		EXIT("unsupported or invalid video-out surface attributes\n");
	}
	Graphics::VideoOutPixelFormatInfo pixel_format {};
	if (!Graphics::DecodeVideoOutPixelFormat(attribute.pixel_format, pixel_format)) {
		EXIT("unsupported video-out pixel format: 0x%016" PRIx64 "\n", attribute.pixel_format);
	}
	if (attribute.pixel_format == Graphics::VIDEO_OUT_PIXEL_FORMAT_R10_G10_B10_A2_BT2100_PQ) {
		static std::atomic_flag warned = ATOMIC_FLAG_INIT;
		if (!warned.test_and_set(std::memory_order_relaxed)) {
			Log::WriteToConsoleAndLog(fmt::format(
			    "Warning: HDR-to-SDR conversion is not implemented; displaying PQ video-out "
			    "pixels unchanged (format=0x{:016x}).\n", attribute.pixel_format));
		}
	}
	const auto tile_mode = linear_scanout ? Graphics::Prospero::TileMode::kLinear
	                                      : Graphics::Prospero::TileMode::kRenderTarget;
	const auto pitch =
	    Graphics::TileGetTexturePitch(pixel_format.guest_format, attribute.width, tile_mode);
	Graphics::TileSizeAlign total {};
	Graphics::TileGetTextureTotalSize(pixel_format.guest_format, attribute.width, attribute.height,
	                                  1, 1, tile_mode, false, total);
	const uint32_t required_alignment = linear_scanout ? 256u : 65536u;
	if (total.size == 0 || total.align != required_alignment ||
	    (buffer.data_address & (total.align - 1u)) != 0) {
		EXIT("invalid video-out surface footprint or alignment\n");
	}
	Graphics::ImageInfo info {};
	info.data            = {buffer.data_address, total.size};
	info.pixel_format    = pixel_format.format;
	info.guest_format    = pixel_format.guest_format;
	info.type            = Graphics::Prospero::ImageType::kColor2D;
	info.extent          = {attribute.width, attribute.height, 1};
	info.resources       = {1, 1};
	info.pitch           = pitch;
	info.bytes_per_block = pixel_format.bytes_per_element;
	info.samples         = 1;
	info.tile_mode       = tile_mode;
	info.bgra16          = pixel_format.bgra16;
	info.mip_layout[0]   = {0, total.size, pitch, attribute.height};
	if (compression != Graphics::VideoOutCompression::Uncompressed) {
		Graphics::TileSizeAlign dcc_size {};
		if (!Graphics::TileGetDccSize(attribute.width, attribute.height, 1,
		                              pixel_format.bytes_per_element, 1, tile_mode, dcc_size)) {
			EXIT("invalid video-out DCC footprint\n");
		}
		info.metadata.range       = {buffer.metadata_address, dcc_size.size};
		info.metadata.kind        = Graphics::ImageMetadataKind::Dcc;
		info.metadata.control     = attribute.dcc_control;
		info.metadata.compression = compression;
	}
	Graphics::ImageOps::Validate(info);
	if (!Graphics::IsSupportedVideoOutFormat(info)) {
		EXIT("unsupported normalized video-out format\n");
	}
	return info;
}

VideoOutDriver::VideoOutDriver(uint32_t width, uint32_t height, Graphics::Presenter& presenter)
    : m_impl(std::make_unique<Impl>(width, height, presenter)) {}

VideoOutDriver::~VideoOutDriver() = default;

VideoOutDriver::Impl& VideoOutDriver::State() noexcept {
	return *m_impl;
}

VideoOutDriver& VideoOutInit(uint32_t width, uint32_t height, Graphics::Presenter& presenter) {
	EXIT_IF(g_video_out_driver != nullptr);
	g_native_dce_owns_main_head.store(false, std::memory_order_release);
	g_native_splash_shared_main_leases.store(0, std::memory_order_release);
	g_native_virtual_display_clock.store(0, std::memory_order_release);
	{
		Common::LockGuard lock(g_native_controller_mutex);
		g_native_controllers = {};
	}
	g_video_out_driver = std::make_unique<VideoOutDriver>(width, height, presenter);
	g_video_out_ready.store(true, std::memory_order_release);
	return *g_video_out_driver;
}

void VideoOutShutdown() {
	g_video_out_ready.store(false, std::memory_order_release);
	g_native_dce_owns_main_head.store(false, std::memory_order_release);
	g_native_splash_shared_main_leases.store(0, std::memory_order_release);
	g_native_virtual_display_clock.store(0, std::memory_order_release);
	g_video_out_driver.reset();
	Common::LockGuard lock(g_native_controller_mutex);
	g_native_controllers = {};
}

VideoOutDriver::Impl::~Impl() {
	if (m_present_thread.joinable()) {
		m_present_thread.request_stop();
		m_present_thread.join();
	}
	for (const auto& event_state: m_sys_events) {
		VideoOutEventQueues vblank_events;
		VideoOutEventQueues set_mode_events;
		{
			Common::LockGuard event_lock(event_state->mutex);
			vblank_events   = event_state->vblank;
			set_mode_events = event_state->set_mode;
		}
		DeleteVideoOutEvents(vblank_events, VideoOutEventKind::Vblank);
		DeleteVideoOutEvents(set_mode_events, VideoOutEventKind::SetMode);
	}
	for (int handle = 1; handle < VIDEO_OUT_NUM_MAX; handle++) {
		if (m_video_out_ctx[handle].master != nullptr) {
			(void)Close(handle);
		}
	}
	for (int handle = 1; handle < VIDEO_OUT_NUM_MAX; handle++) {
		(void)Close(handle);
	}
}

void VideoOutDriver::Impl::Init(uint32_t width, uint32_t height) {
	for (auto& ctx: m_video_out_ctx) {
		ctx.width  = width;
		ctx.height = height;
	}
}

int VideoOutDriver::Impl::Open(int bus_type, int index, bool native_adapter, uint64_t* generation) {
	const auto bus = std::find(VIDEO_OUT_BUSES.begin(), VIDEO_OUT_BUSES.end(), bus_type);
	if (bus == VIDEO_OUT_BUSES.end()) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	EXIT_NOT_IMPLEMENTED(index != 0);
	Common::LockGuard lock(m_mutex);

	const int handle = static_cast<int>(bus - VIDEO_OUT_BUSES.begin()) + 1;
	if (m_video_out_ctx[handle].opened) {
		return VIDEO_OUT_ERROR_RESOURCE_BUSY;
	}
	auto&             config = m_video_out_ctx[handle];
	Common::LockGuard config_lock(config.mutex);

	{
		Common::LockGuard event_lock(config.events->mutex);
		EXIT_IF(!config.events->flip.empty());
		EXIT_IF(!config.events->pre_vblank.empty());
		EXIT_IF(!config.events->vblank.empty());
		EXIT_IF(!config.events->output_mode.empty());
		EXIT_IF(!config.events->set_mode.empty());
	}
	EXIT_IF(config.flip_rate != 0);
	for (const auto& buffer: config.buffers) {
		EXIT_IF(buffer.Occupied());
	}
	for (const auto& group: config.groups) {
		EXIT_IF(group.occupied);
	}

	config.closing = false;
	config.opened  = true;
	config.bus     = bus_type;
	if (++config.generation == 0) {
		EXIT("video-out port generation wrapped\n");
	}
	config.output_mode               = VIDEO_OUT_OUTPUT_MODE_DEFAULT;
	config.native_signal_width             = 0;
	config.native_signal_height            = 0;
	config.native_signal_h_total           = 0;
	config.native_signal_v_total           = 0;
	config.native_signal_refresh_hz        = 0.0f;
	config.native_signal_pixel_clock_10khz = 0;
	config.native_signal_pending           = false;
	config.native_signal_active            = false;
	config.native_signal_ppll_100hz        = 0;
	config.native_timing_generation        = 0;
	config.native_scanout_bound            = native_adapter;
	config.native_scanout_enabled          = false;
	config.native_splash_attribute_record.fill(0);
	config.native_splash_attributes_programmed = false;
	config.blank_after_resume                  = false;
	config.flip_status               = VideoOutFlipStatus();
	config.flip_status.flipArg       = -1;
	config.flip_status.currentBuffer = -1;
	config.flip_status.count         = 0;
	config.pre_vblank_status         = VideoOutVblankStatus();
	config.vblank_status             = VideoOutVblankStatus();
	if (generation != nullptr) *generation = config.generation;
	return handle;
}

bool VideoOutDriver::Impl::Close(int handle, uint64_t expected_generation, VideoOutCloseMode mode) {
	Common::LockGuard lock(m_mutex);

	if (handle <= 0 || handle >= VIDEO_OUT_NUM_MAX || !m_video_out_ctx[handle].opened) {
		return false;
	}

	auto&               config = m_video_out_ctx[handle];
	if (mode == VideoOutCloseMode::NativeClient && handle == 1 &&
	    g_native_dce_owns_main_head.load(std::memory_order_acquire) &&
	    g_native_splash_shared_main_leases.load(std::memory_order_acquire) != 0) {
		{
			Common::LockGuard config_lock(config.mutex);
			if (config.closing || expected_generation == 0 ||
			    config.generation != expected_generation)
				return false;
		}
		m_flip_queue.Cancel(config);
		{
			Common::LockGuard config_lock(config.mutex);
			for (auto& buffer: config.buffers)
				buffer = VideoOutBuffer {};
			for (auto& group: config.groups)
				group = BufferAttributeGroup {};
			config.native_splash_attributes_programmed = false;
			config.native_splash_attribute_record.fill(0);
			g_native_splash_shared_main_leases.store(0, std::memory_order_release);
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_VIDEOOUT_LEASE_RELEASED"
		     " main_head=1 generation=%" PRIu64 "\n",
		     expected_generation);
		return true;
	}
	VideoOutEventQueues flip_events;
	VideoOutEventQueues pre_vblank_events;
	VideoOutEventQueues vblank_events;
	VideoOutEventQueues output_mode_events;
	VideoOutEventQueues set_mode_events;
	VideoOutConfig* master = nullptr;
	{
		Common::LockGuard config_lock(config.mutex);
		if (config.closing ||
		    (expected_generation != 0 && config.generation != expected_generation)) {
			return false;
		}
		if (handle == 1 && mode == VideoOutCloseMode::Native &&
		    g_native_dce_owns_main_head.exchange(false, std::memory_order_acq_rel) &&
		    g_native_splash_shared_main_leases.load(std::memory_order_acquire) != 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_HEAD_OWNERSHIP_TRANSFERRED"
			     " main_head=1 owned_by_splash_lease\n");
			return true;
		}
		if (handle == 1 && mode != VideoOutCloseMode::Direct &&
		    g_native_splash_shared_main_leases.exchange(0, std::memory_order_acq_rel) != 0 &&
		    g_native_dce_owns_main_head.load(std::memory_order_acquire)) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_VIDEOOUT_LEASE_RELEASED"
			     " main_head=1 remains_open_for_DCE_owner\n");
			return true;
		}
		EXIT_IF(config.slave_count != 0);
		if (config.native_scanout_bound) {
			Common::LockGuard controller_lock(g_native_controller_mutex);
			auto&             controller = g_native_controllers[0];
			if (controller.bound_handle == handle &&
			    controller.bound_generation == config.generation) {
				controller.bound_handle     = -1;
				controller.bound_generation = 0;
				controller.pending          = false;
				controller.pending_timing   = {};
				controller.master_locked    = false;
				controller.scanout_enabled  = false;
			}
			config.native_scanout_bound   = false;
			config.native_scanout_enabled = false;
			config.native_signal_pending  = false;
			config.native_signal_active   = false;
			g_native_dce_owns_main_head.store(false, std::memory_order_release);
		}
		config.opened  = false;
		config.closing = true;
		if (++config.generation == 0) {
			EXIT("video-out port generation wrapped\n");
		}
		{
			Common::LockGuard event_lock(config.events->mutex);
			flip_events        = std::move(config.events->flip);
			pre_vblank_events  = std::move(config.events->pre_vblank);
			vblank_events      = std::move(config.events->vblank);
			output_mode_events = std::move(config.events->output_mode);
			set_mode_events    = std::move(config.events->set_mode);
		}
		config.flip_rate   = 0;
		config.blank_after_resume = false;
		master             = config.master;
		config.master      = nullptr;

		for (const auto& buffer: config.buffers) {
			if (buffer.Occupied() &&
			    (buffer.group_index >= VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX ||
			     buffer.data_address == 0 || !config.groups[buffer.group_index].occupied)) {
				EXIT("inconsistent registered video-out buffer state\n");
			}
		}
		for (auto& buffer: config.buffers) {
			buffer = VideoOutBuffer {};
		}
		for (auto& group: config.groups) {
			group = BufferAttributeGroup {};
		}
		config.vblank_cond.SignalAll();
	}
	if (master != nullptr) {
		Common::LockGuard master_lock(master->mutex);
		master->slave_count--;
	}
	m_flip_queue.Cancel(config);
	m_presenter.ClearLayer(config.bus);
	DeleteVideoOutEvents(flip_events, VideoOutEventKind::Flip);
	DeleteVideoOutEvents(pre_vblank_events, VideoOutEventKind::PreVblankStart);
	DeleteVideoOutEvents(vblank_events, VideoOutEventKind::Vblank);
	DeleteVideoOutEvents(output_mode_events, VideoOutEventKind::OutputMode);
	DeleteVideoOutEvents(set_mode_events, VideoOutEventKind::SetMode);
	return true;
}

VideoOutConfig* VideoOutDriver::Impl::Get(int handle) {
	Common::LockGuard lock(m_mutex);
	if (handle <= 0 || handle >= VIDEO_OUT_NUM_MAX || !m_video_out_ctx[handle].opened) {
		return nullptr;
	}

	return m_video_out_ctx + handle;
}

VideoOutConfig* VideoOutDriver::Impl::Get(int handle, uint64_t& generation) {
	Common::LockGuard lock(m_mutex);
	if (handle <= 0 || handle >= VIDEO_OUT_NUM_MAX || !m_video_out_ctx[handle].opened) {
		return nullptr;
	}

	auto*             config = m_video_out_ctx + handle;
	Common::LockGuard config_lock(config->mutex);
	if (!config->opened || config->closing) {
		return nullptr;
	}
	generation = config->generation;
	return config;
}

bool VideoOutDriver::Impl::IsOpened(int handle) {
	Common::LockGuard lock(m_mutex);

	return handle > 0 && handle < VIDEO_OUT_NUM_MAX && m_video_out_ctx[handle].opened;
}

int VideoOutDriver::Impl::SetFlipMaster(int slave_handle, int master_handle) {
	Common::LockGuard lock(m_mutex);
	if (slave_handle <= 0 || slave_handle >= VIDEO_OUT_NUM_MAX ||
	    master_handle <= 0 || master_handle >= VIDEO_OUT_NUM_MAX ||
	    !m_video_out_ctx[slave_handle].opened || !m_video_out_ctx[master_handle].opened) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	auto& slave  = m_video_out_ctx[slave_handle];
	auto& master = m_video_out_ctx[master_handle];
	if (&slave == &master) {
		return VIDEO_OUT_ERROR_UNSUPPORTED_OPERATION;
	}
	Common::LockGuard first_lock(m_video_out_ctx[std::min(slave_handle, master_handle)].mutex);
	Common::LockGuard second_lock(m_video_out_ctx[std::max(slave_handle, master_handle)].mutex);
	if (slave.master != nullptr || slave.slave_count != 0 || master.master != nullptr) {
		return VIDEO_OUT_ERROR_UNSUPPORTED_OPERATION;
	}
	if (slave.flip_status.flipPendingNum != 0 || master.flip_status.flipPendingNum != 0) {
		return VIDEO_OUT_ERROR_RESOURCE_BUSY;
	}
	slave.master = &master;
	master.slave_count++;
	return OK;
}

void VideoOutDriver::Impl::VblankBegin(std::span<VideoOutVblankPhase> phases) {
	Common::LockGuard lock(m_mutex);
	for (auto& phase: phases) {
		if (phase.config == nullptr) continue;
		auto&             ctx = *phase.config;
		Common::LockGuard context_lock(ctx.mutex);
		if (!IsVblankPhaseCurrentLocked(phase)) {
			phase.due            = false;
			phase.flip_available = false;
			continue;
		}
		ctx.pre_vblank_status.count++;
		ctx.pre_vblank_status.processTime        = LibKernel::KernelGetProcessTime();
		ctx.pre_vblank_status.reserved           = LibKernel::KernelReadTsc();
		ctx.pre_vblank_status.processTimeCounter = LibKernel::KernelGetProcessTimeCounter();
		TriggerVideoOutEvents(ctx, VideoOutEventKind::PreVblankStart,
		                      reinterpret_cast<void*>(ctx.pre_vblank_status.count));
	}
}

void VideoOutDriver::Impl::VblankEnd(std::span<const VideoOutVblankPhase> phases,
                                     bool                                 fallback_due) {
	Common::LockGuard lock(m_mutex);
	bool              head0_due = fallback_due;
	for (const auto& phase: phases) {
		if (phase.config == nullptr) continue;
		auto&             ctx = *phase.config;
		Common::LockGuard context_lock(ctx.mutex);
		const bool        current = IsVblankPhaseCurrentLocked(phase);
		if (phase.config == &m_video_out_ctx[1] && ctx.opened && ctx.native_scanout_bound) {
			head0_due = current;
		}
		if (!current) continue;
		ctx.vblank_status.count++;
		ctx.vblank_status.processTime        = LibKernel::KernelGetProcessTime();
		ctx.vblank_status.reserved           = LibKernel::KernelReadTsc();
		ctx.vblank_status.processTimeCounter = LibKernel::KernelGetProcessTimeCounter();
		TriggerVideoOutEvents(ctx, VideoOutEventKind::Vblank,
		                      reinterpret_cast<void*>(ctx.vblank_status.count));
		ctx.vblank_cond.SignalAll();
	}

	for (uint32_t head = 0; head < m_sys_events.size(); head++) {
		if (!(head == 0 ? head0_due : fallback_due)) continue;
		m_sys_vblank_status[head].count++;
		m_sys_vblank_status[head].processTime = LibKernel::KernelGetProcessTime();
		m_sys_vblank_status[head].reserved    = LibKernel::KernelReadTsc();
		VideoOutEventQueues queues;
		{
			Common::LockGuard event_lock(m_sys_events[head]->mutex);
			queues = m_sys_events[head]->vblank;
		}
		for (const auto& registration: queues) {
			const auto result =
			    EventQueue::KernelTriggerEvent(registration->handle, VideoOutSysVblankEventId(head),
				                               EventQueue::KERNEL_EVFILT_VIDEO_OUT, nullptr);
			EXIT_NOT_IMPLEMENTED(result != OK && result != LibKernel::KERNEL_ERROR_EBADF &&
			                     result != LibKernel::KERNEL_ERROR_ENOENT);
		}
	}
}

int VideoOutDriver::Impl::AddSysVblankEvent(EventQueue::KernelEqueue eq, uint32_t head,
                                            void* udata) {
	auto  event_state = m_sys_events[head];
	auto& queues      = event_state->vblank;

	EventQueue::KernelEqueueEvent event {};
	event.event.ident              = VideoOutSysVblankEventId(head);
	event.event.filter             = EventQueue::KERNEL_EVFILT_VIDEO_OUT;
	event.event.udata              = udata;
	event.filter.delete_event_func = RemoveVideoOutEventQueue;
	event.filter.reset_func        = ResetVideoOutEvent;
	event.filter.trigger_func      = TriggerVideoOutSysVblank;

	VideoOutEventRegistrationRef registration;
	bool                         add_queue = false;
	{
		Common::LockGuard event_lock(event_state->mutex);
		const auto        existing =
		    std::find_if(queues.begin(), queues.end(),
			             [eq](const auto& candidate) { return candidate->handle == eq; });
		if (existing != queues.end()) {
			registration = *existing;
		} else {
			registration = std::make_shared<VideoOutEventRegistration>(VideoOutEventRegistration {
			    .handle                = eq,
			    .state                 = event_state,
			    .kind                  = VideoOutEventKind::Vblank,
			    .original_native_ident = VideoOutSysVblankEventId(head)});
			queues.push_back(registration);
			add_queue = true;
		}
	}
	event.filter.data  = registration.get();
	event.filter.owner = registration;
	const int result   = EventQueue::KernelAddEvent(eq, event);
	if (result != OK && add_queue) {
		Common::LockGuard event_lock(event_state->mutex);
		const auto        added = std::find(queues.begin(), queues.end(), registration);
		if (added != queues.end()) {
			queues.erase(added);
		}
	}
	return result == LibKernel::KERNEL_ERROR_EBADF ? VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE : result;
}

size_t VideoOutDriver::Impl::SysVblankRegistrationCountForTest(uint32_t head) {
	auto              event_state = m_sys_events[head];
	Common::LockGuard event_lock(event_state->mutex);
	return event_state->vblank.size();
}

int VideoOutDriver::Impl::AddSysSetModeEvent(EventQueue::KernelEqueue eq, uint32_t head,
                                             void* udata) {
	auto  event_state = m_sys_events[head];
	auto& queues      = event_state->set_mode;

	EventQueue::KernelEqueueEvent event {};
	event.event.ident              = VideoOutSysSetModeEventId(head);
	event.event.filter             = EventQueue::KERNEL_EVFILT_VIDEO_OUT;
	event.event.udata              = udata;
	event.filter.delete_event_func = RemoveVideoOutEventQueue;
	event.filter.reset_func        = ResetVideoOutEvent;

	VideoOutEventRegistrationRef registration;
	bool                         add_queue = false;
	{
		Common::LockGuard event_lock(event_state->mutex);
		const auto        existing =
		    std::find_if(queues.begin(), queues.end(),
			             [eq](const auto& candidate) { return candidate->handle == eq; });
		if (existing != queues.end()) {
			registration = *existing;
		} else {
			registration = std::make_shared<VideoOutEventRegistration>(VideoOutEventRegistration {
			    .handle                = eq,
			    .state                 = event_state,
			    .kind                  = VideoOutEventKind::SetMode,
			    .original_native_ident = VideoOutSysSetModeEventId(head)});
			queues.push_back(registration);
			add_queue = true;
		}
	}
	event.filter.data  = registration.get();
	event.filter.owner = registration;
	const int result   = EventQueue::KernelAddEvent(eq, event);
	if (result != OK && add_queue) {
		Common::LockGuard event_lock(event_state->mutex);
		const auto        added = std::find(queues.begin(), queues.end(), registration);
		if (added != queues.end()) {
			queues.erase(added);
		}
	}
	return result == LibKernel::KERNEL_ERROR_EBADF ? VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE : result;
}

size_t VideoOutDriver::Impl::SysSetModeRegistrationCountForTest(uint32_t head) {
	auto              event_state = m_sys_events[head];
	Common::LockGuard event_lock(event_state->mutex);
	return event_state->set_mode.size();
}

void VideoOutDriver::Impl::GetSysVblankStatus(uint32_t head, VideoOutVblankStatus* status) {
	Common::LockGuard lock(m_mutex);

	*status = m_sys_vblank_status[head];
}

void VideoOutDriver::Impl::PresentThread(std::stop_token token) {
	const uint64_t frequency = Common::Timer::QueryPerformanceFrequency();
	EXIT_IF(frequency == 0);
	struct VblankClock {
		uint64_t deadline    = 0;
		uint64_t whole       = 1;
		uint64_t fraction    = 0;
		uint64_t denominator = 1;
		uint64_t remainder   = 0;
		void     Reset(uint64_t numerator, uint64_t divisor, uint64_t now, bool immediate) {
			whole       = std::max(numerator / divisor, uint64_t {1});
			fraction    = numerator % divisor;
			denominator = divisor;
			remainder   = immediate ? 0 : fraction;
			deadline    = immediate ? now : now + whole;
		}
		bool Poll(uint64_t now) {
			if (now < deadline) return false;
			uint64_t step = whole;
			remainder += fraction;
			if (remainder >= denominator) {
				remainder -= denominator;
				step++;
			}
			deadline += step;
			if (deadline <= now) deadline = now + step;
			return true;
		}
	};
	VblankClock fallback_clock;
	VblankClock native_clock;
	uint32_t    fallback_refresh         = 0;
	uint64_t    native_generation        = 0;
	uint64_t    native_timing_generation = 0;
	bool        native_running           = false;

	while (!token.stop_requested()) {
		const uint64_t frame_begin = Common::Timer::QueryPerformanceCounter();
		const uint32_t refresh     = std::max(Config::GetVblankFrequency(), 1u);
		if (fallback_refresh != refresh) {
			fallback_refresh = refresh;
			fallback_clock.Reset(frequency, refresh, frame_begin, true);
		}
		const bool fallback_due = fallback_clock.Poll(frame_begin);
		const bool paused       = m_presenter.IsGuestPaused();
		std::array<VideoOutVblankPhase, VIDEO_OUT_NUM_MAX> phases {};
		{
			Common::LockGuard lock(m_mutex);
			for (int handle = 1; handle < VIDEO_OUT_NUM_MAX; handle++) {
				auto&             ctx = m_video_out_ctx[handle];
				Common::LockGuard context_lock(ctx.mutex);
				auto&             phase = phases[handle];
				phase.config            = &ctx;
				phase.generation        = ctx.generation;
				phase.timing_generation = ctx.native_timing_generation;
				bool due                = fallback_due;
				if (handle == 1) {
					const bool running = ctx.opened && !ctx.closing && ctx.native_scanout_bound &&
					                     ctx.native_signal_active && ctx.native_scanout_enabled;
					if (running) {
						if (!native_running || native_generation != ctx.generation ||
						    native_timing_generation != ctx.native_timing_generation) {
							uint64_t numerator   = 0;
							uint64_t denominator = 0;
							EXIT_IF(!NativeVblankPeriod(
							    frequency, ctx.native_signal_h_total, ctx.native_signal_v_total,
							    ctx.native_signal_ppll_100hz, numerator, denominator));
							native_clock.Reset(numerator, denominator, frame_begin, false);
							native_generation        = ctx.generation;
							native_timing_generation = ctx.native_timing_generation;
						}
						due = native_clock.Poll(frame_begin);
					} else if (ctx.native_scanout_bound) {
						due = false;
					}
					native_running = running;
				}
				phase.due            = due && !paused && ctx.opened && !ctx.closing;
				phase.flip_available = phase.due;
			}
		}
		bool presented = false;
		if (paused) {
			if (fallback_due) presented = m_presenter.PresentLastFrame();
		} else {
			VblankBegin(phases);
			while (m_flip_queue.Flip(phases))
				presented = true;
		}
		if (fallback_due && !presented && m_presenter.NeedsSystemOverlayRefresh()) {
			if (m_presenter.PresentLastFrame()) {
				presented = true;
			} else {
				uint32_t width  = 0;
				uint32_t height = 0;
				{
					Common::LockGuard lock(m_mutex);
					width  = m_video_out_ctx[0].width;
					height = m_video_out_ctx[0].height;
				}
				auto& blank = m_presenter.PrepareBlankFrame(width, height, true);
				m_presenter.Present(blank);
				presented = true;
			}
		}
		if (fallback_due && !presented && !m_presenter.IsHeadless()) {
			bool     any_open = false;
			uint32_t width    = 0;
			uint32_t height   = 0;
			{
				Common::LockGuard lock(m_mutex);
				width  = m_video_out_ctx[0].width;
				height = m_video_out_ctx[0].height;
				for (int handle = 1; handle < VIDEO_OUT_NUM_MAX; handle++) {
					any_open |= m_video_out_ctx[handle].opened;
				}
			}
			if (!any_open) {
				static std::atomic_bool first_blank = false;
				if (!first_blank.exchange(true)) {
					LOGF("FIRST_FRAME_AUDIT host_blank_no_videoout width=%u height=%u\n", width,
					     height);
				}
				auto& blank = m_presenter.PrepareBlankFrame(width, height, true);
				m_presenter.Present(blank);
			}
		}
		if (!paused) VblankEnd(phases, fallback_due);
		const uint64_t frame_end = Common::Timer::QueryPerformanceCounter();
		if (frame_end - frame_begin >= frequency / 10) {
			LOGF("FIRST_FRAME_AUDIT host_vblank_iteration_slow work_ms=%" PRIu64 "\n",
			     (frame_end - frame_begin) * 1000 / frequency);
		}
		uint64_t next = fallback_clock.deadline;
		if (native_running) next = std::min(next, native_clock.deadline);
		if (next > frame_end) {
			const long double micros =
			    static_cast<long double>(next - frame_end) * 1000000.0L / frequency;
			Common::Thread::SleepMicro(
			    static_cast<uint32_t>(std::clamp(micros + 0.999L, 1.0L, 100000.0L)));
		}
	}
}

bool FlipQueue::Reserve(VideoOutConfig& cfg, int index, int64_t flip_arg, FlipRequestSource source,
                        uint64_t& request_id) {
	Common::LockGuard lock(m_mutex);

	// A newer slave request replaces the one not yet captured by a master flip.
	if (cfg.master != nullptr) {
		for (auto* queue: {&m_requests, &m_cpu_requests}) {
			for (auto it = queue->begin(); it != queue->end();) {
				if (it->cfg != &cfg || it->group != 0) {
					++it;
					continue;
				}
				cfg.flip_status.flipPendingNum--;
				cfg.flip_status.gcQueueNum -= it->source == FlipRequestSource::GpuEop;
				if (it->state == RequestState::Ready) {
					m_presenter.Discard(*it->frame);
					it = queue->erase(it);
				} else {
					auto cancelled = it++;
					m_cancelled_requests.splice(m_cancelled_requests.end(), *queue, cancelled);
				}
			}
		}
		m_done_cond_var.SignalAll();
	}
	if (cfg.flip_status.flipPendingNum >= VIDEO_OUT_FLIP_QUEUE_CAPACITY) {
		return false;
	}
	auto& pending = source == FlipRequestSource::GpuEop ? m_requests : m_cpu_requests;

	Request r {};
	r.id         = m_next_request_id++;
	r.group      = cfg.master == nullptr ? r.id : 0;
	r.cfg        = &cfg;
	r.master     = cfg.master;
	r.generation = cfg.generation;
	r.index      = index;
	r.flip_arg   = flip_arg;
	r.submit_ptc = LibKernel::KernelGetProcessTimeCounter();
	r.source     = source;
	r.state      = RequestState::Reserved;
	if (cfg.slave_count != 0) {
		for (auto* queue: {&m_requests, &m_cpu_requests}) {
			for (auto& slave: *queue) {
				if (slave.master == &cfg && slave.group == 0) {
					slave.group = r.id;
				}
			}
		}
	}

	pending.push_back(r);
	request_id = r.id;

	cfg.flip_status.flipPendingNum++;
	cfg.flip_status.submitProcessTimeCounter = r.submit_ptc;
	if (source == FlipRequestSource::GpuEop) {
		cfg.flip_status.gcQueueNum++;
	}

	return true;
}

FlipQueue::~FlipQueue() {
	for (auto* queue: {&m_requests, &m_cpu_requests, &m_cancelled_requests}) {
		for (auto& request: *queue) {
			if (request.frame != nullptr) {
				m_presenter.Discard(*request.frame);
			}
		}
	}
}

void FlipQueue::Cancel(VideoOutConfig& cfg) {
	std::vector<Graphics::Presenter::Frame*> frames;
	m_mutex.Lock();
	while (m_processing && std::any_of(m_requests.begin(), m_requests.end(), [&cfg](const auto& r) {
		       return r.cfg == &cfg && r.state == RequestState::Presenting;
	       })) {
		m_done_cond_var.Wait(&m_mutex);
	}
	for (auto* queue: {&m_requests, &m_cpu_requests}) {
		for (auto it = queue->begin(); it != queue->end();) {
			if (it->cfg != &cfg) {
				++it;
				continue;
			}
			if (it->state == RequestState::Reserved || it->state == RequestState::Recording) {
				auto cancelled = it++;
				m_cancelled_requests.splice(m_cancelled_requests.end(), *queue, cancelled);
				continue;
			}
			if (it->state == RequestState::Presenting) {
				EXIT("video-out cancellation retained a presenting request\n");
			}
			if (it->frame != nullptr) {
				frames.push_back(it->frame);
			}
			it = queue->erase(it);
		}
	}
	m_done_cond_var.SignalAll();
	m_submit_slot_cond_var.SignalAll();
	m_submit_cond_var.SignalAll();
	m_mutex.Unlock();
	for (auto* frame: frames) {
		m_presenter.Discard(*frame);
	}
	Common::LockGuard lock(cfg.mutex);
	cfg.flip_status.flipPendingNum = 0;
	cfg.flip_status.gcQueueNum     = 0;
}

void FlipQueue::Prepare(uint64_t request_id, Graphics::CommandBuffer& buffer) {
	VideoOutConfig* cfg        = nullptr;
	uint64_t        generation = 0;
	int             index      = 0;
	bool            cpu_request = false;
	{
		Common::LockGuard lock(m_mutex);
		auto request = std::find_if(m_requests.begin(), m_requests.end(),
		                            [request_id](const auto& r) { return r.id == request_id; });
		if (request == m_requests.end()) {
			auto pending = std::find_if(m_cpu_requests.begin(), m_cpu_requests.end(),
			                            [request_id](const auto& r) { return r.id == request_id; });
			if (pending == m_cpu_requests.end()) {
				auto cancelled =
				    std::find_if(m_cancelled_requests.begin(), m_cancelled_requests.end(),
				                 [request_id](const auto& r) { return r.id == request_id; });
				if (cancelled == m_cancelled_requests.end() ||
				    cancelled->state != RequestState::Reserved) {
					EXIT("cannot prepare video-out request id=%" PRIu64 "\n", request_id);
				}
				cancelled->state = RequestState::Recording;
				return;
			}
			request = m_requests.insert(m_requests.end(), *pending);
			m_cpu_requests.erase(pending);
		}
		if (request->state != RequestState::Reserved) {
			EXIT("cannot prepare video-out request id=%" PRIu64 "\n", request_id);
		}
		request->state = RequestState::Recording;
		cfg            = request->cfg;
		generation     = request->generation;
		index          = request->index;
		cpu_request    = request->source == FlipRequestSource::Cpu;
	}

	const bool          special = IsSpecialBufferIndex(index);
	Graphics::ImageInfo source_info;
	uint32_t            width   = 0;
	uint32_t            height  = 0;
	bool                current = false;
	bool                premultiplied_alpha = false;
	{
		Common::LockGuard lock(cfg->mutex);
		current = cfg->opened && !cfg->closing && cfg->generation == generation;
		if (current) {
			if (special) {
				width  = cfg->width;
				height = cfg->height;
			} else {
				const auto& surface = cfg->buffers[index];
				if (!surface.Occupied()) {
					EXIT("cannot prepare flip from an unregistered surface, id=%" PRIu64
					     " index=%d\n",
					     request_id, index);
				}
				if (surface.group_index >= VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX ||
				    !cfg->groups[surface.group_index].occupied) {
					EXIT("video-out surface references an unavailable attribute group, id=%" PRIu64
					     " index=%d group=%d\n",
					     request_id, index, surface.group_index);
				}
				source_info = cfg->groups[surface.group_index].ImageInfo(surface);
				premultiplied_alpha =
				    (cfg->groups[surface.group_index].attribute.option &
				     VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED) != 0;
			}
		}
	}
	if (!current) {
		Common::LockGuard lock(m_mutex);
		const auto        request =
		    std::find_if(m_requests.begin(), m_requests.end(),
		                 [request_id](const auto& r) { return r.id == request_id; });
		if (request != m_requests.end()) {
			m_cancelled_requests.splice(m_cancelled_requests.end(), m_requests, request);
		}
		return;
	}
	Graphics::Presenter::Frame* frame = nullptr;
	if (special) {
		frame = &m_presenter.PrepareBlankFrame(width, height, index == VIDEO_OUT_BUFFER_INDEX_BLACK,
		                                       &buffer);
	} else {
		frame = &m_presenter.PrepareFrame(buffer, source_info);
	}
	// request id + guest address vs SYSAV_DCE_REGISTER_CONFIRMED/FLIP_ACCEPTED tell SysAv frames
	// from other ports'
	if (cpu_request && !special && std::getenv("KYTY_DIAGNOSTIC_SYSAV_FRAME_READBACK") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_CPU_FLIP_SOURCE_PREPARED"
		     " request=%" PRIu64 " index=%d guest_addr=0x%016" PRIx64 " extent=%ux%u\n",
		     request_id, index, source_info.data.address, source_info.extent.width,
		     source_info.extent.height);
	}

	Common::LockGuard lock(m_mutex);
	Request*          prepared = nullptr;
	if (const auto request =
	        std::find_if(m_requests.begin(), m_requests.end(),
	                     [request_id](const auto& r) { return r.id == request_id; });
	    request != m_requests.end()) {
		prepared = &*request;
	} else if (const auto cancelled =
	               std::find_if(m_cancelled_requests.begin(), m_cancelled_requests.end(),
	                            [request_id](const auto& r) { return r.id == request_id; });
	           cancelled != m_cancelled_requests.end()) {
		prepared = &*cancelled;
	}
	if (prepared == nullptr || prepared->state != RequestState::Recording ||
	    prepared->frame != nullptr) {
		EXIT("video-out request changed while recording, id=%" PRIu64 "\n", request_id);
	}
	prepared->frame = frame;
	prepared->premultiplied_alpha = premultiplied_alpha;
}

void FlipQueue::Complete(uint64_t request_id) {
	m_mutex.Lock();
	auto request = std::find_if(m_requests.begin(), m_requests.end(),
	                            [request_id](const auto& r) { return r.id == request_id; });
	if (request != m_requests.end()) {
		if (request->state != RequestState::Recording || request->frame == nullptr) {
			m_mutex.Unlock();
			EXIT("completed GPU flip has no prepared recording, id=%" PRIu64 "\n", request_id);
		}
		request->state = RequestState::Ready;
		m_submit_cond_var.Signal();
		m_mutex.Unlock();
		return;
	}
	auto cancelled = std::find_if(m_cancelled_requests.begin(), m_cancelled_requests.end(),
	                              [request_id](const auto& r) { return r.id == request_id; });
	if (cancelled == m_cancelled_requests.end() || cancelled->state != RequestState::Recording) {
		m_mutex.Unlock();
		EXIT("completed GPU flip has no prepared recording, id=%" PRIu64 "\n", request_id);
	}
	auto* frame = cancelled->frame;
	m_cancelled_requests.erase(cancelled);
	m_done_cond_var.SignalAll();
	m_mutex.Unlock();
	if (frame != nullptr) {
		m_presenter.Discard(*frame);
	}
}

void FlipQueue::WaitForSubmitSlot(VideoOutConfig& cfg) {
	Common::LockGuard lock(m_mutex);
	auto belongs_to_port = [&cfg](const auto& request) { return request.cfg == &cfg; };
	while (std::count_if(m_requests.begin(), m_requests.end(), belongs_to_port) +
	           std::count_if(m_cpu_requests.begin(), m_cpu_requests.end(), belongs_to_port) >=
	       VIDEO_OUT_FLIP_QUEUE_CAPACITY) {
		if (m_requests.empty()) {
			EXIT("video-out queue is saturated by CPU flips queued behind the current EOP\n");
		}
		m_submit_slot_cond_var.Wait(&m_mutex);
	}
}

void FlipQueue::Wait(VideoOutConfig& cfg, int index, uint64_t generation) {
	Common::LockGuard lock(m_mutex);

	auto has_request = [this, &cfg, index, generation] {
		auto matches = [&cfg, index, generation](const auto& r) {
			return r.cfg == &cfg && r.index == index &&
			       (generation == 0 || r.generation == generation);
		};
		return std::any_of(m_requests.begin(), m_requests.end(), matches) ||
		       std::any_of(m_cpu_requests.begin(), m_cpu_requests.end(), matches);
	};
	while (has_request()) {
		m_done_cond_var.Wait(&m_mutex);
	}
}

bool FlipQueue::Flip(std::span<VideoOutVblankPhase> phases) {
	KYTY_PROFILER_BLOCK("FlipQueue::Flip");
	for (;;) {
		m_mutex.Lock();
		EXIT_IF(m_processing);
		auto                 owner       = m_requests.end();
		VideoOutVblankPhase* owner_phase = nullptr;
		for (auto candidate = m_requests.begin(); candidate != m_requests.end(); ++candidate) {
			if (candidate->group != candidate->id || candidate->state != RequestState::Ready)
				continue;
			auto phase = std::find_if(phases.begin(), phases.end(), [&](const auto& value) {
				return value.flip_available && value.config == candidate->cfg &&
				       value.generation == candidate->generation;
			});
			if (phase == phases.end()) continue;
			auto earlier_owner = [&](const auto& value) {
				return value.cfg == candidate->cfg && value.group == value.id &&
				       value.id < candidate->id;
			};
			auto group_pending = [&](const auto& value) { return value.group == candidate->id; };
			if (std::any_of(m_requests.begin(), m_requests.end(), earlier_owner) ||
			    std::any_of(m_cpu_requests.begin(), m_cpu_requests.end(), earlier_owner) ||
			    std::any_of(m_cpu_requests.begin(), m_cpu_requests.end(), group_pending) ||
			    std::any_of(m_requests.begin(), m_requests.end(), [&](const auto& value) {
				    return group_pending(value) && value.state != RequestState::Ready;
			    })) {
				continue;
			}
			if (owner == m_requests.end() || candidate->id < owner->id) {
				owner       = candidate;
				owner_phase = &*phase;
			}
		}
		if (owner == m_requests.end()) {
			m_mutex.Unlock();
			return false;
		}
		const uint64_t group        = owner->id;
		owner_phase->flip_available = false;
		std::array<Request, VideoOutDriver::Impl::VIDEO_OUT_BUSES.size()> requests {};
		size_t                                                            count = 0;
		for (auto& request: m_requests) {
			if (request.group == group) {
				EXIT_IF(count == requests.size());
				request.state     = RequestState::Presenting;
				requests[count++] = request;
			}
		}
		m_processing = true;
		m_mutex.Unlock();

		std::sort(requests.begin(), requests.begin() + count,
		          [](const auto& a, const auto& b) { return a.cfg->bus < b.cfg->bus; });
		bool due = true;
		std::array<Graphics::Presenter::Layer, VideoOutDriver::Impl::VIDEO_OUT_BUSES.size()>
		    layers {};
		for (size_t i = 0; i < count; i++) {
			auto& r = requests[i];
			r.cfg->mutex.Lock();
			due &= r.cfg->opened && !r.cfg->closing && r.cfg->generation == r.generation;
			due &= !r.cfg->native_scanout_bound ||
			       (r.cfg->native_signal_active && r.cfg->native_scanout_enabled);
			if (r.id == group) {
				due &= IsVblankPhaseCurrentLocked(*owner_phase) &&
				       IsFlipDueLocked(*r.cfg, r.generation);
			}
			int present_bus = r.cfg->bus;
			if (present_bus == VIDEO_OUT_BUS_TYPE_SYSTEM &&
			    std::getenv("KYTY_DIAGNOSTIC_SYSTEM_BUS_TO_MAIN_LAYER") != nullptr) {
				EXIT_NOT_IMPLEMENTED(count != 1);
				present_bus                               = VIDEO_OUT_BUS_TYPE_MAIN;
				static std::atomic_bool logged_system_bus = false;
				if (!logged_system_bus.exchange(true)) {
					LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_SYSTEM_BUS_TO_MAIN_LAYER"
					     " source_bus=0x100 target_bus=0 count=%zu NON_AUTHENTIC\n",
					     count);
				}
			}
			layers[i] = {r.frame, present_bus, r.premultiplied_alpha};
		}
		if (due) {
			static std::atomic_bool first_guest_present = false;
			if (!first_guest_present.exchange(true)) {
				LOGF("FIRST_FRAME_AUDIT first_guest_present_attempt layers=%zu request=%" PRIu64
				     "\n",
				     count, group);
			}
			m_presenter.Present(std::span(layers.data(), count));
			if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_FRAME_READBACK") != nullptr) {
				for (size_t i = 0; i < count; i++) {
					const auto& r = requests[i];
					if (r.source == FlipRequestSource::Cpu) {
						LOGF("FIRST_FRAME_AUDIT SYSAV_CPU_FLIP_PRESENTER_INVOKED"
						     " request=%" PRIu64 " index=%d bus=%d\n",
						     r.id, r.index, r.cfg->bus);
					}
				}
			}
			if (std::getenv("KYTY_DIAGNOSTIC_HOLD_FIRST_PRESENT") != nullptr &&
			    first_guest_present.load()) {
				static std::atomic_bool held = false;
				if (!held.exchange(true)) {
					LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_HOST_PRESENT_RETURNED holding_2000ms"
					     " FOR_WINDOW_SAMPLING\n");
					std::this_thread::sleep_for(std::chrono::milliseconds(2000));
				}
			}
		}

		m_mutex.Lock();
		for (auto it = m_requests.begin(); it != m_requests.end();) {
			if (it->group != group) {
				++it;
				continue;
			}
			if (!due) {
				it++->state = RequestState::Ready;
				continue;
			}
			auto& r = *it;
			r.cfg->flip_status.count++;
			r.cfg->flip_status.processTime              = LibKernel::KernelGetProcessTime();
			r.cfg->flip_status.processTimeCounter       = LibKernel::KernelGetProcessTimeCounter();
			r.cfg->flip_status.submitProcessTimeCounter = r.submit_ptc;
			r.cfg->flip_status.flipArg                  = r.flip_arg;
			r.cfg->flip_status.currentBuffer            = r.index;
			r.cfg->flip_status.flipPendingNum--;
			r.cfg->flip_status.gcQueueNum -= r.source == FlipRequestSource::GpuEop;
			TriggerVideoOutEvents(*r.cfg, VideoOutEventKind::Flip,
			                      reinterpret_cast<void*>(r.flip_arg));
			it = m_requests.erase(it);
		}
		m_processing = false;
		m_done_cond_var.SignalAll();
		m_submit_slot_cond_var.SignalAll();
		m_mutex.Unlock();
		for (size_t i = count; i != 0; i--) {
			requests[i - 1].cfg->mutex.Unlock();
		}
		if (due) {
			Graphics::RenderDocOnGuestFlip(m_presenter.Renderer());
			if (Config::GraphicsDebugDumpEnabled() &&
			    Config::GetPrintfDirection() != Config::LogDirection::Silent) {
				LOGF("Flip done: %d\n", requests[0].index);
			}
		}
		if (due) return true;
	}
}

void FlipQueue::GetFlipStatus(VideoOutConfig& cfg, VideoOutFlipStatus& out) {
	Common::LockGuard lock(cfg.mutex);

	out = cfg.flip_status;
}

KYTY_SYSV_ABI int VideoOutSetFlipMaster(int slave_handle, int master_handle) {
	PRINT_NAME();
	return DriverState().SetFlipMaster(slave_handle, master_handle);
}

KYTY_SYSV_ABI void VideoOutAddBufferAttributeOption(VideoOutBufferAttribute2* attribute,
                                                   uint64_t option) {
	PRINT_NAME();
	EXIT_IF(attribute == nullptr);
	attribute->option |= option;
}

KYTY_SYSV_ABI int VideoOutGetOccupiedPrivacyMask(uint64_t* mask) {
	PRINT_NAME();
	if (g_video_out_driver == nullptr) {
		return VIDEO_OUT_ERROR_FATAL;
	}
	if (mask == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}
	*mask                                       = DriverState().OccupiedPrivacyMask();
	static std::atomic_bool first_privacy_query = false;
	if (!first_privacy_query.exchange(true)) {
		LOGF("FIRST_FRAME_AUDIT DCE_PRIVACY_QUERY mask=0x%016" PRIx64
		     " DIAGNOSTIC_BASELINE_NO_RELEASE_MODEL\n",
		     *mask);
	}
	return OK;
}

static int OpenVideoOut(int user_id, int bus_type, int index, const void* param,
                        uint64_t* generation, bool native_client = false) {
	EXIT_NOT_IMPLEMENTED(user_id != 255 && user_id != 0);
	LOGF("\t param = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(param));

	const int handle = DriverState().Open(bus_type, index, false, generation);
	if (handle == VIDEO_OUT_ERROR_RESOURCE_BUSY &&
	    (native_client || std::getenv("KYTY_DIAGNOSTIC_SYSAV_SPLASH_SHARE_DCE_HEAD") != nullptr) &&
	    user_id == 0 && bus_type == VIDEO_OUT_BUS_TYPE_MAIN && index == 0 && param == nullptr &&
	    g_native_dce_owns_main_head.load(std::memory_order_acquire)) {
		// DCE and sceVideoOutOpen share MAIN here, so lease the open head rather than RESOURCE_BUSY
		auto* ctx = DriverState().Get(1);
		if (ctx != nullptr) {
			Common::LockGuard lock(ctx->mutex);
			uint32_t          expected = 0;
			const bool        real_head_eligible =
			    ctx->opened && !ctx->closing && ctx->native_scanout_bound &&
			    g_native_dce_owns_main_head.load(std::memory_order_acquire) &&
			    (ctx->native_signal_active || ctx->native_signal_pending) &&
			    (ctx->native_signal_width == 3840 || ctx->native_signal_width == 1920) &&
			    g_native_splash_shared_main_leases.compare_exchange_strong(
			        expected, 1, std::memory_order_acq_rel);
			if (real_head_eligible) {
				if (generation != nullptr) *generation = ctx->generation;
				LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_VIDEOOUT_HEAD_LEASE_GRANTED"
				     " sceVideoOutOpen_user=0_bus=MAIN shared_head=1"
				     " existing_signal=%ux%u pending=%u active=%u\n",
				     ctx->native_signal_width, ctx->native_signal_height,
				     ctx->native_signal_pending ? 1u : 0u, ctx->native_signal_active ? 1u : 0u);
				return 1;
			}
		}
	}
	if (handle >= 0) {
		static std::atomic_bool first_open = false;
		if (!first_open.exchange(true)) {
			LOGF("FIRST_FRAME_AUDIT first_videoout_open user=%d bus=%d index=%d handle=%d\n",
			     user_id, bus_type, index, handle);
		}
	}
	return handle;
}

KYTY_SYSV_ABI int VideoOutOpen(int user_id, int bus_type, int index, const void* param) {
	PRINT_NAME();
	return OpenVideoOut(user_id, bus_type, index, param, nullptr);
}

int VideoOutNativeAcquireSplashHandle(int*      native_display_handle,
                                      uint64_t* native_display_generation) {
	if (!VideoOutIsInitialized() || native_display_handle == nullptr ||
	    native_display_generation == nullptr || *native_display_handle >= 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	uint64_t  generation = 0;
	const int handle     = OpenVideoOut(0, VIDEO_OUT_BUS_TYPE_MAIN, 0, nullptr, &generation, true);
	if (handle < 0) return handle;
	*native_display_handle     = handle;
	*native_display_generation = generation;
	return OK;
}

KYTY_SYSV_ABI int VideoOutClose(int handle) {
	PRINT_NAME();
	return DriverState().Close(handle, 0, VideoOutCloseMode::User) ? OK
	                                                               : VIDEO_OUT_ERROR_INVALID_HANDLE;
}

KYTY_SYSV_ABI void VideoOutSetBufferAttribute2(VideoOutBufferAttribute2* attribute,
                                               uint64_t pixel_format, uint32_t tiling_mode,
                                               uint32_t width, uint32_t height, uint64_t option,
                                               uint32_t dcc_control,
                                               uint64_t dcc_cb_register_clear_color) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(attribute == nullptr);

	LOGF("\t pixel_format                = %016" PRIx64 "\n"
	     "\t tiling_mode                 = %" PRIu32 "\n"
	     "\t width                       = %" PRIu32 "\n"
	     "\t height                      = %" PRIu32 "\n"
	     "\t option                      = %016" PRIx64 "\n"
	     "\t dcc_control                 = %08" PRIx32 "\n"
	     "\t dcc_cb_register_clear_color = %016" PRIx64 "\n",
	     pixel_format, tiling_mode, width, height, option, dcc_control,
	     dcc_cb_register_clear_color);

	memset(attribute, 0, sizeof(VideoOutBufferAttribute2));

	attribute->tiling_mode                 = tiling_mode;
	attribute->aspect_ratio                = 0;
	attribute->width                       = width;
	attribute->height                      = height;
	attribute->pitch_in_pixel              = 0;
	attribute->option                      = option;
	attribute->pixel_format                = pixel_format;
	attribute->dcc_cb_register_clear_color = dcc_cb_register_clear_color;
	attribute->dcc_control                 = dcc_control;
}

static int RegisterBuffersWithGeneration(int handle, int set_index, int buffer_index_start,
                                         const VideoOutBuffers* buffers, int buffer_num,
                                         const VideoOutBufferAttribute2* attribute, int category,
                                         void* option, uint64_t expected_generation);
static int SubmitFlipWithGeneration(int handle, int index, int flip_mode, int64_t flip_arg,
                                    uint64_t expected_generation);

int VideoOutNativeProgramDisplayClock(uint32_t requested_rate, uint32_t* applied_rate) {
	// 120000 = SysAvControl PLL_SET_DISPCLK (0x45A110)
	if (!VideoOutIsInitialized() || applied_rate == nullptr || requested_rate != 120000u) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	g_native_virtual_display_clock.store(requested_rate, std::memory_order_release);
	*applied_rate = requested_rate;
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_VIRTUAL_DISPLAY_CLOCK_PROGRAMMED"
	     " display_clock_10khz=%u\n",
	     requested_rate);
	return OK;
}

int VideoOutNativeGetControllerSnapshot(uint32_t                          original_port,
                                        VideoOutNativeControllerSnapshot* snapshot) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() ||
	    snapshot == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	*snapshot                     = g_native_controllers[original_port];
	snapshot->display_clock_10khz = g_native_virtual_display_clock.load(std::memory_order_acquire);
	return OK;
}

uint64_t VideoOutNativeGetHandleGeneration(int native_display_handle) {
	if (!VideoOutIsInitialized()) return 0;
	uint64_t generation = 0;
	return DriverState().Get(native_display_handle, generation) != nullptr ? generation : 0;
}

int VideoOutNativeProgramMasterUpdateLock(uint32_t original_port, uint32_t enabled) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() || enabled > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	auto&             controller = g_native_controllers[original_port];
	if (!controller.pending) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	controller.master_locked = enabled != 0;
	LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_MASTER_UPDATE_LOCK"
	     " port=%u enabled=%u transaction=%" PRIu64 "\n",
	     original_port, enabled, controller.transaction_id);
	return OK;
}

int VideoOutNativeProgramPixelClock(uint32_t original_port, uint32_t raw_rate_100hz) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() ||
	    raw_rate_100hz < 200000u || raw_rate_100hz > 12000000u) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	auto&             controller = g_native_controllers[original_port];
	if (!controller.pending || !controller.master_locked ||
	    g_native_virtual_display_clock.load(std::memory_order_acquire) != 120000u) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	const auto&    timing = controller.pending_timing;
	const uint32_t expected_rate =
	    original_port == 0 && timing.width == 720 && timing.height == 480     ? 270000u
		: original_port == 0 && timing.width == 3840 && timing.height == 2160 ? 5934066u
		: original_port == 1 && timing.width == 1920 && timing.height == 1080 ? 1483516u
		                                                                      : 0u;
	if (raw_rate_100hz != expected_rate) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	controller.pending_timing.ppll_rate_100hz   = raw_rate_100hz;
	controller.pending_timing.ppll_programmed   = true;
	controller.pending_timing.timing_programmed = false;
	LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_PIXEL_PLL_PROGRAMMED"
	     " ioctl=0xC0089A0D port=%u raw_rate_100hz=%u"
	     " transaction=%" PRIu64 " pending_only\n",
	     original_port, raw_rate_100hz, controller.transaction_id);
	return OK;
}

int VideoOutNativeProgramOtgTiming(uint32_t original_port, const uint32_t* original_registers,
                                   size_t register_count) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() ||
	    original_registers == nullptr || register_count != 16) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	auto&             controller = g_native_controllers[original_port];
	auto&             timing     = controller.pending_timing;
	const bool        hdmi       = original_port == 0;
	const bool        hdmi_480   = hdmi && timing.width == 720 && timing.height == 480;
	if (!controller.pending || !controller.master_locked || !timing.ppll_programmed ||
	    timing.ppll_rate_100hz != (hdmi_480 ? 270000u
	                               : hdmi   ? 5934066u
	                                        : 1483516u) ||
	    original_registers[0] != timing.pixel_clock_10khz ||
	    original_registers[1] != timing.h_total - 1 ||
	    original_registers[2] != (hdmi_480 ? 842u
	                              : hdmi   ? 4224u
	                                       : 2112u) ||
	    original_registers[3] != (hdmi_480 ? 122u
	                              : hdmi   ? 384u
	                                       : 192u) ||
	    original_registers[4] != 0 ||
	    original_registers[5] != (hdmi_480 ? 62u
	                              : hdmi   ? 88u
	                                       : 44u) ||
	    original_registers[6] != timing.v_total - 1 ||
	    original_registers[7] != (hdmi_480 ? 516u
	                              : hdmi   ? 2242u
	                                       : 1121u) ||
	    original_registers[8] != (hdmi_480 ? 36u
	                              : hdmi   ? 82u
	                                       : 41u) ||
	    original_registers[9] != 0 ||
	    original_registers[10] != (hdmi_480 ? 6u
	                               : hdmi   ? 10u
	                                        : 5u) ||
	    original_registers[11] != 0x426fc28fu || original_registers[12] != 0 ||
	    original_registers[13] != 0 || original_registers[14] != 0 || original_registers[15] != 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	std::copy_n(original_registers, timing.otg_timing.size(), timing.otg_timing.begin());
	timing.timing_programmed = true;
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_OTG_TIMING_PROGRAMMED"
	     " port=%u transaction=%" PRIu64 " pending_only\n",
	     original_port, controller.transaction_id);
	return OK;
}

int VideoOutNativeProgramOtgControl(uint32_t original_request, uint32_t original_port,
                                    uint32_t original_value) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() ||
	    original_value > 1 ||
	    (original_request != 0xc0089a01u && original_request != 0xc0089a04u)) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	auto update = [&](VideoOutConfig* ctx) {
		Common::LockGuard lock(g_native_controller_mutex);
		auto&             controller = g_native_controllers[original_port];
		auto&             timing     = controller.pending_timing;
		if (original_request == 0xc0089a01u && original_value == 0) {
			if (controller.pending) {
				timing.otg_enabled           = false;
				timing.double_buffer_enabled = false;
			}
			if (controller.scanout_enabled) {
				controller.scanout_enabled = false;
				if (++controller.timing_generation == 0) {
					EXIT("native display timing generation wrapped\n");
				}
				if (ctx != nullptr && ctx->opened && !ctx->closing &&
				    controller.bound_handle == 1 &&
				    controller.bound_generation == ctx->generation) {
					ctx->native_scanout_enabled   = false;
					ctx->native_timing_generation = controller.timing_generation;
				}
			}
		} else if (original_request == 0xc0089a01u && !controller.pending) {
			if (!controller.committed || ctx == nullptr || !ctx->opened || ctx->closing ||
			    !ctx->native_signal_active || !ctx->native_scanout_bound ||
			    controller.bound_handle != 1 || controller.bound_generation != ctx->generation) {
				return VIDEO_OUT_ERROR_INVALID_VALUE;
			}
			if (!controller.scanout_enabled) {
				controller.scanout_enabled = true;
				if (++controller.timing_generation == 0) {
					EXIT("native display timing generation wrapped\n");
				}
				ctx->native_scanout_enabled   = true;
				ctx->native_timing_generation = controller.timing_generation;
			}
		} else {
			if (!controller.pending) return VIDEO_OUT_ERROR_INVALID_VALUE;
			if (original_request == 0xc0089a04u) {
				timing.double_buffer_enabled = original_value != 0;
			} else {
				if (!controller.master_locked || !timing.timing_programmed ||
				    !timing.double_buffer_enabled) {
					return VIDEO_OUT_ERROR_INVALID_VALUE;
				}
				timing.otg_enabled = true;
			}
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_OTG_CONTROL_PROGRAMMED"
		     " ioctl=0x%08x port=%u value=%u"
		     " transaction=%" PRIu64 " scanout_enabled=%u\n",
		     original_request, original_port, original_value, controller.transaction_id,
		     controller.scanout_enabled ? 1u : 0u);
		return OK;
	};
	if (original_port == 0 && original_request == 0xc0089a01u) {
		if (auto* ctx = DriverState().Get(1); ctx != nullptr) {
			Common::LockGuard lock(ctx->mutex);
			return update(ctx);
		}
	}
	return update(nullptr);
}

int VideoOutNativeProgramFormatControl(uint32_t original_request, uint32_t original_port,
                                       uint32_t original_value) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size() ||
	    original_value != 0 ||
	    (original_request != 0xc0089a13u && original_request != 0xc0089a14u)) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	Common::LockGuard lock(g_native_controller_mutex);
	auto&             controller = g_native_controllers[original_port];
	auto&             timing     = controller.pending_timing;
	if (!controller.pending || controller.master_locked || !timing.timing_programmed ||
	    !timing.otg_enabled) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (original_request == 0xc0089a13u) {
		timing.pixel_encoding            = original_value;
		timing.pixel_encoding_programmed = true;
	} else {
		timing.subsampling            = original_value;
		timing.subsampling_programmed = true;
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_FORMAT_PROGRAMMED"
	     " ioctl=0x%08x port=%u value=%u transaction=%" PRIu64 "\n",
	     original_request, original_port, original_value, controller.transaction_id);
	return OK;
}

int VideoOutNativeConfigureDisplaySignal(int* native_display_handle, uint32_t original_port,
                                         uint32_t signal_width, uint32_t signal_height,
                                         uint32_t h_total, uint32_t v_total, float refresh_hz,
                                         uint32_t  pixel_clock_10khz,
                                         uint64_t* native_display_generation) {
	const bool hdmi =
	    original_port == 0 && ((signal_width == 3840 && signal_height == 2160 && h_total == 4400 &&
		                        v_total == 2250 && pixel_clock_10khz == 59341) ||
		                       (signal_width == 720 && signal_height == 480 && h_total == 858 &&
		                        v_total == 525 && pixel_clock_10khz == 2700));
	const bool type_c = original_port == 1 && signal_width == 1920 && signal_height == 1080 &&
	                    h_total == 2200 && v_total == 1125 && pixel_clock_10khz == 14836;
	if (!VideoOutIsInitialized() || native_display_handle == nullptr || (!hdmi && !type_c) ||
	    !(refresh_hz >= 59.90f && refresh_hz <= 59.97f)) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	auto stage = [&](VideoOutConfig* ctx, int handle, uint64_t generation) {
		Common::LockGuard lock(g_native_controller_mutex);
		auto&             controller = g_native_controllers[original_port];
		if (g_native_virtual_display_clock.load(std::memory_order_acquire) != 120000u) {
			return VIDEO_OUT_ERROR_INVALID_VALUE;
		}
		if (controller.pending && controller.master_locked) {
			return VIDEO_OUT_ERROR_RESOURCE_BUSY;
		}
		if (hdmi &&
		    (ctx == nullptr || !ctx->opened || ctx->closing || ctx->generation != generation ||
		     !ctx->native_scanout_bound ||
		     (controller.bound_handle >= 0 &&
		      (controller.bound_handle != handle || controller.bound_generation != generation)))) {
			return VIDEO_OUT_ERROR_INVALID_HANDLE;
		}
		VideoOutNativeTimingSnapshot timing {};
		timing.width              = signal_width;
		timing.height             = signal_height;
		timing.h_total            = h_total;
		timing.v_total            = v_total;
		timing.refresh_hz         = refresh_hz;
		timing.pixel_clock_10khz  = pixel_clock_10khz;
		controller.pending_timing = timing;
		controller.pending        = true;
		controller.master_locked  = false;
		if (++controller.transaction_id == 0) EXIT("native display transaction wrapped\n");
		if (hdmi) {
			controller.bound_handle       = handle;
			controller.bound_generation   = generation;
			ctx->native_signal_pending    = true;
			ctx->native_timing_generation = controller.timing_generation;
			*native_display_handle        = handle;
			if (native_display_generation != nullptr) *native_display_generation = generation;
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_SIGNAL_PENDING"
		     " port=%u signal=%ux%u transaction=%" PRIu64
		     " bound_handle=%d bound_generation=%" PRIu64 " committed_unchanged=%u\n",
		     original_port, signal_width, signal_height, controller.transaction_id,
		     controller.bound_handle, controller.bound_generation, controller.committed ? 1u : 0u);
		return OK;
	};
	if (type_c) return stage(nullptr, -1, 0);
	bool     opened_here = false;
	int      handle      = *native_display_handle;
	uint64_t generation  = 0;
	if (handle < 0) {
		{
			Common::LockGuard lock(g_native_controller_mutex);
			if (g_native_virtual_display_clock.load(std::memory_order_acquire) != 120000u) {
				return VIDEO_OUT_ERROR_INVALID_VALUE;
			}
		}
		handle = DriverState().Open(VIDEO_OUT_BUS_TYPE_MAIN, 0, true, &generation);
		if (handle < 0) return handle;
		opened_here = true;
	}
	uint64_t current_generation = 0;
	auto*    ctx                = DriverState().Get(handle, current_generation);
	if (!opened_here) generation = current_generation;
	int result = VIDEO_OUT_ERROR_INVALID_HANDLE;
	if (ctx != nullptr && current_generation == generation) {
		Common::LockGuard lock(ctx->mutex);
		if (opened_here || native_display_generation == nullptr ||
		    *native_display_generation == generation) {
			result = stage(ctx, handle, generation);
		}
		if (result == OK && opened_here) {
			g_native_dce_owns_main_head.store(true, std::memory_order_release);
		}
	}
	if (result != OK && opened_here) (void)DriverState().Close(handle, generation);
	return result;
}

int VideoOutNativeFinishDisplaySignal(uint32_t original_port, uint64_t expected_generation) {
	if (!VideoOutIsInitialized() || original_port >= g_native_controllers.size()) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (original_port == 1) return VIDEO_OUT_ERROR_UNSUPPORTED_OPERATION;
	uint64_t generation = 0;
	auto*    ctx        = DriverState().Get(1, generation);
	if (ctx == nullptr) return VIDEO_OUT_ERROR_INVALID_HANDLE;
	Common::LockGuard context_lock(ctx->mutex);
	Common::LockGuard controller_lock(g_native_controller_mutex);
	auto&             controller  = g_native_controllers[original_port];
	const auto&       timing      = controller.pending_timing;
	uint64_t          numerator   = 0;
	uint64_t          denominator = 0;
	if (!ctx->opened || ctx->closing || ctx->generation != generation ||
	    (expected_generation != 0 && generation != expected_generation) ||
	    !ctx->native_scanout_bound || controller.bound_handle != 1 ||
	    controller.bound_generation != generation || !controller.pending ||
	    controller.master_locked || !timing.ppll_programmed || !timing.timing_programmed ||
	    !timing.double_buffer_enabled || !timing.otg_enabled || !timing.pixel_encoding_programmed ||
	    !timing.subsampling_programmed ||
	    g_native_virtual_display_clock.load(std::memory_order_acquire) != 120000u ||
	    !NativeVblankPeriod(Common::Timer::QueryPerformanceFrequency(), timing.h_total,
	                        timing.v_total, timing.ppll_rate_100hz, numerator, denominator)) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	controller.committed_timing = timing;
	controller.committed        = true;
	controller.pending          = false;
	controller.scanout_enabled  = true;
	if (++controller.timing_generation == 0) EXIT("native display timing generation wrapped\n");
	ctx->native_signal_width             = timing.width;
	ctx->native_signal_height            = timing.height;
	ctx->native_signal_h_total           = timing.h_total;
	ctx->native_signal_v_total           = timing.v_total;
	ctx->native_signal_refresh_hz        = timing.refresh_hz;
	ctx->native_signal_pixel_clock_10khz = timing.pixel_clock_10khz;
	ctx->native_signal_ppll_100hz        = timing.ppll_rate_100hz;
	ctx->native_signal_pending           = false;
	ctx->native_signal_active            = true;
	ctx->native_scanout_enabled          = true;
	ctx->native_timing_generation        = controller.timing_generation;
	TriggerVideoOutEvents(*ctx, VideoOutEventKind::SetMode,
	                      reinterpret_cast<void*>(ctx->output_mode));
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KYTY_SIGNAL_ACTIVE"
	     " port=0 adapter=diagnostic_HDMI_to_MAIN signal=%ux%u"
	     " ppll_100hz=%u h_total=%u v_total=%u timing_generation=%" PRIu64
	     " guest_vblank_clock=1\n",
	     timing.width, timing.height, timing.ppll_rate_100hz, timing.h_total, timing.v_total,
	     controller.timing_generation);
	return OK;
}

int VideoOutNativeConfigureSplashAttributes(const uint64_t* original_words,
                                            size_t original_word_count, int handle,
                                            uint64_t expected_generation) {
	// DCE cmd 0x38 from sceVideoOutRegisterBuffers2, layout only; backing comes in a later command
	static constexpr uint64_t exact_original[12] = {0x0000000000000000ull,
	                                                0x8000000000000000ull,
	                                                0x0000078000000000ull,
	                                                0x0000043800000780ull,
	                                                0xffffffff00000000ull,
	                                                0x00000000ffffffffull,
	                                                0x8000000000000000ull,
	                                                0,
	                                                0,
	                                                0,
	                                                0,
	                                                0};
	if (!VideoOutIsInitialized() || original_words == nullptr ||
	    original_word_count != std::size(exact_original) ||
	    std::memcmp(original_words, exact_original, sizeof(exact_original)) != 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	uint64_t generation = 0;
	auto*    ctx        = DriverState().Get(handle, generation);
	if (ctx == nullptr || (expected_generation != 0 && generation != expected_generation))
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	Common::LockGuard lock(ctx->mutex);
	if (!ctx->opened || ctx->closing || !ctx->native_signal_active ||
	    ctx->generation != generation || ctx->native_splash_attributes_programmed) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	std::copy_n(original_words, original_word_count, ctx->native_splash_attribute_record.begin());
	ctx->native_splash_attributes_programmed = true;
	LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_ATTRIBUTES_PROGRAMMED"
	     " handle=%d generation=%" PRIu64 " source=DCE_command0x38"
	     " width=1920 height=1080 format=0x8000000000000000 record_bytes=96\n",
	     handle, generation);
	return OK;
}

int VideoOutNativeRegisterSplashBuffer(int* native_display_handle, int buffer_index,
                                       uint64_t  original_guest_address,
                                       uint64_t* native_display_generation) {
	constexpr uint64_t format = 0x8000000000000000ull;
	if (native_display_handle == nullptr || !VideoOutIsInitialized() || buffer_index < 0 ||
	    buffer_index >= 4 || original_guest_address == 0 || (original_guest_address & 0xffu) != 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	bool     opened_here = false;
	int      handle      = *native_display_handle;
	uint64_t generation  = handle < 0 ? 0 : VideoOutNativeGetHandleGeneration(handle);
	if (handle >= 0 && (generation == 0 || (native_display_generation != nullptr &&
	                                        *native_display_generation != generation))) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_NATIVE_SPLASH_ATTR_96") != nullptr) {
		auto* ctx = DriverState().Get(1);
		if (ctx == nullptr) return VIDEO_OUT_ERROR_INVALID_HANDLE;
		Common::LockGuard lock(ctx->mutex);
		if (!ctx->native_splash_attributes_programmed) {
			return VIDEO_OUT_ERROR_INVALID_VALUE;
		}
	}
	if (handle < 0) {
		handle = OpenVideoOut(0, VIDEO_OUT_BUS_TYPE_MAIN, 0, nullptr, &generation);
		if (handle < 0) {
			return handle;
		}
		opened_here = true;
	}
	VideoOutBufferAttribute2 attr {};
	VideoOutSetBufferAttribute2(&attr, format, 1, 1920, 1080, 0, 0, 0);
	VideoOutBuffers buffer {};
	buffer.data = reinterpret_cast<const void*>(original_guest_address);
	// one index at a time, so one attribute group each
	const int rc = RegisterBuffersWithGeneration(
	    handle, buffer_index, buffer_index, &buffer, 1, &attr,
	    VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_UNCOMPRESSED, nullptr, generation);
	if (rc != OK) {
		if (opened_here) {
			(void)DriverState().Close(handle, generation, VideoOutCloseMode::User);
		}
		return rc;
	}
	*native_display_handle = handle;
	if (native_display_generation != nullptr) *native_display_generation = generation;
	LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_BUFFER_REGISTER"
	     " local_handle=%d index=%d guest_addr=0x%016" PRIx64 "\n",
	     handle, buffer_index, original_guest_address);
	return OK;
}

void VideoOutNativeReleaseSplashHandle(int* native_display_handle, uint64_t expected_generation) {
	if (native_display_handle != nullptr && *native_display_handle >= 0) {
		if (VideoOutIsInitialized()) {
			(void)DriverState().Close(*native_display_handle, expected_generation,
			                          VideoOutCloseMode::Native);
		}
		*native_display_handle = -1;
	}
}

void VideoOutNativeReleaseClientHandle(int* handle, uint64_t expected_generation) {
	if (handle == nullptr || *handle < 0) return;
	if (VideoOutIsInitialized() && expected_generation != 0)
		(void)DriverState().Close(*handle, expected_generation, VideoOutCloseMode::NativeClient);
	*handle = -1;
}

int VideoOutNativeSubmitSplashFlip(int native_display_handle, int buffer_index, int flip_mode,
                                   int64_t flip_arg, uint64_t original_guest_address,
                                   uint64_t expected_generation) {
	if (!VideoOutIsInitialized() || native_display_handle < 0 || buffer_index < 0 ||
	    buffer_index >= 4 || flip_mode != VIDEO_OUT_FLIP_MODE_VSYNC ||
	    original_guest_address == 0 || (original_guest_address & 0xffu) != 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	// splash cycles 0..3; wait out a flip of the same index still in flight
	uint64_t generation = 0;
	auto*    ctx        = DriverState().Get(native_display_handle, generation);
	if (ctx == nullptr || (expected_generation != 0 && expected_generation != generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	DriverState().GetFlipQueue().Wait(*ctx, buffer_index, generation);
	if (VideoOutNativeGetHandleGeneration(native_display_handle) != generation) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	// fade renderer writes from the CPU and CLFLUSHes before the flip. The range may be untracked
	// (uploads can stage straight from guest memory), so then invalidate both caches directly
	auto& renderer = g_video_out_driver->State().Renderer();
	if (!renderer.InvalidateMemory(original_guest_address, 0x7e9000)) {
		renderer.GetBufferCache().InvalidateMemory(original_guest_address, 0x7e9000);
		renderer.GetTextureCache().InvalidateMemory(original_guest_address, 0x7e9000);
		LOGF("FIRST_FRAME_AUDIT SYSAV_GUEST_FLIP_UNTRACKED_GPU_RANGE"
		     " index=%d guest_addr=0x%016" PRIx64 " bytes=0x7e9000 cache_aliases_invalidated\n",
		     buffer_index, original_guest_address);
	}
	const int rc = SubmitFlipWithGeneration(native_display_handle, buffer_index, flip_mode,
	                                        flip_arg, generation);
	if (rc == OK) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_GUEST_FLIP_QUEUED"
		     " local_handle=%d index=%d mode=%d arg=%" PRId64 "\n",
		     native_display_handle, buffer_index, flip_mode, flip_arg);
	}
	return rc;
}

int VideoOutNativeGetFlipStatus(int native_display_handle, uint64_t* original_words,
                                size_t original_word_count, uint64_t expected_generation) {
	if (!VideoOutIsInitialized() || original_words == nullptr || original_word_count != 16) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	uint64_t generation = 0;
	auto*    ctx        = DriverState().Get(native_display_handle, generation);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	Common::LockGuard lock(ctx->mutex);
	if (!ctx->opened || ctx->closing || ctx->bus != VIDEO_OUT_BUS_TYPE_MAIN ||
	    ctx->generation != generation ||
	    (expected_generation != 0 && expected_generation != generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	const auto& status = ctx->flip_status;
	if (status.gcQueueNum < 0 || status.flipPendingNum < status.gcQueueNum) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	std::array<uint64_t, 16> words {};
	words[0] = static_cast<uint64_t>(status.flipArg);
	words[2] = status.count;
	words[3] = status.processTime;
	words[4] = status.reserved0;
	words[5] = static_cast<uint32_t>(status.currentBuffer) |
	           (static_cast<uint64_t>(status.flipPendingNum - status.gcQueueNum) << 32);
	words[6] = static_cast<uint32_t>(status.gcQueueNum);
	words[7] = status.reserved1;
	words[8] = status.processTimeCounter;
	words[9] = status.submitProcessTimeCounter;
	std::copy(words.begin(), words.end(), original_words);
	LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_FLIP_STATUS"
	     " local_handle=%d completed=%" PRIu64 " flip_arg=%" PRId64
	     " current_buffer=%d pending=%d gpu_pending=%d wire_layout=0x462f80\n",
	     native_display_handle, status.count, status.flipArg, status.currentBuffer,
	     status.flipPendingNum, status.gcQueueNum);
	return OK;
}

KYTY_SYSV_ABI int VideoOutSetFlipRate(int handle, int rate) {
	PRINT_NAME();

	LOGF("\trate = %d\n", rate);

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	if (rate < 0 || rate > 2) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}

	Common::LockGuard lock(ctx->mutex);
	ctx->flip_rate = rate;

	return OK;
}

KYTY_SYSV_ABI int VideoOutSetBlankAfterResume(int handle) {
	PRINT_NAME();

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	Common::LockGuard lock(ctx->mutex);
	if (!ctx->opened || ctx->closing) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	ctx->blank_after_resume = true;
	LOGF("\t blank after resume armed, handle=%d\n", handle);
	return OK;
}

KYTY_SYSV_ABI int VideoOutDeleteFlipEvent(EventQueue::KernelEqueue eq, int handle) {
	PRINT_NAME();
	return DeleteVideoOutEvent(handle, eq, VideoOutEventKind::Flip);
}

KYTY_SYSV_ABI int VideoOutAddFlipEvent(EventQueue::KernelEqueue eq, int handle, void* udata) {
	PRINT_NAME();
	return RegisterVideoOutEvent(handle, eq, VideoOutEventKind::Flip, udata);
}

int VideoOutNativeRegisterOriginalSplashFlipEvent(EventQueue::KernelEqueue eq,
                                                  uint64_t original_ident, int handle,
                                                  uint64_t expected_generation) {
	// flip completions here carry the EVFILT_VIDEO_OUT (-13) ident back
	if (!VideoOutIsInitialized() || original_ident != 0x0006010000000000ull || handle < 0 ||
	    expected_generation == 0 ||
	    VideoOutNativeGetHandleGeneration(handle) != expected_generation) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	const int rc =
	    RegisterVideoOutEvent(handle, eq, VideoOutEventKind::Flip, nullptr,
		                      static_cast<uintptr_t>(original_ident), expected_generation);
	if (rc == OK) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_FLIP_EVENT_REGISTERED"
		     " ident=0x%016" PRIx64 " filter=EVFILT_VIDEO_OUT"
		     " queue=%" PRId64 " handle=%d generation=%" PRIu64 " NO_FLIP_QUEUED\n",
		     original_ident, eq, handle, expected_generation);
	}
	return rc;
}

KYTY_SYSV_ABI int VideoOutDeleteVblankEvent(EventQueue::KernelEqueue eq, int handle) {
	PRINT_NAME();
	return DeleteVideoOutEvent(handle, eq, VideoOutEventKind::Vblank);
}

KYTY_SYSV_ABI int VideoOutDeletePreVblankStartEvent(EventQueue::KernelEqueue eq, int handle) {
	PRINT_NAME();
	return DeleteVideoOutEvent(handle, eq, VideoOutEventKind::PreVblankStart);
}

KYTY_SYSV_ABI int VideoOutAddVblankEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                         void* udata) {
	PRINT_NAME();
	const int result = RegisterVideoOutEvent(handle, eq, VideoOutEventKind::Vblank, udata);
	LOGF("FIRST_FRAME_AUDIT vblank_event eq=0x%016" PRIx64 " handle=%d udata=0x%016" PRIx64
	     " result=0x%08x\n",
	     static_cast<uint64_t>(eq), handle, reinterpret_cast<uint64_t>(udata),
	     static_cast<unsigned>(result));
	return result;
}

KYTY_SYSV_ABI int VideoOutAddPreVblankStartEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                                 void* udata) {
	PRINT_NAME();
	return RegisterVideoOutEvent(handle, eq, VideoOutEventKind::PreVblankStart, udata);
}

KYTY_SYSV_ABI int VideoOutAddOutputModeEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                             void* udata) {
	PRINT_NAME();
	return RegisterVideoOutEvent(handle, eq, VideoOutEventKind::OutputMode, udata);
}

KYTY_SYSV_ABI int VideoOutAddSetModeEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                          void* udata) {
	PRINT_NAME();
	return RegisterVideoOutEvent(handle, eq, VideoOutEventKind::SetMode, udata);
}

KYTY_SYSV_ABI int VideoOutRegisterBuffers2(int handle, int set_index, int buffer_index_start,
                                           const VideoOutBuffers* buffers, int buffer_num,
                                           const VideoOutBufferAttribute2* attribute, int category,
                                           void* option) {
	PRINT_NAME();
	return RegisterBuffersWithGeneration(handle, set_index, buffer_index_start, buffers, buffer_num,
	                                     attribute, category, option, 0);
}

static int RegisterBuffersWithGeneration(int handle, int set_index, int buffer_index_start,
                                         const VideoOutBuffers* buffers, int buffer_num,
                                         const VideoOutBufferAttribute2* attribute, int category,
                                         void* option, uint64_t expected_generation) {
	uint64_t generation = 0;
	auto*    ctx        = DriverState().Get(handle, generation);
	if (ctx == nullptr || (expected_generation != 0 && generation != expected_generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	if (buffers == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (attribute == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}

	if (set_index < 0 || set_index >= VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX ||
	    buffer_index_start < 0 || buffer_index_start >= VIDEO_OUT_BUFFER_NUM_MAX ||
	    buffer_num < 1 || buffer_num > VIDEO_OUT_BUFFER_NUM_MAX ||
	    buffer_index_start + buffer_num > VIDEO_OUT_BUFFER_NUM_MAX) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}

	LOGF("\t start_index    = %d\n"
	     "\t buffer_num     = %d\n"
	     "\t set_index      = %d\n"
	     "\t pixel_format   = 0x%016" PRIx64 "\n"
	     "\t tiling_mode    = %" PRIu32 "\n"
	     "\t aspect_ratio   = %" PRIu32 "\n"
	     "\t width          = %" PRIu32 "\n"
	     "\t height         = %" PRIu32 "\n"
	     "\t pitch_in_pixel = %" PRIu32 "\n"
	     "\t option         = %" PRIu64 "\n"
	     "\t category       = %d\n",
	     buffer_index_start, buffer_num, set_index, attribute->pixel_format, attribute->tiling_mode,
	     attribute->aspect_ratio, attribute->width, attribute->height, attribute->pitch_in_pixel,
	     attribute->option, category);

	if (option != nullptr) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}
	if (category != VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_UNCOMPRESSED &&
	    category != VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_COMPRESSED) {
		return VIDEO_OUT_ERROR_INVALID_CATEGORY;
	}

	BufferAttributeGroup group {
	    .attribute = *attribute,
	    .category  = category,
	    .occupied  = true,
	};
	std::vector<VideoOutBuffer> registrations;
	registrations.reserve(static_cast<size_t>(buffer_num));

	for (int i = 0; i < buffer_num; i++) {
		LOGF("\t buffers[%d]: data=%p metadata=%p\n", i, buffers[i].data, buffers[i].metadata);
		if (buffers[i].reserved[0] != nullptr || buffers[i].reserved[1] != nullptr) {
			LOGF("\t buffers[%d]: ignoring reserved fields {%p, %p}\n", i, buffers[i].reserved[0],
			     buffers[i].reserved[1]);
		}
		const auto data_address     = reinterpret_cast<uint64_t>(buffers[i].data);
		const auto metadata_address = reinterpret_cast<uint64_t>(buffers[i].metadata);
		registrations.push_back({
		    .group_index      = set_index,
		    .data_address     = data_address,
		    .metadata_address = metadata_address,
		});
		(void)group.ImageInfo(registrations.back());
	}

	Common::LockGuard lock(ctx->mutex);
	if (!ctx->opened || ctx->closing || ctx->generation != generation ||
	    (expected_generation != 0 && expected_generation != generation)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (ctx->groups[set_index].occupied) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}
	for (int i = 0; i < buffer_num; i++) {
		if (ctx->buffers[buffer_index_start + i].Occupied()) {
			return VIDEO_OUT_ERROR_SLOT_OCCUPIED;
		}
	}

	ctx->groups[set_index] = group;
	for (int i = 0; i < buffer_num; i++) {
		ctx->buffers[buffer_index_start + i] = registrations[static_cast<size_t>(i)];
		const auto& buffer                   = registrations[static_cast<size_t>(i)];
		LOGF("\tbuffers[%d] = %016" PRIx64 " metadata = %016" PRIx64 " dcc = %08" PRIx32 "\n",
		     buffer_index_start + i, buffer.data_address, buffer.metadata_address,
		     attribute->dcc_control);
	}
	static std::atomic_bool first_register = false;
	if (!first_register.exchange(true)) {
		LOGF("FIRST_FRAME_AUDIT first_videoout_register handle=%d set=%d start=%d count=%d\n",
		     handle, set_index, buffer_index_start, buffer_num);
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutSubmitChangeBufferAttribute2(int handle, int set_index,
                                                       const VideoOutBufferAttribute2* attribute,
                                                       void*                           option) {
	PRINT_NAME();

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	if (attribute == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}
	if (set_index < 0 || set_index >= VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}

	if (option != nullptr) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}

	Common::LockGuard lock(ctx->mutex);
	const auto&       current = ctx->groups[set_index];
	if (ctx->closing || !current.occupied) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}

	BufferAttributeGroup replacement {
	    .attribute = *attribute,
	    .category  = current.category,
	    .occupied  = true,
	};
	for (const auto& buffer: ctx->buffers) {
		if (buffer.group_index == set_index) {
			(void)replacement.ImageInfo(buffer);
		}
	}
	ctx->groups[set_index] = replacement;

	return OK;
}

KYTY_SYSV_ABI int VideoOutUnregisterBuffers(int handle, int set_index) {
	PRINT_NAME();

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (set_index < 0 || set_index >= VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}

	Common::LockGuard lock(ctx->mutex);
	if (ctx->closing) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	if (!ctx->groups[set_index].occupied) {
		return VIDEO_OUT_ERROR_INVALID_INDEX;
	}
	ctx->groups[set_index] = BufferAttributeGroup {};
	for (auto& buffer: ctx->buffers) {
		if (buffer.group_index == set_index) {
			buffer = VideoOutBuffer {};
		}
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutSubmitFlip(int handle, int index, int flip_mode, int64_t flip_arg) {
	PRINT_NAME();
	return SubmitFlipWithGeneration(handle, index, flip_mode, flip_arg, 0);
}

static int SubmitFlipWithGeneration(int handle, int index, int flip_mode, int64_t flip_arg,
                                    uint64_t expected_generation) {
	uint64_t  request_id = 0;
	const int result = ReserveFlipRequest(DriverState(), handle, index, flip_mode, flip_arg,
	                                      FlipRequestSource::Cpu, request_id, expected_generation);
	if (result == VIDEO_OUT_ERROR_INVALID_FLIP_MODE) {
		LOGF("\t unsupported flip_mode = %d\n", flip_mode);
	}
	if (result != OK) {
		return result;
	}
	g_video_out_driver->SubmitFlipPreparation(request_id);
	static std::atomic_bool first_cpu_flip = false;
	if (!first_cpu_flip.exchange(true)) {
		LOGF("FIRST_FRAME_AUDIT first_cpu_flip handle=%d index=%d request=%" PRIu64 "\n", handle,
		     index, request_id);
	}

	return OK;
}

int VideoOutDriver::SubmitFlipFromGpu(Graphics::CommandBuffer& buffer, int handle, int index,
                                      int flip_mode, int64_t flip_arg, uint64_t& request_id) {
	EXIT_IF(buffer.IsInvalid());

	const int result = ReserveFlipRequest(*m_impl, handle, index, flip_mode, flip_arg,
	                                      FlipRequestSource::GpuEop, request_id);
	if (result != OK) {
		return result;
	}
	m_impl->GetFlipQueue().Prepare(request_id, buffer);

	return OK;
}

void VideoOutDriver::SubmitFlipPreparation(uint64_t request_id) {
	m_impl->Renderer().GetGpu().SubmitFlipPreparation(request_id);
}

void VideoOutDriver::PrepareFlip(uint64_t request_id, Graphics::CommandBuffer& buffer) {
	m_impl->GetFlipQueue().Prepare(request_id, buffer);
}

void VideoOutDriver::CompleteFlip(uint64_t request_id) {
	m_impl->GetFlipQueue().Complete(request_id);
}

void VideoOutDriver::WaitForSubmitSlot(int handle) {
	auto* cfg = m_impl->Get(handle);
	EXIT_IF(cfg == nullptr);
	m_impl->GetFlipQueue().WaitForSubmitSlot(*cfg);
}

void VideoOutDriver::WaitFlipDone(int handle, int index) {
	auto* ctx = m_impl->Get(handle);
	EXIT_IF(ctx == nullptr);

	EXIT_NOT_IMPLEMENTED(!IsValidBufferIndex(index));
	m_impl->GetFlipQueue().Wait(*ctx, index);
}

KYTY_SYSV_ABI int VideoOutGetFlipStatus(int handle, VideoOutFlipStatus* status) {
	PRINT_NAME();

	if (status == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	DriverState().GetFlipQueue().GetFlipStatus(*ctx, *status);

	LOGF("\t count = %" PRIu64 "\n"
	     "\t processTime = %" PRIu64 "\n"
	     "\t processTimeCounter = %" PRIu64 "\n"
	     "\t submitProcessTimeCounter = %" PRIu64 "\n"
	     "\t flipArg = %" PRId64 "\n"
	     "\t gcQueueNum = %d\n"
	     "\t flipPendingNum = %d\n"
	     "\t currentBuffer = %d\n",
	     status->count, status->processTime, status->processTimeCounter,
	     status->submitProcessTimeCounter, status->flipArg, status->gcQueueNum,
	     status->flipPendingNum, status->currentBuffer);

	return OK;
}

KYTY_SYSV_ABI int VideoOutIsFlipPending(int handle) {
	PRINT_NAME();

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	VideoOutFlipStatus status {};
	DriverState().GetFlipQueue().GetFlipStatus(*ctx, status);

	if (Config::GraphicsDebugDumpEnabled()) {
		LOGF("\t flipPendingNum = %d\n", status.flipPendingNum);
	}

	return status.flipPendingNum;
}

KYTY_SYSV_ABI int VideoOutGetVblankStatus(int handle, VideoOutVblankStatus* status) {
	PRINT_NAME();

	if (status == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	ctx->mutex.Lock();
	*status = ctx->vblank_status;
	ctx->mutex.Unlock();

	LOGF("\t count = %" PRIu64 "\n"
	     "\t processTime = %" PRIu64 "\n"
	     "\t processTimeCounter = %" PRIu64 "\n",
	     status->count, status->processTime, status->processTimeCounter);

	return OK;
}

KYTY_SYSV_ABI int VideoOutGetEventId(const EventQueue::KernelEvent* ev) {
	PRINT_NAME();

	if (ev == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (ev->filter != EventQueue::KERNEL_EVFILT_VIDEO_OUT) {
		return VIDEO_OUT_ERROR_INVALID_EVENT;
	}

	switch (ev->ident) {
		case VIDEO_OUT_EVENT_FLIP:
		case VIDEO_OUT_EVENT_VBLANK:
		case VIDEO_OUT_EVENT_PRE_VBLANK_START:
		case VIDEO_OUT_EVENT_SET_MODE: return static_cast<int>(ev->ident);
		case VIDEO_OUT_EVENT_SET_MODE_INTERNAL: return VIDEO_OUT_EVENT_SET_MODE;
		default: return VIDEO_OUT_ERROR_INVALID_EVENT;
	}
}

KYTY_SYSV_ABI int VideoOutGetEventData(const EventQueue::KernelEvent* ev, int64_t* data) {
	PRINT_NAME();

	if (ev == nullptr || data == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (ev->filter != EventQueue::KERNEL_EVFILT_VIDEO_OUT) {
		return VIDEO_OUT_ERROR_INVALID_EVENT;
	}

	uint64_t event_data = static_cast<uint64_t>(ev->data) >> 16u;
	if (ev->ident == VIDEO_OUT_EVENT_FLIP &&
	    (static_cast<uint64_t>(ev->data) & 0x8000000000000000ULL) != 0) {
		event_data |= 0xffff000000000000ULL;
	}

	*data = static_cast<int64_t>(event_data);

	return OK;
}

KYTY_SYSV_ABI int VideoOutGetEventCount(const EventQueue::KernelEvent* ev) {
	PRINT_NAME();

	if (ev == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (ev->filter != EventQueue::KERNEL_EVFILT_VIDEO_OUT) {
		return VIDEO_OUT_ERROR_INVALID_EVENT;
	}

	return static_cast<int>((static_cast<uint64_t>(ev->data) >> 12u) & 0xfu);
}

KYTY_SYSV_ABI int VideoOutWaitVblank(int handle) {
	PRINT_NAME();

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	Common::LockGuard lock(ctx->mutex);
	const auto        count = ctx->vblank_status.count;
	while (ctx->opened && ctx->vblank_status.count == count) {
		ctx->vblank_cond.Wait(&ctx->mutex);
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutGetOutputStatus(int handle, VideoOutOutputStatus* status) {
	PRINT_NAME();

	if (status == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	int32_t attribute3 = 0;
	Loader::SystemContentParamSfoGetInt("ATTRIBUTE3", &attribute3);
	ctx->mutex.Lock();
	// Primary output reports 4K unless param.json Video-out Info enables resolution detection.
	status->resolution =
	    ((attribute3 & 4) != 0 && ctx->width < 3840 && ctx->height < 2160 ? 1u : 2u);
	status->dynamicRange = 1;
	status->refreshRate =
	    (ctx->output_mode == VIDEO_OUT_OUTPUT_MODE_119_88HZ || Config::GetVblankFrequency() >= 119
	         ? VIDEO_OUT_REFRESH_RATE_119_88HZ
	         : VIDEO_OUT_REFRESH_RATE_59_94HZ);
	status->flags       = 0;
	status->reserved[0] = 0;
	status->reserved[1] = 0;
	status->reserved[2] = 0;
	ctx->mutex.Unlock();

	return OK;
}

KYTY_SYSV_ABI int VideoOutSysGetResolutionStatus2(uint32_t bus, VideoOutResolutionStatus* status) {
	PRINT_NAME();

	if (bus > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (status == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	// bus 0 = the 4K output VideoOutGetOutputStatus reports, bus 1 (HMD) has no mode
	*status       = VideoOutResolutionStatus();
	status->flags = 6;
	if (bus == 0) {
		status->fullWidth  = 3840;
		status->fullHeight = 2160;
		status->paneWidth  = 3840;
		status->paneHeight = 2160;
		status->refreshRate =
		    (Config::GetVblankFrequency() >= 119 ? VIDEO_OUT_REFRESH_RATE_119_88HZ
			                                     : VIDEO_OUT_REFRESH_RATE_59_94HZ);
	}
	static std::atomic_uint logged = 0;
	if (logged.fetch_add(1) < 2) {
		LOGF("FIRST_FRAME_AUDIT VIDEOOUT_SYS_RESOLUTION bus=%u %ux%u refresh=%" PRIu64
		     " EMULATOR_DEFINED_NO_DCE\n",
		     bus, status->fullWidth, status->fullHeight, status->refreshRate);
	}
	return OK;
}

KYTY_SYSV_ABI int VideoOutSysGetVblankStatus2(uint32_t head, VideoOutVblankStatus* status) {
	PRINT_NAME();

	if (head > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}

	// dce cmd 9 (ioctl 0x80208218): vblank count, processTime, tsc, one flags byte. XXX: flags
	// unknown, left 0
	DriverState().GetSysVblankStatus(head, status);
	static std::atomic_uint logged = 0;
	if (logged.fetch_add(1) < 2) {
		LOGF("FIRST_FRAME_AUDIT VIDEOOUT_SYS_VBLANK_STATUS head=%u count=%" PRIu64
		     " EMULATOR_DEFINED_NO_DCE\n",
		     head, status->count);
	}
	return OK;
}

KYTY_SYSV_ABI int VideoOutSysIsUserStatusSystemDefault(int handle, uint32_t bus, uint64_t /*arg*/,
                                                       int option, void* reserved) {
	PRINT_NAME();

	if (handle != 0xff) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (option != 0) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}
	if (reserved != nullptr || bus > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	return 1;
}

KYTY_SYSV_ABI int VideoOutSysIsUserStatusVr(int handle, uint32_t bus, uint64_t /*arg*/, int option,
                                            void* reserved) {
	PRINT_NAME();

	if (handle != 0xff) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (option != 0) {
		return VIDEO_OUT_ERROR_INVALID_OPTION;
	}
	if (reserved != nullptr || bus > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	return 0;
}

KYTY_SYSV_ABI int VideoOutSysGetPipelineStatus(uint32_t* status, void* reserved) {
	PRINT_NAME();

	if (status == nullptr || reserved != nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}
	std::fill_n(status, 8, 0u);
	return OK;
}

KYTY_SYSV_ABI int VideoOutSysAddSetModeEvent2(LibKernel::EventQueue::KernelEqueue eq, uint32_t head,
                                              void* udata) {
	PRINT_NAME();

	LOGF("\t eq    = 0x%016" PRIx64 "\n"
	     "\t head  = %u\n"
	     "\t udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), head, reinterpret_cast<uint64_t>(udata));

	if (head > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (!VideoOutIsInitialized()) {
		return VIDEO_OUT_ERROR_FATAL;
	}

	return DriverState().AddSysSetModeEvent(eq, head, udata);
}

extern "C" size_t KytyVideoOutSysSetModeRegistrationCountForTest(uint32_t head) {
	if (head > 1 || !VideoOutIsInitialized()) {
		return 0;
	}
	return DriverState().SysSetModeRegistrationCountForTest(head);
}

extern "C" size_t KytyVideoOutSysVblankRegistrationCountForTest(uint32_t head) {
	if (head > 1 || !VideoOutIsInitialized()) {
		return 0;
	}
	return DriverState().SysVblankRegistrationCountForTest(head);
}

KYTY_SYSV_ABI int VideoOutSysAddVblankEvent2(LibKernel::EventQueue::KernelEqueue eq, uint32_t head,
                                             void* udata) {
	PRINT_NAME();

	LOGF("\t eq    = 0x%016" PRIx64 "\n"
	     "\t head  = %u\n"
	     "\t udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), head, reinterpret_cast<uint64_t>(udata));

	if (head > 1) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	return DriverState().AddSysVblankEvent(eq, head, udata);
}

KYTY_SYSV_ABI int VideoOutSysAddVblankEvent(LibKernel::EventQueue::KernelEqueue eq, int bus_type,
                                            void* udata) {
	PRINT_NAME();

	LOGF("\t eq       = 0x%016" PRIx64 "\n"
	     "\t bus_type = 0x%x\n"
	     "\t udata    = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), bus_type, reinterpret_cast<uint64_t>(udata));

	// XXX: no authinfo check for bus 0x100
	const auto& buses = VideoOutDriver::Impl::VIDEO_OUT_BUSES;
	if (std::find(buses.begin(), buses.end(), bus_type) == buses.end()) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	return DriverState().AddSysVblankEvent(eq, 0, udata);
}

KYTY_SYSV_ABI int VideoOutAllowOutputResolutionWqhdDetection(int handle) {
	if (!DriverState().IsOpened(handle)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	return OK;
}

KYTY_SYSV_ABI int VideoOutVrrPegToFixedRate(int handle, uint64_t arg1, uint64_t arg2) {
	PRINT_NAME();

	static std::atomic_bool logged {false};
	if (!logged.exchange(true, std::memory_order_relaxed)) {
		LOGF("\t handle = %d\n"
		     "\t arg1   = 0x%016" PRIx64 "\n"
		     "\t arg2   = 0x%016" PRIx64 "\n",
		     handle, arg1, arg2);
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutVrrUnpegFromFixedRate(int handle) {
	PRINT_NAME();

	static std::atomic_bool logged {false};
	if (!logged.exchange(true, std::memory_order_relaxed)) {
		LOGF("\t handle = %d\n", handle);
	}

	return OK;
}

static int ValidateOutputConfig(int handle, uint64_t mode, const VideoOutOutputOptions* options,
                                void* reserved_ptr, uint64_t reserved) {
	if (!DriverState().IsOpened(handle)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	if (reserved_ptr != nullptr || reserved != 0) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}

	if (options != nullptr) {
		for (auto v: options->internalData) {
			if (v != 0) {
				return VIDEO_OUT_ERROR_INVALID_OPTION;
			}
		}
	}

	if (mode != VIDEO_OUT_OUTPUT_MODE_DEFAULT && mode != VIDEO_OUT_OUTPUT_MODE_119_88HZ) {
		return VIDEO_OUT_ERROR_UNSUPPORTED_OUTPUT_MODE;
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutInitializeOutputOptions(VideoOutOutputOptions* options) {
	PRINT_NAME();

	if (options == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	memset(options, 0, sizeof(VideoOutOutputOptions));

	return OK;
}

KYTY_SYSV_ABI int VideoOutIsOutputSupported(int handle, uint64_t mode,
                                            const VideoOutOutputOptions* options,
                                            void* reserved_ptr, uint64_t reserved) {
	PRINT_NAME();

	LOGF("\t mode = 0x%016" PRIx64 "\n", mode);

	int result = ValidateOutputConfig(handle, mode, options, reserved_ptr, reserved);
	if (result != OK) {
		return result;
	}

	if (mode == VIDEO_OUT_OUTPUT_MODE_119_88HZ) {
		return (Config::GetVblankFrequency() >= 119 ? VIDEO_OUT_TRUE : VIDEO_OUT_FALSE);
	}

	return VIDEO_OUT_TRUE;
}

KYTY_SYSV_ABI int VideoOutConfigureOutput(int handle, uint64_t mode,
                                          const VideoOutOutputOptions* options, void* reserved_ptr,
                                          uint64_t reserved) {
	PRINT_NAME();

	LOGF("\t mode = 0x%016" PRIx64 "\n", mode);

	int result = VideoOutIsOutputSupported(handle, mode, options, reserved_ptr, reserved);
	if (result < 0) {
		return result;
	}
	if (result == VIDEO_OUT_FALSE) {
		return VIDEO_OUT_ERROR_UNAVAILABLE_OUTPUT_MODE;
	}

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	ctx->mutex.Lock();
	ctx->output_mode = mode;
	TriggerVideoOutEvents(*ctx, VideoOutEventKind::OutputMode,
	                      reinterpret_cast<void*>(ctx->output_mode));
	TriggerVideoOutEvents(*ctx, VideoOutEventKind::SetMode,
	                      reinterpret_cast<void*>(ctx->output_mode));
	ctx->mutex.Unlock();

	return OK;
}

KYTY_SYSV_ABI int VideoOutSetWindowModeMargins(int handle, int top, int bottom) {
	PRINT_NAME();

	[[maybe_unused]] auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	LOGF("\t top    = %d\n"
	     "\t bottom = %d\n",
	     top, bottom);

	return OK;
}

KYTY_SYSV_ABI int VideoOutLatencyControlWaitBeforeInput(int handle) {
	PRINT_NAME();

	[[maybe_unused]] auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	return OK;
}

KYTY_SYSV_ABI int VideoOutLatencyMeasureSetStartPoint(int handle, uint32_t point) {
	PRINT_NAME();

	[[maybe_unused]] auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	LOGF("\t point = %" PRIu32 "\n", point);

	return OK;
}

KYTY_SYSV_ABI int VideoOutColorSettingsSetGamma(VideoOutColorSettings* settings, float gamma) {
	PRINT_NAME();

	if (settings == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (gamma < 0.1f || gamma > 2.0f) {
		return VIDEO_OUT_ERROR_INVALID_VALUE;
	}

	settings->gamma = gamma;
	return OK;
}

KYTY_SYSV_ABI int VideoOutAdjustColor(int handle, const VideoOutColorSettings* settings) {
	PRINT_NAME();

	if (settings == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}

	if (!DriverState().IsOpened(handle)) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}

	auto* ctx = DriverState().Get(handle);
	if (ctx == nullptr) {
		return VIDEO_OUT_ERROR_INVALID_HANDLE;
	}
	ctx->mutex.Lock();
	ctx->gamma = settings->gamma;
	ctx->mutex.Unlock();

	return OK;
}

} // namespace Libs::VideoOut
