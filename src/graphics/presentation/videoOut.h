#ifndef EMULATOR_INCLUDE_EMULATOR_GRAPHICS_VIDEOOUT_H_
#define EMULATOR_INCLUDE_EMULATOR_GRAPHICS_VIDEOOUT_H_

#include "common/common.h"
// #include "common/subsystems.h"

#include "common/abi.h"
#include "kernel/eventQueue.h"

#include <array>
#include <memory>

namespace Libs::Graphics {
class CommandBuffer;
class Presenter;
} // namespace Libs::Graphics

namespace Libs::VideoOut {

struct VideoOutBufferAttribute2;
struct VideoOutFlipStatus;
struct VideoOutVblankStatus;
struct VideoOutOutputStatus;
struct VideoOutOutputOptions;
struct VideoOutBuffers;
struct VideoOutColorSettings;

class VideoOutDriver final {
public:
	struct Impl;

	VideoOutDriver(uint32_t width, uint32_t height, Graphics::Presenter& presenter);
	~VideoOutDriver();
	KYTY_CLASS_NO_COPY(VideoOutDriver);

	int  SubmitFlipFromGpu(Graphics::CommandBuffer& buffer, int handle, int index, int flip_mode,
	                       int64_t flip_arg, uint64_t& request_id);
	void PrepareFlip(uint64_t request_id, Graphics::CommandBuffer& buffer);
	void CompleteFlip(uint64_t request_id);
	void SubmitFlipPreparation(uint64_t request_id);
	void WaitForSubmitSlot(int handle);
	void WaitFlipDone(int handle, int index);

	[[nodiscard]] Impl& State() noexcept;

private:
	std::unique_ptr<Impl> m_impl;
};

[[nodiscard]] VideoOutDriver& VideoOutInit(uint32_t width, uint32_t height,
                                           Graphics::Presenter& presenter);
void                          VideoOutShutdown();
bool                          VideoOutIsInitialized() noexcept;
// Binds a raw EVFILT_VIDEO_OUT change to the MAIN head's flip-completion queue.
int  VideoOutNativeRegisterOriginalSplashFlipEvent(LibKernel::EventQueue::KernelEqueue eq,
                                                   uint64_t original_ident, int handle = -1,
                                                   uint64_t expected_generation = 0);
void VideoOutNativeReleaseClientHandle(int* handle, uint64_t expected_generation);
// Software display clock; the stored rate gates later DCE mode programming
int VideoOutNativeProgramDisplayClock(uint32_t requested_rate, uint32_t* applied_rate);
struct VideoOutNativeTimingSnapshot {
	uint32_t                 width             = 0;
	uint32_t                 height            = 0;
	uint32_t                 h_total           = 0;
	uint32_t                 v_total           = 0;
	uint32_t                 pixel_clock_10khz = 0;
	uint32_t                 ppll_rate_100hz   = 0;
	float                    refresh_hz        = 0.0f;
	std::array<uint32_t, 16> otg_timing {};
	uint32_t                 pixel_encoding                                        = 0;
	uint32_t                 subsampling                                           = 0;
	bool                     ppll_programmed                                       = false;
	bool                     timing_programmed                                     = false;
	bool                     double_buffer_enabled                                 = false;
	bool                     otg_enabled                                           = false;
	bool                     pixel_encoding_programmed                             = false;
	bool                     subsampling_programmed                                = false;
	bool                     operator==(const VideoOutNativeTimingSnapshot&) const = default;
};

struct VideoOutNativeControllerSnapshot {
	uint32_t                     display_clock_10khz = 0;
	uint64_t                     transaction_id      = 0;
	uint64_t                     timing_generation   = 0;
	uint64_t                     bound_generation    = 0;
	int32_t                      bound_handle        = -1;
	bool                         pending             = false;
	bool                         committed           = false;
	bool                         master_locked       = false;
	bool                         scanout_enabled     = false;
	VideoOutNativeTimingSnapshot pending_timing;
	VideoOutNativeTimingSnapshot committed_timing;
	bool operator==(const VideoOutNativeControllerSnapshot&) const = default;
};
int      VideoOutNativeGetControllerSnapshot(uint32_t                          original_port,
                                             VideoOutNativeControllerSnapshot* snapshot);
uint64_t VideoOutNativeGetHandleGeneration(int native_display_handle);
int      VideoOutNativeAcquireSplashHandle(int*      native_display_handle,
                                           uint64_t* native_display_generation);
int      VideoOutNativeProgramMasterUpdateLock(uint32_t original_port, uint32_t enabled);
int      VideoOutNativeProgramPixelClock(uint32_t original_port, uint32_t raw_rate_100hz);
int      VideoOutNativeProgramOtgTiming(uint32_t original_port, const uint32_t* original_registers,
                                        size_t register_count);
int      VideoOutNativeProgramOtgControl(uint32_t original_ioctl, uint32_t original_port,
                                         uint32_t original_value);
int      VideoOutNativeProgramFormatControl(uint32_t original_ioctl, uint32_t original_port,
                                            uint32_t original_value);
// The diagnostic HDMI adapter maps to the MAIN output. TYPE_C has no output route.
int VideoOutNativeConfigureDisplaySignal(int* native_display_handle, uint32_t original_port,
                                         uint32_t signal_width, uint32_t signal_height,
                                         uint32_t h_total, uint32_t v_total, float refresh_hz,
                                         uint32_t  pixel_clock_10khz,
                                         uint64_t* native_display_generation = nullptr);
// Command 11 can finish a mode change begun on another /dev/dce fd, so state is per device.
int VideoOutNativeFinishDisplaySignal(uint32_t original_port, uint64_t expected_generation = 0);
// Backend 0, only for the linear 1920x1080 SceSysAvControlSplash buffers.
int VideoOutNativeRegisterSplashBuffer(int* native_display_handle, int buffer_index,
                                       uint64_t  original_guest_address,
                                       uint64_t* native_display_generation = nullptr);
// 96-byte command 0x38 format record, MAIN head
int VideoOutNativeConfigureSplashAttributes(const uint64_t* original_words,
                                            size_t original_word_count, int handle = 1,
                                            uint64_t expected_generation = 0);
// OK means queued, not presented.
int  VideoOutNativeSubmitSplashFlip(int native_display_handle, int buffer_index, int flip_mode,
                                    int64_t flip_arg, uint64_t original_guest_address,
                                    uint64_t expected_generation = 0);
int  VideoOutNativeGetFlipStatus(int native_display_handle, uint64_t* original_words,
                                 size_t original_word_count, uint64_t expected_generation = 0);
void VideoOutNativeReleaseSplashHandle(int*     native_display_handle,
                                       uint64_t expected_generation = 0);
KYTY_SYSV_ABI int  VideoOutOpen(int user_id, int bus_type, int index, const void* param);
KYTY_SYSV_ABI int  VideoOutClose(int handle);
KYTY_SYSV_ABI int  VideoOutSetFlipMaster(int slave_handle, int master_handle);
KYTY_SYSV_ABI void VideoOutAddBufferAttributeOption(VideoOutBufferAttribute2* attribute,
                                                   uint64_t option);
KYTY_SYSV_ABI void VideoOutSetBufferAttribute2(VideoOutBufferAttribute2* attribute,
                                               uint64_t pixel_format, uint32_t tiling_mode,
                                               uint32_t width, uint32_t height, uint64_t option,
                                               uint32_t dcc_control,
                                               uint64_t dcc_cb_register_clear_color);
KYTY_SYSV_ABI int  VideoOutSetFlipRate(int handle, int rate);
KYTY_SYSV_ABI int  VideoOutAddFlipEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                        void* udata);
KYTY_SYSV_ABI int  VideoOutAddVblankEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                          void* udata);
KYTY_SYSV_ABI int VideoOutAddPreVblankStartEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                                 void* udata);
KYTY_SYSV_ABI int VideoOutAddOutputModeEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                             void* udata);
KYTY_SYSV_ABI int  VideoOutAddSetModeEvent(LibKernel::EventQueue::KernelEqueue eq, int handle,
                                           void* udata);
KYTY_SYSV_ABI int VideoOutDeleteFlipEvent(LibKernel::EventQueue::KernelEqueue eq, int handle);
KYTY_SYSV_ABI int VideoOutDeleteVblankEvent(LibKernel::EventQueue::KernelEqueue eq, int handle);
KYTY_SYSV_ABI int VideoOutDeletePreVblankStartEvent(LibKernel::EventQueue::KernelEqueue eq,
                                                    int                                 handle);
KYTY_SYSV_ABI int VideoOutRegisterBuffers2(int handle, int set_index, int buffer_index_start,
                                           const VideoOutBuffers* buffers, int buffer_num,
                                           const VideoOutBufferAttribute2* attribute, int category,
                                           void* option);
KYTY_SYSV_ABI int VideoOutSubmitChangeBufferAttribute2(int handle, int set_index,
                                                       const VideoOutBufferAttribute2* attribute,
                                                       void*                           option);
KYTY_SYSV_ABI int VideoOutUnregisterBuffers(int handle, int set_index);
KYTY_SYSV_ABI int VideoOutSubmitFlip(int handle, int index, int flip_mode, int64_t flip_arg);
KYTY_SYSV_ABI int VideoOutGetFlipStatus(int handle, VideoOutFlipStatus* status);
KYTY_SYSV_ABI int VideoOutIsFlipPending(int handle);
KYTY_SYSV_ABI int VideoOutGetVblankStatus(int handle, VideoOutVblankStatus* status);
KYTY_SYSV_ABI int VideoOutGetEventId(const LibKernel::EventQueue::KernelEvent* ev);
KYTY_SYSV_ABI int VideoOutGetEventData(const LibKernel::EventQueue::KernelEvent* ev, int64_t* data);
KYTY_SYSV_ABI int VideoOutGetEventCount(const LibKernel::EventQueue::KernelEvent* ev);
KYTY_SYSV_ABI int VideoOutWaitVblank(int handle);
KYTY_SYSV_ABI int VideoOutGetOutputStatus(int handle, VideoOutOutputStatus* status);
KYTY_SYSV_ABI int  VideoOutSysGetVblankStatus2(uint32_t head, VideoOutVblankStatus* status);
KYTY_SYSV_ABI int VideoOutSysAddSetModeEvent2(LibKernel::EventQueue::KernelEqueue eq, uint32_t head,
                                              void* udata);
KYTY_SYSV_ABI int VideoOutSysAddVblankEvent2(LibKernel::EventQueue::KernelEqueue eq, uint32_t head,
                                             void* udata);
KYTY_SYSV_ABI int VideoOutAllowOutputResolutionWqhdDetection(int handle);
KYTY_SYSV_ABI int VideoOutVrrPegToFixedRate(int handle, uint64_t arg1, uint64_t arg2);
KYTY_SYSV_ABI int VideoOutVrrUnpegFromFixedRate(int handle);
KYTY_SYSV_ABI int VideoOutInitializeOutputOptions(VideoOutOutputOptions* options);
KYTY_SYSV_ABI int VideoOutIsOutputSupported(int handle, uint64_t mode,
                                            const VideoOutOutputOptions* options,
                                            void* reserved_ptr, uint64_t reserved);
KYTY_SYSV_ABI int VideoOutConfigureOutput(int handle, uint64_t mode,
                                          const VideoOutOutputOptions* options, void* reserved_ptr,
                                          uint64_t reserved);
KYTY_SYSV_ABI int VideoOutSetWindowModeMargins(int handle, int top, int bottom);
KYTY_SYSV_ABI int VideoOutLatencyControlWaitBeforeInput(int handle);
KYTY_SYSV_ABI int VideoOutLatencyMeasureSetStartPoint(int handle, uint32_t point);
KYTY_SYSV_ABI int VideoOutColorSettingsSetGamma(VideoOutColorSettings* settings, float gamma);
KYTY_SYSV_ABI int VideoOutAdjustColor(int handle, const VideoOutColorSettings* settings);

} // namespace Libs::VideoOut

#endif /* EMULATOR_INCLUDE_EMULATOR_GRAPHICS_VIDEOOUT_H_ */
