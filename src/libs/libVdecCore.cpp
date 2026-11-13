#include "common/abi.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "libs/videoDec2Decoder.h"
#include "loader/symbolDatabase.h"

#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Libs {

LIB_VERSION("VdecCore", 1, "VdecCore", 1, 1);

namespace VdecCore {

namespace Decoder = VideoDec2::Decoder;

constexpr int32_t VDECCORE_ERROR_ARGUMENT    = static_cast<int32_t>(0x80c00001);
constexpr int32_t VDECCORE_ERROR_INSTANCE    = static_cast<int32_t>(0x80c00002);
constexpr int32_t VDECCORE_ERROR_UNSUPPORTED = static_cast<int32_t>(0x80c00005);
constexpr int32_t VDECCORE_ERROR_NO_BUFFER   = static_cast<int32_t>(0x80c0000a);
constexpr int32_t VDECCORE_ERROR_ALIGNMENT   = static_cast<int32_t>(0x80c0000b);
constexpr int32_t VDECCORE_ERROR_WOULD_BLOCK = static_cast<int32_t>(0x80c00012);
constexpr int32_t VDECCORE_ERROR_RESET_ARG   = static_cast<int32_t>(0x80c00014);

// Kyty's ffmpeg backend tags the codec with the sce videodec2 enum, not VdecCore's config enum.
constexpr uint32_t KYTY_CODEC_HEVC = 974921;

using DecoderState = Decoder::Instance;

struct ReadyFrame {
	uint64_t             base;
	uint32_t             width;
	uint32_t             height;
	uint32_t             pitch;
	uint64_t             pts  = 0;
	uint64_t             size = 0;
	Decoder::PictureInfo info;
};

struct Handle {
	DecoderState* decoder = nullptr;
	uint32_t      codec   = 0; // config codec, 4 = HEVC
	uint32_t      width   = 0;
	uint32_t      height  = 0;

	std::vector<std::pair<uint64_t, uint64_t>> regions; // (addr, size) in MapMemory order
	std::vector<size_t>    frame_regions; // indices into regions large enough for a frame
	size_t                 next_buffer = 0;
	std::deque<ReadyFrame> ready;

	// A SetDecodeInput job stays outstanding until SyncDecode collects it.
	bool job_pending = false;
	bool job_failed  = false;

	// desc+64 points here; VSE reads aspect ratio and colour info right after GetDecodeOutput
	uint8_t color_meta[256] = {};

	// Videodec2 reads this synchronously after the Bid get-output, so one per handle will do
	uint8_t    dims[64] = {};
	std::mutex m;

	int ref_count = 0;
};

static std::mutex                g_handle_mutex;
static std::unordered_set<void*> g_handles;
static std::condition_variable   g_handle_cv;

static bool Diag() {
	static const bool enabled = std::getenv("KYTY_DIAGNOSTIC_VDECCORE") != nullptr;
	return enabled;
}

static uint32_t AlignUp(uint32_t v, uint32_t a) {
	return (v + a - 1u) & ~(a - 1u);
}

static uint64_t Nv12Size(uint32_t w, uint32_t h) {
	const uint32_t pitch  = AlignUp(w, 256);
	const uint64_t chroma = (static_cast<uint64_t>(h) + 1u) / 2u;
	return static_cast<uint64_t>(pitch) * h + static_cast<uint64_t>(pitch) * chroma;
}

class HandleRef {
public:
	HandleRef() = default;
	explicit HandleRef(Handle* h): m_handle(h) {}
	HandleRef(const HandleRef&)            = delete;
	HandleRef& operator=(const HandleRef&) = delete;
	~HandleRef();
	Handle* operator->() const { return m_handle; }
	        operator Handle*() const { return m_handle; }

private:
	Handle* m_handle = nullptr;
};

static HandleRef Get(void* handle) {
	std::scoped_lock lock(g_handle_mutex);
	if (!g_handles.contains(handle)) {
		return {};
	}
	auto* h = static_cast<Handle*>(handle);
	h->ref_count++;
	return HandleRef(h);
}

HandleRef::~HandleRef() {
	if (m_handle != nullptr) {
		std::scoped_lock lock(g_handle_mutex);
		if (--m_handle->ref_count == 0) {
			g_handle_cv.notify_all();
		}
	}
}

// mapped regions big enough for an NV12 frame are VSE's pool buffers, wanted back as the
// GetDecodeOutput base
static void EnsureFrameRegions(Handle* h) {
	if (!h->frame_regions.empty() || h->regions.empty()) {
		return;
	}
	const uint64_t need = Nv12Size(h->width, h->height);
	for (size_t i = 0; i < h->regions.size(); i++) {
		if (h->regions[i].second >= need) {
			h->frame_regions.push_back(i);
		}
	}
	if (h->frame_regions.empty()) {
		uint64_t best = 0;
		for (const auto& r: h->regions) {
			if (r.second > best) {
				best = r.second;
			}
		}
		for (size_t i = 0; i < h->regions.size(); i++) {
			if (h->regions[i].second == best) {
				h->frame_regions.push_back(i);
			}
		}
	}
	if (Diag()) {
		LOGF("VdecCore: %zu/%zu mapped regions usable as frame buffers (need=0x%" PRIx64 ")\n",
		     h->frame_regions.size(), h->regions.size(), need);
	}
}

struct SizeInfo {
	uint64_t instance = 0;
	uint64_t work     = 0;
	uint32_t frame    = 0;
	uint32_t count    = 0;
};

// libSceVdecCore.native.sprx sizes for HEVC (codec 4).
// Frame count -1: MaxDpbSize (HEVC A.4.2) for the picture size, plus one.
static bool HevcSizes(const void* config, SizeInfo* s) {
	const auto* c = static_cast<const int32_t*>(config);
	const auto* b = static_cast<const uint8_t*>(config);

	if (c[1] != 4) {
		LOGF("VdecCore: size query for config codec %d, only the HEVC size model is implemented\n",
		     c[1]);
		return false;
	}
	if (c[5] < 0 || c[6] < 0) {
		LOGF("VdecCore: size query for %dx%d is not modelled\n", c[5], c[6]);
		return false;
	}

	const int32_t  profile = c[2];
	const int32_t  frames  = c[4];
	const auto     w       = static_cast<uint32_t>(c[5]);
	const auto     h       = static_cast<uint32_t>(c[6]);
	const uint32_t depth   = b[42];
	if ((profile != 1 && profile != 2) || b[43] != depth || (depth != 8 && depth != 10) ||
	    (profile == 1 && depth != 8)) {
		return false;
	}
	if (w < 57 || h < 57 || w > 4096 || h > 2176 || frames < -1 || frames > 16) {
		return false;
	}

	uint32_t max_luma_ps = 0;
	switch (c[3]) {
		case 0x1e: max_luma_ps = 36864; break;
		case 0x3c: max_luma_ps = 122880; break;
		case 0x3f: max_luma_ps = 245760; break;
		case 0x5a: max_luma_ps = 552960; break;
		case 0x5d: max_luma_ps = 983040; break;
		case 0x78:
		case 0x7b: max_luma_ps = 2228224; break;
		case 0x96:
		case 0x99:
		case 0x9c: max_luma_ps = 8912896; break;
		default: return false;
	}

	const uint32_t rows = AlignUp(h, 8) >> 4;
	const uint32_t ps   = (AlignUp(w, 8) >> 4) * rows * 256;

	uint32_t count = static_cast<uint32_t>(frames + 1);
	if (frames < 0) {
		count = 7;
		if (ps <= max_luma_ps >> 2) {
			count = 17;
		} else if (ps <= max_luma_ps >> 1) {
			count = 13;
		} else if (ps <= (3 * max_luma_ps) >> 2) {
			count = 9;
		}
	}

	// count - 1 4:2:0 pictures at 8 or 12 bits, chosen by profile rather than the configured depth
	const uint32_t main10 = profile == 2 ? 1 : 0;
	const uint32_t ref_h  = AlignUp(h, 64);
	const uint32_t ref    = (AlignUp(w, 256) * (main10 != 0 ? 12u : 8u) * (ref_h + ref_h / 2)) >> 3;
	const uint32_t refs   = AlignUp((count > 1 ? count - 1 : 1) * ref, 256);
	const uint32_t aux    = ((rows << 8) + 1024) << main10;

	static const uint32_t instance[12] = {0x8c7580, 0x8e7800, 0x907b00, 0x927d00,
	                                      0x948000, 0x968280, 0x988580, 0x9a8780,
	                                      0x9c8a80, 0x9e8d00, 0xa09000, 0xa29200};

	s->instance = instance[count > 6 ? count - 6 : 0];
	s->work     = ((0x44657f + aux + refs) & 0xffff0000) + 0x1e0100;
	s->frame    = AlignUp(w * (depth > 8 ? 2u : 1u), 256) * AlignUp(h, 8) * 3 / 2 + 0x20900;
	s->count    = count;
	return true;
}

static int32_t KYTY_SYSV_ABI QueryInstanceSize(const void* config, void* out, void* out2,
                                               int32_t flag) {
	PRINT_NAME();

	if (config == nullptr || out == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	SizeInfo s {};
	if (!HevcSizes(config, &s)) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	// VSE allocates both; ffmpeg keeps its own state, so neither block gets used
	*static_cast<uint64_t*>(out) = s.instance;
	if (out2 != nullptr) {
		*static_cast<uint64_t*>(out2) = s.work;
	}

	if (Diag()) {
		LOGF("VdecCore::QueryInstanceSize flag=%d instance=0x%" PRIx64 " work=0x%" PRIx64 "\n",
		     flag, s.instance, s.work);
	}
	return OK;
}

static int32_t KYTY_SYSV_ABI QueryFrameBufferInfo(const void* config, void* out) {
	PRINT_NAME();

	if (config == nullptr || out == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	SizeInfo s {};
	if (!HevcSizes(config, &s)) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	// o[2] frames + 1 (0 for the -1 sentinel), o[3] level-derived count, o[1]/o[5] alignments of
	// the frame buffer and the 0x20100 block
	const auto* c = static_cast<const int32_t*>(config);
	auto*       o = static_cast<uint32_t*>(out);
	o[0]          = s.frame;
	o[1]          = 0x100;
	o[2]          = static_cast<uint32_t>(c[4] + 1);
	o[3]          = s.count;
	o[4]          = 0x20100;
	o[5]          = 0x80;

	if (Diag()) {
		LOGF("VdecCore::QueryFrameBufferInfo %dx%d frame=0x%x frames+1=%u count=%u\n", c[5], c[6],
		     o[0], o[2], o[3]);
	}
	return OK;
}

static int32_t KYTY_SYSV_ABI CreateDecoderBid(uint64_t bid, const void* config, void* mem_desc,
                                              void** out_handle) {
	PRINT_NAME();

	if (config == nullptr || out_handle == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	const auto*    c         = static_cast<const int32_t*>(config);
	const uint32_t cfg_codec = static_cast<uint32_t>(c[1]);
	const int32_t  max_w     = c[5] > 0 ? c[5] : -1;
	const int32_t  max_h     = c[6] > 0 ? c[6] : -1;

	if (Diag()) {
		for (int i = 0; i < 24; i += 8) {
			LOGF("VdecCore: config +%02x: %08x %08x %08x %08x %08x %08x %08x %08x\n", i * 4, c[i],
			     c[i + 1], c[i + 2], c[i + 3], c[i + 4], c[i + 5], c[i + 6], c[i + 7]);
		}
		if (mem_desc != nullptr) {
			// size and pointer of the instance block, of a second block and of the work memory
			uint64_t m[6];
			std::memcpy(m, mem_desc, sizeof(m));
			LOGF("VdecCore: memory 0x%" PRIx64 "@0x%" PRIx64 " 0x%" PRIx64 "@0x%" PRIx64
			     " 0x%" PRIx64 "@0x%" PRIx64 "\n",
			     m[0], m[1], m[2], m[3], m[4], m[5]);
		}
	}

	uint32_t kyty_codec = KYTY_CODEC_HEVC;
	if (cfg_codec != 4) {
		LOGF("VdecCore: unexpected config codec %u, decoding as HEVC\n", cfg_codec);
	}
	const uint32_t depth = static_cast<const uint8_t*>(config)[42];
	if (depth != 8) {
		LOGF("VdecCore: %u-bit config, pictures are still written as 8-bit NV12\n", depth);
	}

	auto* state = Decoder::Create({kyty_codec, max_w, max_h});
	if (state == nullptr) {
		LOGF("VdecCore::CreateDecoderBid ffmpeg decoder unavailable for codec %u\n", cfg_codec);
		return VDECCORE_ERROR_ARGUMENT;
	}

	auto* handle    = new Handle();
	handle->decoder = state;
	handle->codec   = cfg_codec;
	handle->width   = max_w > 0 ? static_cast<uint32_t>(max_w) : 0;
	handle->height  = max_h > 0 ? static_cast<uint32_t>(max_h) : 0;

	{
		std::scoped_lock lock(g_handle_mutex);
		g_handles.insert(handle);
	}
	*out_handle = handle;

	if (Diag()) {
		LOGF("VdecCore::CreateDecoderBid bid=0x%" PRIx64
		     " codec=%u max=%dx%d handle=%p memDesc=%p\n",
		     bid, cfg_codec, max_w, max_h, static_cast<void*>(handle), mem_desc);
	}
	return OK;
}

static int32_t KYTY_SYSV_ABI MapMemory(void* handle, uint64_t addr, uint64_t size) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}

	std::scoped_lock lock(h->m);
	h->regions.emplace_back(addr, size);

	if (Diag()) {
		LOGF("VdecCore::MapMemory handle=%p addr=0x%" PRIx64 " size=0x%" PRIx64 "\n", handle, addr,
		     size);
	}
	return OK;
}

static void QueuePicture(Handle* h, const Decoder::Output& decoded) {
	ReadyFrame frame {reinterpret_cast<uint64_t>(decoded.buffer), decoded.width, decoded.height,
	                  decoded.pitch};
	frame.size = decoded.buffer_size;
	if (!Decoder::GetPictureInfo(decoded.buffer, &frame.info)) {
		LOGF("VdecCore: no picture info for frame buffer %p\n", decoded.buffer);
	}
	h->ready.push_back(frame);

	if (Diag()) {
		LOGF("VdecCore: picture %ux%u pitch=%u base=0x%" PRIx64 " pts=0x%" PRIx64
		     " corrupt=%d ready=%zu\n",
		     decoded.width, decoded.height, decoded.pitch, frame.base, frame.info.pts,
		     decoded.error_frame ? 1 : 0, h->ready.size());
	}
}

// AU descriptor carries its output frame buffer at +48/+56.
// out: low dword 0 = job started (VSE then calls SyncDecode), high dword 1 = buffer taken (VSE
// files it as pending)
static int32_t KYTY_SYSV_ABI SetDecodeInput(void* handle, const void* au_desc, void* arg,
                                            uint64_t* out) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (au_desc == nullptr || out == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	uint64_t d[10];
	std::memcpy(d, au_desc, sizeof(d));
	const auto*    data    = reinterpret_cast<const uint8_t*>(d[0]);
	const uint64_t size    = d[1];
	auto*          fb      = reinterpret_cast<void*>(d[6]);
	const uint64_t fb_size = d[7];

	if (Diag()) {
		LOGF("VdecCore::SetDecodeInput handle=%p arg=%p au=%016" PRIx64 " %016" PRIx64
		     " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64
		     " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
		     handle, arg, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9]);
		if (data != nullptr && size >= 8) {
			char   nals[64] = {};
			size_t used     = 0;
			for (uint64_t i = 0; i + 3 < size && used + 4 < sizeof(nals); i++) {
				if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
					used += static_cast<size_t>(std::snprintf(nals + used, sizeof(nals) - used,
					                                          " %u", (data[i + 3] >> 1) & 0x3fu));
					i += 3;
				}
			}
			LOGF("VdecCore: au bytes %02x %02x %02x %02x %02x %02x %02x %02x nal types%s\n",
			     data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], nals);
		}
	}

	if (static_cast<uint32_t>(d[5] >> 32) >= 3) {
		return VDECCORE_ERROR_UNSUPPORTED;
	}
	if ((d[6] & 0xff) != 0) {
		return VDECCORE_ERROR_ALIGNMENT;
	}
	if (data == nullptr || size == 0) {
		return VDECCORE_ERROR_ARGUMENT;
	}
	if (fb == nullptr || fb_size == 0) {
		return VDECCORE_ERROR_NO_BUFFER;
	}

	std::scoped_lock lock(h->m);

	// decoder reorders, each picture goes to the buffer its own AU brought
	Decoder::Output decoded {};
	const auto      begin = std::chrono::steady_clock::now();
	auto            res   = Decoder::Decode(
	    h->decoder,
	    {data, static_cast<size_t>(size), d[2], d[3], d[4], fb, static_cast<size_t>(fb_size)}, {},
	    &decoded);
	if (!decoded.input_accepted) {
		LOGF("VdecCore::SetDecodeInput decoder did not take the AU, result=%d\n",
		     static_cast<int>(res));
		return VDECCORE_ERROR_ARGUMENT;
	}

	h->job_pending = true;
	h->job_failed  = false;
	while (res == Decoder::Result::Ok && decoded.valid) {
		QueuePicture(h, decoded);
		res = Decoder::Flush(h->decoder, {}, &decoded);
	}
	if (res != Decoder::Result::Ok) {
		LOGF("VdecCore::SetDecodeInput picture output failed, result=%d\n", static_cast<int>(res));
		h->job_failed = true;
	}
	if (Diag()) {
		const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
		    std::chrono::steady_clock::now() - begin);
		LOGF("VdecCore::SetDecodeInput decode took %lld us, ready=%zu\n",
		     static_cast<long long>(us.count()), h->ready.size());
	}

	*out = 1ull << 32;
	return OK;
}

static int32_t KYTY_SYSV_ABI SyncDecode(void* handle, int32_t* count_out) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}

	std::scoped_lock lock(h->m);
	if (!h->job_pending) {
		return VDECCORE_ERROR_ARGUMENT;
	}
	h->job_pending = false;

	// already decoded in SetDecodeInput; 0 pictures while reordering
	const int32_t n = static_cast<int32_t>(h->ready.size());
	if (count_out != nullptr) {
		*count_out = n;
	}

	if (Diag()) {
		LOGF("VdecCore::SyncDecode handle=%p pictures=%d failed=%d\n", handle, n,
		     h->job_failed ? 1 : 0);
	}
	return h->job_failed ? VDECCORE_ERROR_ARGUMENT : OK;
}

static int32_t KYTY_SYSV_ABI GetDecodeOutput(void* handle, uint64_t /*unused0*/,
                                             uint64_t /*unused1*/, void* desc) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (desc == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	std::scoped_lock lock(h->m);
	if (h->ready.empty()) {
		return VDECCORE_ERROR_ARGUMENT;
	}
	const ReadyFrame frame = h->ready.front();
	h->ready.pop_front();

	// Explicit sample aspect ratio is idc 255 at +62 with the ratio at +56/+58.
	// flag 0x40000 at +48: primaries/transfer/matrix at +63..+65 present. +60/+61 (depth - 8) stay
	// 0
	auto* info = &h->color_meta[0];
	std::memset(info, 0, sizeof(h->color_meta));
	if (frame.info.sar_width > 0 && frame.info.sar_height > 0) {
		info[62] = 255;
		std::memcpy(info + 56, &frame.info.sar_width, 2);
		std::memcpy(info + 58, &frame.info.sar_height, 2);
	}
	if (frame.info.color_primaries != 2 || frame.info.color_trc != 2 ||
	    frame.info.color_space != 2) {
		const uint32_t flags = 0x40000;
		std::memcpy(info + 48, &flags, 4);
		info[63] = frame.info.color_primaries;
		info[64] = frame.info.color_trc;
		info[65] = frame.info.color_space;
	}

	auto* d = static_cast<uint8_t*>(desc);
	std::memset(d, 0, 208);

	// VSE finds the pending frame item by the pointer at +16, which is the one it passed in the AU
	// descriptor.
	const uint32_t entries = 1;
	const uint32_t kind    = 4;
	std::memcpy(d + 0, &frame.width, 4);
	std::memcpy(d + 4, &frame.pitch, 4);
	std::memcpy(d + 8, &frame.height, 4);
	std::memcpy(d + 12, &entries, 4);
	std::memcpy(d + 16, &frame.base, 8);
	std::memcpy(d + 32, &kind, 4);
	std::memcpy(d + 40, &frame.info.pts, 8);
	std::memcpy(d + 48, &frame.info.dts, 8);
	std::memcpy(d + 56, &frame.info.attached_data, 8);
	std::memcpy(d + 64, &info, 8);
	std::memcpy(d + 180, &frame.pitch, 4);
	std::memcpy(d + 184, &frame.base, 8);
	std::memcpy(d + 192, &frame.size, 8);
	// VSE treats nonzero desc+172 or desc+204 as a decode error

	if (Diag()) {
		LOGF("VdecCore::GetDecodeOutput handle=%p base=0x%" PRIx64 " %ux%u pitch=%u pts=0x%" PRIx64
		     " left=%zu\n",
		     handle, frame.base, frame.width, frame.height, frame.pitch, frame.info.pts,
		     h->ready.size());
	}
	return OK;
}

// Videodec2 uses the Bid submit/get-output pair instead of the NIDs above.
// Submit desc: output frame buffer +0, AU +0x10, has-output byte +0x40. Decode is async in
// firmware, so submit only reports accepted.
static int32_t KYTY_SYSV_ABI SetDecodeInputBid(void* handle, const void* in_desc,
                                               uint32_t* out_flag) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (in_desc == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}
	if (out_flag != nullptr) {
		*out_flag = 1;
	}

	const auto* p       = static_cast<const uint8_t*>(in_desc);
	uint64_t    out_buf = 0, out_buf_size = 0, au_data = 0, au_size = 0, pts = 0;
	uint32_t    hint_w = 0, hint_h = 0;
	uint8_t     has_out = 0;
	std::memcpy(&out_buf, p + 0x00, sizeof(out_buf));
	std::memcpy(&out_buf_size, p + 0x08, sizeof(out_buf_size));
	std::memcpy(&au_data, p + 0x10, sizeof(au_data));
	std::memcpy(&au_size, p + 0x18, sizeof(au_size));
	std::memcpy(&pts, p + 0x20, sizeof(pts));
	std::memcpy(&hint_w, p + 0x38, sizeof(hint_w));
	std::memcpy(&hint_h, p + 0x3c, sizeof(hint_h));
	has_out = p[0x40];

	if (Diag()) {
		LOGF("VdecCore::SetDecodeInputBid handle=%p au=0x%" PRIx64 " size=0x%" PRIx64
		     " out=0x%" PRIx64 " outSize=0x%" PRIx64 " hint=%ux%u hasOut=%u pts=0x%" PRIx64 "\n",
		     handle, au_data, au_size, out_buf, out_buf_size, hint_w, hint_h, has_out, pts);
	}

	if (au_data == 0 || au_size == 0) {
		return OK;
	}

	std::scoped_lock lock(h->m);

	uint64_t base = 0, bsz = 0;
	if (has_out == 1 && out_buf != 0) {
		base = out_buf;
		bsz  = out_buf_size;
	} else {
		EnsureFrameRegions(h);
		if (h->frame_regions.empty()) {
			if (Diag()) {
				LOGF("VdecCore::SetDecodeInputBid no output buffer and no mapped frame regions\n");
			}
			return OK;
		}
		const size_t ri = h->frame_regions[h->next_buffer % h->frame_regions.size()];
		h->next_buffer++;
		base = h->regions[ri].first;
		bsz  = h->regions[ri].second;
	}

	Decoder::Output decoded {};
	const auto      res = Decoder::Decode(
	    h->decoder,
	    {reinterpret_cast<void*>(au_data), static_cast<size_t>(au_size), pts,
		 Decoder::TIMESTAMP_INVALID, 0, reinterpret_cast<void*>(base), static_cast<size_t>(bsz)},
	    {reinterpret_cast<void*>(base), static_cast<size_t>(bsz)}, &decoded);
	if (decoded.input_accepted) {
		h->job_pending = true;
		h->job_failed  = false;
	}
	if (res != Decoder::Result::Ok) {
		if (Diag()) {
			LOGF("VdecCore::SetDecodeInputBid decode result=%d\n", static_cast<int>(res));
		}
		return OK;
	}
	if (decoded.valid) {
		h->ready.push_back({base, decoded.width, decoded.height, decoded.pitch, pts});
		if (Diag()) {
			LOGF("VdecCore: decoded %ux%u pitch=%u base=0x%" PRIx64 " ready=%zu (bid)\n",
			     decoded.width, decoded.height, decoded.pitch, base, h->ready.size());
		}
	}
	return OK;
}

// out_info: frame type +0, pts +8/+24, dims record pointer +32. Type 4 = HEVC progressive, dims+60
// == 0 is 8-bit
static int32_t KYTY_SYSV_ABI GetDecodeOutputBid(void* handle, void* /*scratch*/, void* out_info,
                                                int32_t /*mode*/) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (out_info == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	ReadyFrame frame {};
	void*      dims_ptr = nullptr;
	{
		std::scoped_lock lock(h->m);
		if (h->ready.empty()) {
			return VDECCORE_ERROR_WOULD_BLOCK;
		}
		frame = h->ready.front();
		h->ready.pop_front();
		std::memset(h->dims, 0, sizeof(h->dims));
		std::memcpy(h->dims + 0, &frame.width, 4);
		std::memcpy(h->dims + 4, &frame.height, 4);
		dims_ptr = &h->dims[0];
	}

	auto* o = static_cast<uint8_t*>(out_info);
	std::memset(o, 0, 48);
	const uint32_t frame_type = 4;
	std::memcpy(o + 0, &frame_type, 4);
	std::memcpy(o + 8, &frame.pts, 8);
	std::memcpy(o + 24, &frame.pts, 8);
	std::memcpy(o + 32, &dims_ptr, 8);

	if (Diag()) {
		LOGF("VdecCore::GetDecodeOutputBid handle=%p base=0x%" PRIx64 " %ux%u pts=0x%" PRIx64 "\n",
		     handle, frame.base, frame.width, frame.height, frame.pts);
	}
	return OK;
}

static int32_t KYTY_SYSV_ABI FlushDecodeOutput(void* handle, int32_t* count_out, void* /*unused*/) {
	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (count_out == nullptr) {
		return VDECCORE_ERROR_ARGUMENT;
	}

	std::scoped_lock lock(h->m);
	EnsureFrameRegions(h);

	for (;;) {
		// Only pictures submitted through the Bid path land here; an AU from SetDecodeInput brought
		// its own buffer.
		Decoder::FrameBuffer fallback {};
		if (!h->frame_regions.empty()) {
			const size_t ri = h->frame_regions[h->next_buffer % h->frame_regions.size()];
			fallback        = {reinterpret_cast<void*>(h->regions[ri].first),
			                   static_cast<size_t>(h->regions[ri].second)};
		}

		Decoder::Output decoded {};
		const auto      res = Decoder::Drain(h->decoder, fallback, &decoded);
		if (res != Decoder::Result::Ok || !decoded.valid) {
			break;
		}
		h->next_buffer++;
		QueuePicture(h, decoded);
	}

	// VSE calls GetDecodeOutput this many times, stopping at the first failure
	h->job_pending = false;
	*count_out     = static_cast<int32_t>(h->ready.size());

	if (Diag()) {
		LOGF("VdecCore::FlushDecodeOutput handle=%p pictures=%d\n", handle, *count_out);
	}
	return OK;
}

static int32_t KYTY_SYSV_ABI ResetDecoder(void* handle, const uint32_t* arg) {
	PRINT_NAME();

	auto h = Get(handle);
	if (h == nullptr) {
		return VDECCORE_ERROR_INSTANCE;
	}
	if (arg != nullptr && (arg[0] != 0 || arg[1] >= 3)) {
		return VDECCORE_ERROR_RESET_ARG;
	}

	std::scoped_lock lock(h->m);
	Decoder::Reset(h->decoder);
	h->ready.clear();
	h->next_buffer = 0;
	h->job_pending = false;
	h->job_failed  = false;
	return OK;
}

static int32_t KYTY_SYSV_ABI DeleteDecoder(void* handle) {
	PRINT_NAME();

	Handle* h = nullptr;
	{
		std::unique_lock lock(g_handle_mutex);
		auto             it = g_handles.find(handle);
		if (it == g_handles.end()) {
			return VDECCORE_ERROR_INSTANCE;
		}
		h = static_cast<Handle*>(*it);
		g_handles.erase(it);
		g_handle_cv.wait(lock, [h] { return h->ref_count == 0; });
	}

	Decoder::Destroy(h->decoder);
	delete h;
	return OK;
}

// Svp/DRM variants, not used by the boot movie
static int32_t KYTY_SYSV_ABI CreateDecoderSvp(uint64_t, const void*, void*, void**) {
	PRINT_NAME();
	LOGF("VdecCore::CreateDecoderSvp not supported\n");
	return VDECCORE_ERROR_UNSUPPORTED;
}

static int32_t KYTY_SYSV_ABI SetDecodeInputSvp(void*, const void*, void*, void*) {
	PRINT_NAME();
	return VDECCORE_ERROR_UNSUPPORTED;
}

static int32_t KYTY_SYSV_ABI DrmQuery(void*, void*, void*, void*) {
	PRINT_NAME();
	static const bool bypass = std::getenv("KYTY_DIAGNOSTIC_VDECCORE_DRM") != nullptr;
	if (bypass) {
		LOGF("VdecCore: DRM check bypassed NON_AUTHENTIC (KYTY_DIAGNOSTIC_VDECCORE_DRM)\n");
		return OK;
	}
	return VDECCORE_ERROR_UNSUPPORTED;
}

LIB_DEFINE(InitVdecCore_1) {
	PRINT_NAME_ENABLE(true);

	LIB_FUNC("Zsh1K8YTD1E", QueryInstanceSize);
	LIB_FUNC("UxV5adxfBFg", QueryFrameBufferInfo);
	LIB_FUNC("ZZnvlKc8nfg", CreateDecoderBid);
	LIB_FUNC("hUza-a0hX2c", MapMemory);
	LIB_FUNC("F4nrEfi-M84", SetDecodeInput);
	LIB_FUNC("S+a76Q3kh+k", SetDecodeInputBid);
	LIB_FUNC("OyxRC7GT4Es", SyncDecode);
	LIB_FUNC("K4sH-0WUfuc", GetDecodeOutput);
	LIB_FUNC("jLPubkiwpac", GetDecodeOutputBid);
	LIB_FUNC("b0xbD0x+02M", FlushDecodeOutput);
	LIB_FUNC("nFn-3CWQEyo", ResetDecoder);
	LIB_FUNC("D0RWslNmK9s", DeleteDecoder);
	LIB_FUNC("xI8avtVkGWw", CreateDecoderSvp);
	LIB_FUNC("cPn3fXO-J5M", SetDecodeInputSvp);
	LIB_FUNC("uAsJCITzX5k", DrmQuery);
}

} // namespace VdecCore

} // namespace Libs
