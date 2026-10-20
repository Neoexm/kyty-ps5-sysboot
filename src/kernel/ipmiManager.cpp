#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/appMount.h"
#include "kernel/budget.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "common/logging/log.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel {
bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool writable);
}


namespace Libs::LibKernel::IpmiManager {

namespace {
enum class AdmissionReason : uint8_t {
	PeerMissing,
	AuthInfoMissing,
	FilteredAuthority,
	CapabilityMismatch,
};
struct AdmissionTraceKey {
	int             pid                    = 0;
	uint64_t        public_authority       = 0;
	bool            public_authority_valid = false;
	bool            authority_known        = false;
	bool            capability62_known     = false;
	AdmissionReason reason                 = AdmissionReason::PeerMissing;
	std::string     name;
};

std::mutex                     admission_trace_mutex;
std::vector<AdmissionTraceKey> admission_trace_keys;
const char* AdmissionReasonName(AdmissionReason reason) {
	switch (reason) {
		case AdmissionReason::PeerMissing: return "peer_missing";
		case AdmissionReason::AuthInfoMissing: return "authinfo_missing";
		case AdmissionReason::FilteredAuthority: return "filtered_authority";
		case AdmissionReason::CapabilityMismatch: return "capability_mismatch";
	}
	return "unknown";
}
std::string ServiceHex(std::string_view name) {
	constexpr char digits[] = "0123456789abcdef";
	const auto     size     = std::min<size_t>(name.size(), 96);
	std::string    result;
	result.reserve(size * 2);
	for (size_t i = 0; i < size; ++i) {
		const auto ch    = name[i];
		const auto value = static_cast<uint8_t>(ch);
		result.push_back(digits[value >> 4]);
		result.push_back(digits[value & 15]);
	}
	return result;
}
void TraceAdmissionDecision(int pid, std::string_view name, const AuthInfo::Record* auth_info,
                            AdmissionReason reason, int rc,
                            const AuthInfo::AuthorizationFacts* facts = nullptr) {
	if (Log::IsSilent()) return;
	uint64_t public_authority       = 0;
	bool     public_authority_valid = false;
	if (auth_info != nullptr) {
		const auto filtered    = AuthInfo::Filter(*auth_info);
		public_authority       = AuthInfo::AuthorityId(filtered);
		public_authority_valid = public_authority != 0;
	}
	const bool authority_known    = facts && facts->has_authority;
	const bool capability62_known = facts && (facts->known_capability0 & (1ull << 62));
	bool       emit               = false;
	{
		std::lock_guard lock(admission_trace_mutex);
		const bool      seen = std::any_of(
		    admission_trace_keys.begin(), admission_trace_keys.end(), [&](const auto& key) {
			    return key.pid == pid && key.public_authority == public_authority &&
				       key.public_authority_valid == public_authority_valid &&
				       key.authority_known == authority_known &&
				       key.capability62_known == capability62_known && key.reason == reason &&
				       key.name == name;
		    });
		if (!seen && admission_trace_keys.size() < 128) {
			admission_trace_keys.push_back({pid, public_authority, public_authority_valid,
			                                authority_known, capability62_known, reason,
			                                std::string(name)});
			emit = true;
		}
	}
	if (!emit) return;
	const auto service_hex = ServiceHex(name);
	LOGF("ORIGINAL_APP_IPMI_ADMISSION_DECISION pid=%d service_hex=%s public_authority=%016llx"
	     " public_authority_valid=%u reason=%s kernel_result=%08x posix_errno=%d"
	     " config_read=0 registration_attempted=0 authority_known=%u capability62_known=%u "
	     "full_record_required=0\n",
	     pid, service_hex.c_str(), static_cast<unsigned long long>(public_authority),
	     public_authority_valid ? 1u : 0u, AdmissionReasonName(reason), static_cast<unsigned>(rc),
	     KernelToPosix(rc), authority_known ? 1u : 0u, capability62_known ? 1u : 0u);
}
} // namespace
} // namespace Libs::LibKernel::IpmiManager
