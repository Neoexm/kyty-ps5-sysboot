#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "libs/errno.h"
#include "common/logging/log.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {
thread_local int test_pid = 101;
thread_local Libs::LibKernel::AuthInfo::Record test_auth_info {};
thread_local uint64_t test_public_auth_id = 0;
thread_local bool test_peer_exists = true;
thread_local bool test_has_auth_info = false;
thread_local bool test_partial_auth = false;
thread_local bool test_has_identity = false;
thread_local Libs::LibKernel::AuthInfo::ImageIdentity test_identity;
thread_local int test_remote_pid = 0;
thread_local uint32_t test_remote_host_pid = 0;
thread_local uint64_t test_remote_host_birth = 0;
thread_local std::function<void()> test_remote_lookup;
thread_local Libs::LibKernel::AuthInfo::AuthorizationFacts test_authorization;
thread_local bool test_capture_log = false;
thread_local std::vector<std::string> test_log;
thread_local uint64_t test_non_guest_address = 0;
thread_local uint64_t test_non_guest_size = 0;
thread_local uint64_t test_jemspace_address = 0;
thread_local uint64_t test_jemspace_size = 0;
std::atomic_bool test_jemspace_live {true};
thread_local uint64_t test_stack_address = 0;
thread_local uint64_t test_stack_size = 0;
bool ContainsRange(uint64_t outer, uint64_t outer_size, uint64_t inner, uint64_t inner_size) {
    return outer && inner >= outer && inner_size <= outer_size && inner - outer <= outer_size - inner_size;
}
void Check(bool value, const char* text) {
    if (!value) { std::fprintf(stderr, "IpmiManagerTests: %s\n", text); std::abort(); }
}
template<class T> uint64_t Address(T* value) { return reinterpret_cast<uint64_t>(value); }
int Call(uint32_t command, int handle, void* args, size_t size) {
    int32_t result = -1;
    int status = -1;
    Check(Libs::LibKernel::IpmiManager::TryCall(command, handle, &result, args, size, 0x1234, &status), "handled fixture request");
    Check(status == 0, "native call status");
    return result;
}
void CheckServerRejected(void* args, size_t size, int error, const char* name = nullptr) {
    int32_t result = 0x5a123456;
    int status = 0;
    *Libs::Posix::GetErrorAddr() = 0;
    Check(Libs::LibKernel::IpmiManager::TryCall(0, 0, &result, args, size, 0x1234, &status) &&
          status == -1 && *Libs::Posix::GetErrorAddr() == error && result == 0x5a123456,
          "server rejection returns transport errno without modifying logical result");
    if (name) {
        uint32_t server = 0, owner = 0, host = 0;
        Check(!Libs::LibKernel::IpmiScope::Lookup(name, &server, &owner, &host),
              "rejected server is not admitted to the shared namespace");
    }
}
struct ServerBuffers {
    std::array<uint8_t, 0x2900> bytes {};
    std::array<uint64_t, 3> info {};
    uint32_t timeout = 0;
    int Receive(int handle, size_t capacity = 0x2900) {
        uint64_t args[4] {Address(bytes.data()), capacity, Address(info.data()), Address(&timeout)};
        return Call(0x201, handle, args, sizeof(args));
    }
    void Await(int handle) {
        const auto bound = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        for (;;) {
            int result = Receive(handle);
            if (result == 0) return;
            Check(result == Libs::LibKernel::KERNEL_ERROR_EAGAIN, "poll status");
            Check(std::chrono::steady_clock::now() < bound, "fixture request deadline");
            std::this_thread::yield();
        }
    }
};
}
namespace Log {
bool IsSilent() { return !test_capture_log; }
void Write(std::string_view text) { test_log.emplace_back(text); }
void Flush() {}
}
namespace Libs::Posix {
int* GetErrorAddr() { static thread_local int error = 0; return &error; }
}
namespace Libs::LibKernel::Process {
int GetPid() { return test_pid; }
bool FindPeerByPid(int pid, PeerProcess* peer) {
    if (pid == test_remote_pid) {
        if (test_remote_lookup) std::exchange(test_remote_lookup, nullptr)();
        *peer = {};
        peer->pid = pid;
        peer->host_pid = test_remote_host_pid;
        peer->host_birth = test_remote_host_birth;
        return true;
    }
    if (pid != test_pid || !test_peer_exists) return false;
    *peer = {};
    peer->pid = pid;
    peer->has_auth_info = test_has_auth_info;
    peer->auth_info = test_auth_info;
    peer->auth_id = test_public_auth_id;
    return true;
}
AuthInfo::AuthorizationFacts GetCurrentAuthorizationFacts() {
    if (test_partial_auth) return test_authorization;
    if (!test_has_auth_info) return {};
    return {true, AuthInfo::AuthorityId(test_auth_info), AuthInfo::Capability0(test_auth_info), UINT64_MAX};
}
bool GetVerifiedOriginalSelfIdentity(AuthInfo::ImageIdentity* identity) {
    if (!test_has_identity || identity == nullptr) return false;
    *identity = test_identity;
    return true;
}
}
namespace Libs::LibKernel::AppMount {
bool GetAttachedApp(int pid, int32_t* app_id) { (void)pid; (void)app_id; return false; }
}
namespace Libs::LibKernel::Budget {
bool Ptype(int pid, int32_t* ptype) { (void)pid; (void)ptype; return false; }
}
namespace Libs::LibKernel::Memory {
int KYTY_SYSV_ABI KernelVirtualQuery(const void* addr, int, VirtualQueryInfo* info, uint64_t) {
    if (ContainsRange(test_non_guest_address, test_non_guest_size,
                      reinterpret_cast<uint64_t>(addr), 1)) return KERNEL_ERROR_EACCES;
    MEMORY_BASIC_INFORMATION region {};
    if (!VirtualQuery(addr, &region, sizeof(region))) return KERNEL_ERROR_EFAULT;
    *info = {};
    info->start = Address(static_cast<uint8_t*>(region.BaseAddress));
    info->end = info->start + region.RegionSize;
    info->is_committed = region.State == MEM_COMMIT;
    const DWORD protection = region.Protect & 0xff;
    if (!(region.Protect & PAGE_GUARD) && protection != PAGE_NOACCESS) info->protection |= 1;
    if (!(region.Protect & PAGE_GUARD) && (protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY)) info->protection |= 2;
    return OK;
}

bool QueryGuestRangeNoTrace(const void* address, VirtualQueryInfo* info) {
    return KernelVirtualQuery(address, 0, info, sizeof(*info)) == OK;
}
bool CanWriteGuest(const void* destination, uint64_t size) {
    uint64_t cursor = reinterpret_cast<uint64_t>(destination);
    if (size == 0) return true;
    if (!cursor || size > UINT64_MAX - cursor) return false;
    const uint64_t end = cursor + size;
    while (cursor < end) {
        VirtualQueryInfo region {};
        if (KernelVirtualQuery(reinterpret_cast<void*>(cursor), 0, &region, sizeof(region)) != OK ||
            !region.is_committed || !(region.protection & 2) || region.end <= cursor) return false;
        cursor = std::min<uint64_t>(end, region.end);
    }
    return true;
}
bool CopyToGuest(void* destination, const void* source, uint64_t size) {
    if (!CanWriteGuest(destination, size)) return false;
    SIZE_T copied = 0;
    return !size || (WriteProcessMemory(GetCurrentProcess(), destination, source, size, &copied) && copied == size);
}
bool CopyFromGuest(void* destination, const void* source, uint64_t size) {
    if (size == 0) return true;
    const auto address = reinterpret_cast<uint64_t>(source);
    if (destination == nullptr || source == nullptr || size > UINT64_MAX - address) return false;
    const auto end = address + size;
    for (auto cursor = address; cursor < end;) {
        VirtualQueryInfo region {};
        if (KernelVirtualQuery(reinterpret_cast<void*>(cursor), 0, &region, sizeof(region)) != OK ||
            !region.is_committed || !(region.protection & 1) || region.end <= cursor) return false;
        cursor = std::min<uint64_t>(end, region.end);
    }
    std::memcpy(destination, source, size);
    return true;
}
}

namespace Libs::LibKernel {
bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool) {
    return ContainsRange(test_stack_address, test_stack_size,
                         reinterpret_cast<uint64_t>(pointer), size);
}
}

namespace Libs::Jemspace {
bool QueryAllocation(const void* pointer, uint64_t size, uint64_t* offset, uint64_t* allocation_size) {
    const auto address = reinterpret_cast<uint64_t>(pointer);
    if (!test_jemspace_live.load() ||
        !ContainsRange(test_jemspace_address, test_jemspace_size, address, size)) return false;
    if (offset) *offset = address - test_jemspace_address;
    if (allocation_size) *allocation_size = test_jemspace_size;
    return true;
}
bool CopyFromAllocation(void* destination, const void* source, uint64_t size) {
    if (size == 0) return true;
    if (destination == nullptr || !QueryAllocation(source, size, nullptr, nullptr)) return false;
    std::memcpy(destination, source, size);
    return true;
}
bool CopyToAllocation(void* destination, const void* source, uint64_t size) {
    if (size == 0) return true;
    if (source == nullptr || !QueryAllocation(destination, size, nullptr, nullptr)) return false;
    std::memcpy(destination, source, size);
    return true;
}
}

void CheckAdmissionDecisionTrace() {
    using namespace Libs::LibKernel;
    uint64_t object = 1;
    const char name[] = "SceAdmissionFixture";
    uint64_t create[3] {Address(&object), Address(name), 1};
    auto StoreAuth64 = [&](size_t offset, uint64_t value) {
        std::memcpy(test_auth_info.data() + offset, &value, sizeof(value));
    };
    auto Count = [](std::string_view needle) {
        return std::count_if(test_log.begin(), test_log.end(), [&](const auto& line) {
            return line.find(needle) != std::string::npos;
        });
    };
    auto Find = [](std::string_view reason) -> const std::string& {
        const auto found = std::find_if(test_log.begin(), test_log.end(), [&](const auto& line) {
            return line.find("ORIGINAL_APP_IPMI_ADMISSION_DECISION") != std::string::npos &&
                   line.find(reason) != std::string::npos;
        });
        Check(found != test_log.end(), "admission decision marker reason");
        return *found;
    };

    test_capture_log = true;
    test_log.clear();
    test_peer_exists = false;
    test_has_auth_info = false;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);

    test_peer_exists = true;
    test_public_auth_id = 0xfeedfacecafebeefull;
    StoreAuth64(0, 0x3800000000000011ull);
    StoreAuth64(8, 1ull << 62);
    test_has_auth_info = false;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);

    StoreAuth64(0, 0x4800000010000004ull);
    test_has_auth_info = true;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);

    StoreAuth64(0, 0x3800000000000011ull);
    StoreAuth64(8, 0);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, name);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, name);

    Check(Count("ORIGINAL_APP_IPMI_ADMISSION_DECISION") == 4,
          "admission decision marker is one-shot per process, service, public authority and reason");
    const auto& peer_missing = Find("reason=peer_missing");
    Check(peer_missing.find("pid=101 service_hex=53636541646d697373696f6e46697874757265") != std::string::npos &&
          peer_missing.find("public_authority=0000000000000000 public_authority_valid=0") != std::string::npos &&
          peer_missing.find("kernel_result=8002004e posix_errno=78 config_read=0 registration_attempted=0") != std::string::npos,
          "missing peer marker has zero authority and unchanged ENOSYS boundary state");
    const auto& authinfo_missing = Find("reason=authinfo_missing");
    Check(authinfo_missing.find("public_authority=0000000000000000 public_authority_valid=0") != std::string::npos &&
          authinfo_missing.find("kernel_result=8002004e posix_errno=78 config_read=0 registration_attempted=0") != std::string::npos,
          "missing authinfo marker exposes no unverified SELF authority before configuration access");
    const auto& filtered = Find("reason=filtered_authority");
    Check(filtered.find("public_authority=4800000010000004 public_authority_valid=1") != std::string::npos &&
          filtered.find("kernel_result=8002004e posix_errno=78 config_read=0 registration_attempted=0") != std::string::npos,
          "filtered authority marker exposes only the verified public filter and preserves ENOSYS");
    const auto& mismatch = Find("reason=capability_mismatch");
    Check(mismatch.find("public_authority=0000000000000000 public_authority_valid=0") != std::string::npos &&
          mismatch.find("kernel_result=80020001 posix_errno=1 config_read=0 registration_attempted=0") != std::string::npos,
          "capability mismatch marker hides nonpublic authority and preserves EPERM");
    for (const auto& line: test_log) {
        if (line.find("ORIGINAL_APP_IPMI_ADMISSION_DECISION") != std::string::npos) {
            Check(line.find(" service=") == std::string::npos && line.find("self_authority=") == std::string::npos,
                  "admission decision marker never exposes raw service or SELF identity fields");
            Check(line.find("feedfacecafebeef") == std::string::npos,
                  "admission decision marker never exposes unfiltered peer SELF authority");
        }
    }
    Check(Count("result_untouched=1") == 8,
          "all repeated admission failures preserve the logical output contract");
    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 0, 0};
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);
    Check(Count("ORIGINAL_APP_IPMI_ADMISSION_DECISION") == 5 &&
          std::any_of(test_log.begin(), test_log.end(), [](const auto& line) {
              return line.find("reason=authinfo_missing") != std::string::npos &&
                     line.find("authority_known=1 capability62_known=0 full_record_required=0") != std::string::npos;
          }),
          "newly known authority emits a distinct missing-capability decision");
    test_partial_auth = false;
    test_authorization = {};

    test_peer_exists = false;
    const char injected_name[] = "SceTrace\nreason=spoof";
    create[1] = Address(injected_name);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, injected_name);
    const auto injected = std::find_if(test_log.begin(), test_log.end(), [](const auto& line) {
        return line.find("service_hex=53636554726163650a726561736f6e3d73706f6f66") != std::string::npos;
    });
    Check(injected != test_log.end() && injected->find("SceTrace") == std::string::npos &&
          injected->find('\r') == std::string::npos && injected->find('\n') == injected->size() - 1,
          "guest service bytes cannot inject admission marker fields or records");
    for (int i = 0; i < 140; ++i) {
        const std::string bounded_name = "SceAdmissionBound" + std::to_string(i);
        create[1] = Address(bounded_name.c_str());
        CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, bounded_name.c_str());
    }
    Check(Count("ORIGINAL_APP_IPMI_ADMISSION_DECISION") == 128,
          "admission decision marker has a fixed process-wide record bound");

    test_capture_log = false;
    test_log.clear();
    test_peer_exists = true;
    test_public_auth_id = 0;
    test_has_auth_info = false;
    test_auth_info = {};
}

void CheckPartialAuthorization() {
    using namespace Libs::LibKernel;
    test_partial_auth = true;
    test_has_auth_info = false;
    test_authorization = {};
    std::array<uint8_t, 56> config {};
    uint64_t create[3] {1, Address("ScePartialAuthFixture"), Address(config.data())};
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS);
    test_authorization.has_authority = true;
    test_authorization.authority_id = 0x4800000000000007ull;
    test_authorization.capability0 = UINT64_MAX;
    test_authorization.known_capability0 = ~(1ull << 62);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS);
    Check(IpmiManager::ValidateServerAuthorization("guest.ipc", test_authorization) == KERNEL_ERROR_ENOSYS,
          "unknown system bit is not a known non-system credential");
    test_authorization.known_capability0 = 1ull << 62;
    test_authorization.has_authority = false;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS);
    test_authorization.has_authority = true;
    test_authorization.capability0 = 0;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM);
    Check(IpmiManager::ValidateServerAuthorization("guest.ipc", test_authorization) == OK,
          "one known clear capability bit suffices for non-system authorization");
    test_authorization.capability0 = 1ull << 62;
    const int server = Call(0, 0, create, sizeof(create));
    Check(server > 0 && !test_has_auth_info,
          "partial synthetic fixture registers without constructing an AuthInfo record");
    Check(Call(1, server, nullptr, 0) == OK, "partial authorization fixture cleanup");
    for (const uint64_t authority: {0x4800000010000004ull, 0x4800000010000011ull,
         0x4800000010000012ull, 0x4800000010000013ull, 0x4800000000001010ull}) {
        test_authorization.authority_id = authority;
        test_authorization.known_capability0 = 0;
        CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS);
    }
    test_partial_auth = false;
    test_authorization = {};
}

void CheckPupUtilDiagnosticAdmission() {
    using namespace Libs::LibKernel;
    static constexpr char self[] = "fbfb75883655ae35c26981402f59dbd4c5a35ce1b35dd9dc26ecf89edfffe1f2";
    static constexpr char elf[] = "8eb94402b0d055ad0276a0bfc1fe34e2135ac349cad44d4cbe42cf68e90349b0";
    std::array<uint8_t, 56> config {};
    const char name[] = "SceUpdatePupUtilService";
    uint64_t create[3] {1, Address(name), Address(config.data())};

    test_partial_auth = true;
    test_authorization = {true, 0x480000000000100dull, 0, 1ull << 62};
    test_has_identity = true;
    test_identity = {};
    test_identity.authority_id = test_authorization.authority_id;
    test_identity.self_size = 283036;
    test_identity.elf_size = 669468;
    Check(AuthInfo::ParseDigestHex(self, &test_identity.self_sha256), "PupUtil SELF fixture digest");
    Check(AuthInfo::ParseDigestHex(elf, &test_identity.elf_sha256), "PupUtil ELF fixture digest");

    _putenv_s("KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION", "");
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, name);
    _putenv_s("KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION", "1");
    test_capture_log = true;
    test_log.clear();
    const int server = Call(0, 0, create, sizeof(create));
    Check(server > 0, "exact PupUtil identity is admitted behind the diagnostic gate");
    Check(std::count_if(test_log.begin(), test_log.end(), [](const auto& line) {
        return line.find("NON_AUTHENTIC_IPMI_PUPUTIL_ADMISSION") != std::string::npos;
    }) == 1, "PupUtil diagnostic admission logs the NON_AUTHENTIC marker");
    Check(Call(1, server, nullptr, 0) == OK, "PupUtil diagnostic server cleanup");

    test_identity.self_size++;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, name);
    test_identity.self_size--;
    const char other[] = "SceUpdatePupUtilService2";
    create[1] = Address(other);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, other);
    create[1] = Address(name);
    test_identity.authority_id++;
    test_authorization.authority_id++;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EPERM, name);

    _putenv_s("KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION", "");
    test_capture_log = false;
    test_log.clear();
    test_has_identity = false;
    test_identity = {};
    test_partial_auth = false;
    test_authorization = {};
}

void CheckCreationNames() {
    using namespace Libs::LibKernel;
    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
    std::array<uint64_t, 7> config {};
    std::string name = "Sce" + std::string(21, 'x');
    uint64_t create[3] {1, Address(name.data()), Address(config.data())};
    const int server = Call(0, 0, create, sizeof(create));
    Check(server > 0, "24-byte server name is accepted");
    create[2] = 0;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EINVAL);
    create[2] = 1;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EFAULT);
    create[2] = Address(config.data());
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EEXIST);
    Check(Call(1, server, nullptr, 0) == OK, "24-byte server name cleanup");
    name.push_back('x');
    create[1] = Address(name.data());
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENAMETOOLONG, name.c_str());
    std::array<uint64_t, 42> client_config {};
    client_config[0] = sizeof(client_config);
    create[2] = Address(client_config.data());
    int32_t result = 0x12345678;
    int status = 0;
    Check(IpmiManager::TryCall(2, 0, &result, create, sizeof(create), 0, &status) && status == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG && result == 0x12345678,
          "client creation enforces the same 24-byte limit without changing output");
    name.pop_back();
    create[1] = Address(name.data());
    const int client = Call(2, 0, create, sizeof(create));
    Check(client > 0 && Call(3, client, nullptr, 0) == OK, "24-byte disconnected client name is accepted");
    auto* pages = static_cast<char*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Check(pages != nullptr, "name boundary fixture allocation");
    DWORD previous = 0;
    Check(VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous), "name boundary fixture guard");
    std::memcpy(pages + 4096 - 25, name.c_str(), 25);
    create[1] = Address(pages + 4096 - 25);
    create[2] = Address(config.data());
    const int boundary_server = Call(0, 0, create, sizeof(create));
    Check(boundary_server > 0 && Call(1, boundary_server, nullptr, 0) == OK,
          "valid name terminator at mapping boundary does not read the guard page");
    pages[4095] = 'x';
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENAMETOOLONG);
    create[1] = Address(pages + 4096 - 24);
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EFAULT);
    create[1] = UINT64_MAX;
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EFAULT);
    Check(VirtualFree(pages, 0, MEM_RELEASE), "name boundary fixture cleanup");
    test_partial_auth = false;
    test_authorization = {};
}

void CheckServerDirectoryCapacity() {
    using namespace Libs::LibKernel;
    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
    const uint64_t handler = 0x00000008c0ffee10ull;
    std::array<uint64_t, 7> server_config {};
    server_config[6] = handler;
    uint64_t object = 1;
    std::vector<int> servers;
    servers.reserve(512);
    for (int i = 0; i < 48; ++i) {
        const std::string name = "SceCapacity" + std::to_string(i);
        uint64_t create[3] {Address(&object), Address(name.c_str()), Address(server_config.data())};
        const int server = Call(0, 0, create, sizeof(create));
        Check(server > 0, "first 48 shared server rows");
        servers.push_back(server);
    }

    const char db_name[] = "SceDbRecoveryShellCore";
    uint64_t db_create[3] {Address(&object), Address(db_name), Address(server_config.data())};
    const int db_server = Call(0, 0, db_create, sizeof(db_create));
    Check(db_server > 0, "DbRecovery is admitted as the 49th shared server");
    servers.push_back(db_server);
    uint32_t db_scope = 0, db_owner = 0, db_host = 0;
    Check(IpmiScope::Lookup(db_name, &db_scope, &db_owner, &db_host) && db_scope != 0 && db_owner == 101,
          "DbRecovery registration has a shared endpoint");

    // 512 rows: ShellCore registers its 58th server at RpControlServer with init far from done.
    for (int i = 49; i < 512; ++i) {
        const std::string name = "SceCapacity" + std::to_string(i);
        uint64_t create[3] {Address(&object), Address(name.c_str()), Address(server_config.data())};
        const int server = Call(0, 0, create, sizeof(create));
        Check(server > 0, "remaining shared server rows");
        servers.push_back(server);
    }
    const char overflow_name[] = "SceCapacityOverflow";
    uint64_t overflow[3] {Address(&object), Address(overflow_name), Address(server_config.data())};
    CheckServerRejected(overflow, sizeof(overflow), Libs::Posix::POSIX_EBUSY, overflow_name);
    CheckServerRejected(db_create, sizeof(db_create), Libs::Posix::POSIX_EEXIST);

    test_pid = 202;
    Check(Call(1, db_server, nullptr, 0) == KERNEL_ERROR_EBADF,
          "foreign process cannot destroy DbRecovery server");
    Check(IpmiScope::Lookup(db_name, &db_scope, &db_owner, &db_host) && db_owner == 101,
          "foreign destroy leaves DbRecovery registered");
    std::array<uint64_t, 42> client_config {};
    client_config[0] = sizeof(client_config);
    client_config[1] = 1;
    client_config[2] = client_config[3] = 0x100;
    uint64_t client_create[3] {Address(&object), Address(db_name), Address(client_config.data())};
    const int client = Call(2, 0, client_create, sizeof(client_create));
    Check(client > 0, "DbRecovery client allocation");
    int callback_status = 0x12345678;
    uint32_t timeout = 1000000;
    uint64_t connect[4] {0, 0, Address(&callback_status), Address(&timeout)};
    auto pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x400, client, connect, sizeof(connect));
    });
    test_pid = 101;
    ServerBuffers buffers;
    buffers.Await(db_server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 1 && buffers.info[1] >> 32 != 0 && buffers.info[2] == handler,
          "DbRecovery receives the connect callback and registered handler");
    int callback = -17;
    Check(Call(0x212, buffers.info[1] >> 32, &callback, sizeof(callback)) == OK && pending.get() == OK &&
          callback_status == callback, "DbRecovery callback result reaches its client");
    test_pid = 202;
    Check(Call(3, client, nullptr, 0) == OK, "DbRecovery client cleanup");
    test_pid = 101;

    for (auto it = servers.rbegin(); it != servers.rend(); ++it) {
        Check(Call(1, *it, nullptr, 0) == OK, "shared server cleanup");
    }
    Check(!IpmiScope::Lookup(db_name, &db_scope, &db_owner, &db_host),
          "owned DbRecovery destroy removes the shared endpoint");
    const int replacement = Call(0, 0, db_create, sizeof(db_create));
    Check(replacement > 0 && Call(1, replacement, nullptr, 0) == OK,
          "freed shared row can host a replacement DbRecovery server");
    test_partial_auth = false;
    test_authorization = {};
}

void CheckDuplicateRegistrationRace() {
    using namespace Libs::LibKernel;
    struct Result { int pid; int status; int32_t value; int error; };
    std::array<uint64_t, 7> config {};
    for (int attempt = 0; attempt < 12; ++attempt) {
        const std::string name = "SceRegisterRace" + std::to_string(attempt);
        uint64_t create[3] {1, Address(name.c_str()), Address(config.data())};
        std::promise<void> ready;
        auto start = ready.get_future().share();
        auto register_server = [&](int pid) {
            test_pid = pid;
            test_partial_auth = true;
            test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
            start.wait();
            Result result {pid, -9, 0x12345678, 0};
            Check(IpmiManager::TryCall(0, 0, &result.value, create, sizeof(create), 0, &result.status),
                  "concurrent registration handled");
            result.error = *Libs::Posix::GetErrorAddr();
            return result;
        };
        auto first = std::async(std::launch::async, register_server, 401);
        auto second = std::async(std::launch::async, register_server, 402);
        ready.set_value();
        auto winner = first.get();
        auto loser = second.get();
        if (winner.status != OK) std::swap(winner, loser);
        Check(winner.status == OK && winner.value > 0 && loser.status == -1 &&
              loser.error == Libs::Posix::POSIX_EEXIST && loser.value == 0x12345678,
              "concurrent duplicate has one server and one EEXIST with untouched output");
        uint32_t id = 0, owner = 0, host = 0;
        Check(IpmiScope::Lookup(name, &id, &owner, &host) && owner == static_cast<uint32_t>(winner.pid),
              "registration race retains the winning owner");
        test_pid = winner.pid;
        Check(Call(1, winner.value, nullptr, 0) == OK, "registration race server cleanup");
        Check(!IpmiScope::Lookup(name, &id, &owner, &host), "registration race leaves no service behind");
    }
    test_pid = 101;
}

void CheckClientConfig() {
    using namespace Libs::LibKernel;
    std::array<uint8_t, 336> config {};
    auto store = [&](size_t offset, uint64_t value, bool dword = false) {
        std::memcpy(config.data() + offset, &value, dword ? 4 : 8);
    };
    store(0, config.size());
    for (int i = 0; i < 32; ++i) store(0x40 + i * 8, 1);
    uint64_t create[3] {1, Address("SceClientConfig"), Address(config.data())};
    auto rejected = [&] {
        int32_t result = 0x12345678;
        int status = 0;
        Check(IpmiManager::TryCall(2, 0, &result, create, sizeof(create), 0, &status) &&
              status == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL && result == 0x12345678,
              "invalid client config returns EINVAL with untouched output");
    };
    auto accepted = [&] {
        const int client = Call(2, 0, create, sizeof(create));
        Check(client > 0 && Call(3, client, nullptr, 0) == OK, "bounded client config creates an owned object");
    };
    struct Field { size_t offset; uint64_t limit; bool dword; };
    const Field fields[] {{0, 336, false}, {8, 16, true}, {0x10, 0x100000, false}, {0x18, 0xfc00, false},
        {0x20, 16, true}, {0x28, 0x100000, false}, {0x30, 0x100000, false}, {0x38, 32, true},
        {0x140, 16, true}, {0x144, 1, true}};
    for (const auto& field: fields) {
        store(field.offset, field.limit, field.dword);
        accepted();
        store(field.offset, field.limit + 1, field.dword);
        rejected();
        store(field.offset, field.offset ? 0 : config.size(), field.dword);
    }
    store(0, 0);
    accepted();
    store(0, config.size());
    store(0x38, 1, true);
    store(0x40, 0);
    rejected();
    store(0x40, 0x80001);
    rejected();
    store(0x40, 0x80000);
    accepted();
    store(0x38, 0, true);
    for (const auto& name: {"SceSaveData", "SceNpEntAccess", "SceSaveDataSuffix"}) {
        const uint64_t limit = std::strcmp(name, "SceSaveData") == 0 ? 0x100000 :
            std::strcmp(name, "SceNpEntAccess") == 0 ? 0x18000 : 0xfc00;
        create[1] = Address(name);
        store(0x18, limit);
        accepted();
        store(0x18, limit + 1);
        rejected();
    }
    store(0x18, 0);
    create[2] = 0;
    rejected();
    create[2] = Address(config.data());

    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
    std::array<uint64_t, 7> server_config {};
    create[1] = Address("SceClientConfig");
    create[2] = Address(server_config.data());
    const int server = Call(0, 0, create, sizeof(create));
    create[2] = Address(config.data());
    test_pid = 501;
    const int client = Call(2, 0, create, sizeof(create));
    int completion = 0x12345678;
    uint32_t timeout = 1000000;
    uint64_t connect[4] {0, 0, Address(&completion), Address(&timeout)};
    auto connecting = std::async(std::launch::async, [&] { test_pid = 501; return Call(0x400, client, connect, sizeof(connect)); });
    test_pid = 101;
    ServerBuffers buffers;
    buffers.Await(server);
    uint32_t count = 0;
    std::memcpy(&count, buffers.bytes.data() + 8, sizeof(count));
    Check(count == 1 && config[8] == 0, "native default count reaches connect packet without modifying guest config");
    int callback = -7;
    Check(Call(0x212, buffers.info[1] >> 32, &callback, sizeof(callback)) == OK &&
          connecting.get() == OK && completion == -7, "client config fixture receives only its callback");
    test_pid = 501;
    Check(Call(3, client, nullptr, 0) == OK, "client config fixture client cleanup");
    test_pid = 101;
    Check(Call(1, server, nullptr, 0) == OK, "client config fixture server cleanup");
    test_partial_auth = false;
    test_authorization = {};
}

void CheckTraceReporting() {
    using namespace Libs::LibKernel;
    std::array<uint8_t, 64> record {};
    auto Store = [&](size_t offset, auto value) { std::memcpy(record.data() + offset, &value, sizeof(value)); };
    Store(0, int32_t {-1});
    std::memcpy(record.data() + 8, "SceMbusIpc", 11);
    Store(0x24, static_cast<uint32_t>(KERNEL_ERROR_ENOSYS));
    const auto original = record;
    test_capture_log = true;
    test_log.clear();
    Check(Call(0x10, 0x1f02, record.data(), record.size()) == OK && record == original,
          "failed server creation diagnostic copies its error without changing input");
    Check(test_log.size() == 1 && test_log.back().find("pid=101 host_tid=") != std::string::npos &&
          test_log.back().find("suboperation=00001f02 known=1 kid=ffff code=8002004e") != std::string::npos &&
          test_log.back().find("name_hex=5363654d62757349706300") != std::string::npos,
          "diagnostic sink records process/thread context, bounded embedded service name and original failure");
    uint32_t server = 0, owner = 0, host = 0;
    Check(!IpmiScope::Lookup("SceMbusIpc", &server, &owner, &host), "trace does not register the reported server");
    uint64_t create[3] {1, Address("SceMbusIpc"), 1};
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, "SceMbusIpc");
    for (const uint32_t type: {0x1f00u, 0x1f01u, 0x1f03u, 0x1f04u, 0x1f05u}) {
        record.fill(0);
        Store(0, int32_t {-1});
        Store(8, uint64_t {0x12345678abcdef01});
        Store(0x10, uint64_t {0x01234567fedcba98});
        Store(0x18, uint32_t {0xa1b2c3d4});
        const auto before = record;
        Check(Call(0x10, type, record.data(), record.size()) == OK && record == before,
              "known trace subtype processes fixed copied fields without modifying them");
        const auto& line = test_log.back();
        Check(line.find(type == 0x1f00 ? "code=fedcba98 code2=00000000 payload=12345678abcdef01" :
                        type == 0x1f04 ? "code=abcdef01 code2=a1b2c3d4 payload=01234567fedcba98" :
                                         "code=abcdef01 code2=00000000 payload=0000000000000000") != std::string::npos,
              "trace field offsets match recovered native subtype layout");
    }
    for (const int32_t type: {0x1f06, -1}) {
        Check(Call(0x10, type, record.data(), record.size()) == OK &&
              test_log.back().find("known=0 kid=ffff code=00000000 code2=00000000 payload=ffffffffffffffff") != std::string::npos,
              "unknown trace subtype records defaults and completes only the reporting operation");
    }
    auto CheckTransport = [&](void* args, size_t size, int error) {
        int32_t result = 0x5a123456;
        int status = 0;
        const auto count = test_log.size();
        Check(IpmiManager::TryCall(0x10, 0x1f02, &result, args, size, 0, &status) && status == -1 &&
              *Libs::Posix::GetErrorAddr() == error && result == 0x5a123456 && test_log.size() == count,
              "invalid trace shape/copyin returns transport failure with untouched logical result");
    };
    for (const size_t size: {size_t {0}, size_t {1}, size_t {48}, size_t {63}})
        CheckTransport(record.data(), size, Libs::Posix::POSIX_EINVAL);
    CheckTransport(nullptr, 64, Libs::Posix::POSIX_EINVAL);
    CheckTransport(reinterpret_cast<void*>(1), 64, Libs::Posix::POSIX_EFAULT);
    const auto count = test_log.size();
    Check(Call(0x10, 0x1f02, nullptr, 65) == static_cast<int32_t>(0x800e0001u) &&
          Call(0x10, 0x1f02, nullptr, SIZE_MAX) == static_cast<int32_t>(0x800e0001u) && test_log.size() == count,
          "outer request limit returns captured logical error before record access");
    auto* pages = static_cast<uint8_t*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Check(pages != nullptr, "trace copyout fixture allocation");
    DWORD previous = 0;
    Check(VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous), "trace unreadable boundary fixture");
    CheckTransport(pages + 4096 - 32, 64, Libs::Posix::POSIX_EFAULT);
    *reinterpret_cast<int32_t*>(pages) = 0x12345678;
    Check(VirtualProtect(pages, 4096, PAGE_READONLY, &previous), "trace read-only output fixture");
    int status = 0;
    Check(IpmiManager::TryCall(0x10, 0x1f02, reinterpret_cast<int32_t*>(pages), record.data(), 64, 0, &status) &&
          status == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
          *reinterpret_cast<int32_t*>(pages) == 0x12345678 && test_log.size() == count + 1,
          "trace processing precedes failed result copyout without overwriting protected output");
    Check(VirtualFree(pages, 0, MEM_RELEASE), "trace fixture cleanup");
    test_capture_log = false;
    test_log.clear();
}

// Every 0x202 here is posted by the fixture.
void CheckServerPost() {
    using namespace Libs::LibKernel;
    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
    std::array<uint64_t, 7> server_config {};
    server_config[6] = 0x00000008c0ffee00ull;
    uint64_t create[3] {1, Address("SceServerPostFixture"), Address(server_config.data())};
    int server = Call(0, 0, create, sizeof(create));
    Check(server > 0, "server post fixture server");
    uint64_t stop[4] {1, 0, 0, 0};
    auto Rejected = [&](int handle, void* args, size_t size, int error) {
        int32_t result = 0x5a123456;
        int status = 0;
        *Libs::Posix::GetErrorAddr() = 0;
        Check(IpmiManager::TryCall(0x202, handle, &result, args, size, 0, &status) && status == -1 &&
              *Libs::Posix::GetErrorAddr() == error && result == 0x5a123456,
              "rejected server post returns errno with the logical result untouched");
    };
    ServerBuffers buffers;
    auto Event = [&](const char* text) {
        buffers.bytes.fill(0xcc);
        buffers.info = {7, 7, 7};
        Check(buffers.Receive(server) == OK && buffers.info[0] == 0 && buffers.info[1] == 0xffffffff000000b0ull &&
              buffers.info[2] == server_config[6] &&
              std::all_of(buffers.bytes.begin(), buffers.bytes.end(), [](uint8_t b) { return b == 0xcc; }), text);
    };
    Check(Call(0x202, server, stop, 24) == OK, "post to the caller's own server");
    Event("type 1 message arrives as kind b0 from client -1 with the handler and an untouched buffer");
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "one receive consumes the message");
    stop[0] = 0xdeadbeef00000001ull;
    stop[3] = 0x1234;
    Check(Call(0x202, server, stop, sizeof(stop)) == OK, "only the low dword type and the two qwords after it are checked");
    Event("message from a longer argument block");
    stop[0] = 1;
    stop[3] = 0;

    for (const uint64_t type: {0ull, 2ull, 0xffffffffull, 0x100000000ull}) {
        stop[0] = type;
        Rejected(server, stop, 24, Libs::Posix::POSIX_EINVAL);
    }
    stop[0] = 1;
    stop[1] = 1;
    Rejected(server, stop, 24, Libs::Posix::POSIX_EINVAL);
    stop[1] = 0;
    stop[2] = 1;
    Rejected(server, stop, 24, Libs::Posix::POSIX_EINVAL);
    stop[1] = 1;
    Check(Call(0x202, server, stop, 4) == OK, "short argument block reads as zero past the copied bytes");
    Event("message from a four byte argument block");
    stop[1] = stop[2] = 0;
    Rejected(server, nullptr, 0, Libs::Posix::POSIX_EINVAL);
    Rejected(server, reinterpret_cast<void*>(1), 24, Libs::Posix::POSIX_EFAULT);
    std::array<uint64_t, 9> wide {1};
    Check(Call(0x202, server, wide.data(), 64) == OK, "dispatcher copies in up to 0x40 bytes");
    Event("message from a 0x40 byte argument block");
    int32_t oversized = 0x5a123456;
    int status = 0;
    Check(IpmiManager::TryCall(0x202, server, &oversized, wide.data(), 65, 0, &status) && status == OK &&
          static_cast<uint32_t>(oversized) == 0x800e0001u, "oversized argument block gets the dispatcher result");
    test_pid = 202;
    Rejected(server, stop, 24, Libs::Posix::POSIX_ENOENT);
    stop[1] = 1;
    Rejected(server, stop, 24, Libs::Posix::POSIX_EINVAL);
    stop[1] = 0;
    test_pid = 101;
    Rejected(0x1000ffff, stop, 24, Libs::Posix::POSIX_ENOENT);
    int32_t unmanaged = 0x5a123456;
    Check(!IpmiManager::TryCall(0x202, 5, &unmanaged, stop, 24, 0, &status) && unmanaged == 0x5a123456,
          "handle outside the kernel object classes is not claimed");
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "rejected posts queue nothing");

    std::array<uint64_t, 42> client_params {};
    client_params[0] = 336;
    client_params[1] = 1;
    client_params[2] = client_params[3] = 0x100;
    create[2] = Address(client_params.data());
    test_pid = 501;
    const int client = Call(2, 0, create, sizeof(create));
    Check(client > 0, "server post fixture client");
    Rejected(client, stop, 24, Libs::Posix::POSIX_ENOENT);
    test_pid = 101;
    Rejected(client, stop, 24, Libs::Posix::POSIX_ENOENT);

    buffers.timeout = 1000;
    Check(buffers.Receive(server) == KERNEL_ERROR_ETIMEDOUT, "finite receive still times out with nothing posted");
    buffers.timeout = 2000000;
    auto blocked = std::async(std::launch::async, [&] { test_pid = 101; return buffers.Receive(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Check(blocked.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout, "receive waits with nothing posted");
    Check(Call(0x202, server, stop, 24) == OK && blocked.get() == OK && buffers.info[1] == 0xffffffff000000b0ull,
          "post wakes a blocked receive");
    buffers.timeout = 0;

    int completion = 0x12345678;
    uint32_t connect_timeout = 1000000;
    uint64_t connect[4] {0, 0, Address(&completion), Address(&connect_timeout)};
    Check(Call(0x202, server, stop, 24) == OK, "post ahead of a connect");
    auto connecting = std::async(std::launch::async, [&] { test_pid = 501; return Call(0x400, client, connect, sizeof(connect)); });
    Event("message posted before the connect is received first");
    const auto bound = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int polled = KERNEL_ERROR_EAGAIN;
    while (polled == KERNEL_ERROR_EAGAIN && std::chrono::steady_clock::now() < bound) polled = buffers.Receive(server, 8);
    Check(polled == KERNEL_ERROR_EMSGSIZE, "connect is queued and stays at the head");
    Check(Call(0x202, server, stop, 24) == OK, "post into the slot the first message freed");
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 1, "older connect is received before a newer message in a lower slot");
    uint64_t object = 1;
    uint64_t session_params[2] {16, 0};
    uint64_t create_session[2] {Address(&object), Address(session_params)};
    const int session = Call(4, -1, create_session, 16);
    Check(session > 0, "server post fixture session");
    Rejected(session, stop, 24, Libs::Posix::POSIX_ENOENT);
    int callback = -7;
    Check(Call(0x212, buffers.info[1] >> 32, &callback, sizeof(callback)) == OK && connecting.get() == OK && completion == -7,
          "connect gets only its callback");
    Event("message posted after the connect follows it");
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "server post queue drained");

    int posted = 0;
    for (;;) {
        int32_t result = 0x5a123456;
        status = 0;
        Check(IpmiManager::TryCall(0x202, server, &result, stop, 24, 0, &status), "bounded post handled");
        if (status != OK) {
            Check(*Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOMEM && result == 0x5a123456,
                  "full shared pool reports ENOMEM with the result untouched");
            break;
        }
        Check(result == OK && ++posted <= 32, "posts fill the shared slots");
    }
    // concurrency check below needs 24 free slots
    Check(posted >= 24 && Call(1, server, nullptr, 0) == OK, "destroy server with messages queued");
    Rejected(server, stop, 24, Libs::Posix::POSIX_ENOENT);
    create[2] = Address(server_config.data());
    server = Call(0, 0, create, sizeof(create));
    Check(server > 0 && buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "replacement server starts with an empty queue");
    for (int i = 0; i < posted; ++i) Check(Call(0x202, server, stop, 24) == OK, "slots held by the destroyed server are free again");
    for (int i = 0; i < posted; ++i) Event("refilled queue drains");
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "refilled queue drained");

    std::vector<std::future<void>> posters;
    for (int t = 0; t < 4; ++t) {
        posters.push_back(std::async(std::launch::async, [&] {
            test_pid = 101;
            for (int i = 0; i < 6; ++i) Check(Call(0x202, server, stop, 24) == OK, "concurrent post");
        }));
    }
    int received = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (received < 24) {
        const int result = buffers.Receive(server);
        if (result == OK) {
            Check(buffers.info[1] == 0xffffffff000000b0ull, "concurrent message kind");
            ++received;
            continue;
        }
        Check(result == KERNEL_ERROR_EAGAIN && std::chrono::steady_clock::now() < deadline, "concurrent posts arrive within fixture deadline");
        std::this_thread::yield();
    }
    for (auto& poster: posters) poster.get();
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "each concurrent post is delivered once");

    Check(Call(0x202, server, stop, 24) == OK, "post before transport loss");
    _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", "");
    Rejected(server, stop, 24, Libs::Posix::POSIX_ENOSYS);
    const std::string scope = "test_" + std::to_string(GetCurrentProcessId());
    _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", scope.c_str());
    Event("unavailable transport neither drops nor adds a message");
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "transport loss queued nothing");

    test_pid = 501;
    Check(Call(3, client, nullptr, 0) == OK, "server post fixture client cleanup");
    test_pid = 101;
    Check(Call(1, server, nullptr, 0) == OK, "server post fixture server cleanup");
    Rejected(session, stop, 24, Libs::Posix::POSIX_ENOENT);
    test_partial_auth = false;
    test_authorization = {};
}

// 0x468 returns the cmd 4 user data; SysAv and SysCore find their connection record with it
void CheckSessionUserData() {
    using namespace Libs::LibKernel;
    test_partial_auth = true;
    test_authorization = {true, 0x4800000000000007ull, 1ull << 62, 1ull << 62};
    std::array<uint64_t, 7> server_config {};
    server_config[6] = 0x00000008c0ffee10ull;
    uint64_t create[3] {1, Address("SceSysAvControlIpc"), Address(server_config.data())};
    const int server = Call(0, 0, create, sizeof(create));
    Check(server > 0, "user data fixture server");
    std::array<uint64_t, 42> client_params {};
    client_params[0] = 336;
    client_params[1] = 1;
    client_params[2] = client_params[3] = 0x100;
    client_params[40] = 2;
    create[2] = Address(client_params.data());
    int clients[3] {};
    for (int i = 0; i < 3; ++i) {
        test_pid = 202 + i;
        clients[i] = Call(2, 0, create, sizeof(create));
        Check(clients[i] > 0, "user data fixture client");
    }
    test_pid = 101;

    const uint64_t untouched = 0xa5a5a5a5a5a5a5a5ull;
    uint64_t out = untouched;
    uint64_t args[1] {Address(&out)};
    auto Rejected = [&](int handle, void* data, size_t size, int error) {
        int32_t result = 0x5a123456;
        int status = 0;
        *Libs::Posix::GetErrorAddr() = 0;
        Check(IpmiManager::TryCall(0x468, handle, &result, data, size, 0x1234, &status) && status == -1 &&
              *Libs::Posix::GetErrorAddr() == error && result == 0x5a123456 && out == untouched,
              "rejected user data read returns errno with the result and output untouched");
    };
    Rejected(server, args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(-1, args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(0x30000fff, args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(0, args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(5, args, 8, Libs::Posix::POSIX_ENOENT);
    test_pid = 202;
    Rejected(clients[0], args, 8, Libs::Posix::POSIX_ENOENT);
    test_pid = 101;

    ServerBuffers buffers;
    uint64_t object = 1;
    int completion = -1;
    uint32_t timeout = 1000000;
    uint64_t connect[4] {0, 0, Address(&completion), Address(&timeout)};
    const uint64_t user_data[3] {0x0000000900aa0202ull, 0x0000000900aa0203ull, 0x0000000900aa0204ull};
    int sessions[3] {};
    uint32_t scopes[3] {};
    for (int i = 0; i < 3; ++i) {
        auto pending = std::async(std::launch::async, [&, i] { test_pid = 202 + i; return Call(0x400, clients[i], connect, sizeof(connect)); });
        buffers.Await(server);
        scopes[i] = buffers.info[1] >> 32;
        uint64_t params[2] {16, user_data[i]};
        uint64_t session_args[2] {Address(&object), Address(params)};
        sessions[i] = Call(4, -1, session_args, 16);
        int callback = 0;
        Check(sessions[i] > 0 && Call(0x212, scopes[i], &callback, 4) == OK && pending.get() == OK, "user data fixture session");
    }
    std::array<uint8_t, 24> lifecycle_args {};
    test_log.clear();
    test_capture_log = true;
    _putenv_s("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE", "");
    Check(Call(0x254, sessions[0], lifecycle_args.data(), lifecycle_args.size()) == KERNEL_ERROR_ENOSYS,
          "unimplemented lifecycle command remains ENOSYS without diagnostics");
    Check(std::none_of(test_log.begin(), test_log.end(), [](const auto& line) {
              return line.find("APP_KILL_LIFECYCLE_IPMI") != std::string::npos;
          }),
          "disabled lifecycle diagnostics emit no marker");
    test_log.clear();
    _putenv_s("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE", "1");
    const int lifecycle_result = Call(0x254, sessions[0], lifecycle_args.data(), lifecycle_args.size());
    const int lifecycle_invalid = Call(0x254, 0x30000fff, lifecycle_args.data(), lifecycle_args.size());
    test_pid = 202;
    const int lifecycle_foreign = Call(0x254, sessions[0], lifecycle_args.data(), lifecycle_args.size());
    test_pid = 101;
    _putenv_s("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE", "");
    test_capture_log = false;
    Check(lifecycle_result == KERNEL_ERROR_ENOSYS && lifecycle_invalid == KERNEL_ERROR_EBADF &&
              lifecycle_foreign == KERNEL_ERROR_EBADF,
          "lifecycle diagnostics preserve owned, invalid and foreign results");
    uint32_t lifecycle_server = 0, lifecycle_owner = 0, lifecycle_host = 0;
    Check(IpmiScope::Lookup("SceSysAvControlIpc", &lifecycle_server, &lifecycle_owner, &lifecycle_host),
          "resolve lifecycle fixture server identity");
    const auto owned_line = std::find_if(test_log.begin(), test_log.end(), [&](const auto& line) {
        return line.find("APP_KILL_LIFECYCLE_IPMI") != std::string::npos &&
               line.find(" pid=101 ") != std::string::npos &&
               line.find(" handle=" + std::to_string(sessions[0]) + " ") != std::string::npos &&
               line.find(" bytes=24 ") != std::string::npos &&
               line.find(" owned_server=0 owned_client=0 owned_session=1 session_found=1 ") != std::string::npos &&
               line.find(" server=" + std::to_string(lifecycle_server) + " ") != std::string::npos &&
               line.find(" client=" + std::to_string(scopes[0]) + " request=0 peer_known=1 peer_pid=202 ") != std::string::npos &&
               line.find(" result=0x8002004e outcome=UNCHANGED") != std::string::npos;
    });
    const auto invalid_line = std::find_if(test_log.begin(), test_log.end(), [](const auto& line) {
        return line.find("APP_KILL_LIFECYCLE_IPMI") != std::string::npos &&
               line.find(" handle=805310463 ") != std::string::npos &&
               line.find(" owned_server=0 owned_client=0 owned_session=0 session_found=0 ") != std::string::npos &&
               line.find(" result=0x80020009 outcome=UNCHANGED") != std::string::npos;
    });
    const auto foreign_line = std::find_if(test_log.begin(), test_log.end(), [&](const auto& line) {
        return line.find("APP_KILL_LIFECYCLE_IPMI") != std::string::npos &&
               line.find(" pid=202 ") != std::string::npos &&
               line.find(" handle=" + std::to_string(sessions[0]) + " ") != std::string::npos &&
               line.find(" owned_session=0 session_found=1 ") != std::string::npos &&
               line.find(" peer_known=1 peer_pid=202 ") != std::string::npos &&
               line.find(" result=0x80020009 outcome=UNCHANGED") != std::string::npos;
    });
    Check(owned_line != test_log.end() && invalid_line != test_log.end() && foreign_line != test_log.end(),
          "lifecycle diagnostics classify exact ownership and preserve each result");
    struct EventArgs {
        uint32_t index;
        uint32_t padding0;
        uint64_t desired;
        uint32_t mode;
        uint32_t padding1;
        uint64_t output;
        uint64_t timeout;
    } event {};
    struct SetEventArgs { uint32_t index; uint32_t padding; uint64_t bits; } set_event {};
    static_assert(sizeof(EventArgs) == 40 && sizeof(SetEventArgs) == 16);
    uint64_t pattern = 0xa5a5a5a5a5a5a5a5ull;
    event.desired = 2;
    event.mode = 2;
    event.output = Address(&pattern);
    test_pid = 202;
    Check(Call(0x491, clients[0], &event, 32) == KERNEL_ERROR_EBUSY && pattern == 0,
          "empty client event flag polls busy and returns the current pattern");
    test_pid = 101;
    set_event.bits = 3;
    Check(Call(0x493, sessions[0], &set_event, sizeof(set_event)) == OK, "session sets its peer event flag");
    test_pid = 202;
    event.mode = 0x22;
    pattern = 0;
    Check(Call(0x491, clients[0], &event, 32) == OK && pattern == 3,
          "OR poll returns the pre-clear pattern and clears requested bits");
    event.desired = 1;
    event.mode = 0x11;
    pattern = 0;
    Check(Call(0x491, clients[0], &event, 32) == OK && pattern == 1,
          "AND poll returns the pre-clear pattern and clear-all consumes it");
    pattern = 9;
    Check(Call(0x491, clients[0], &event, 32) == KERNEL_ERROR_EBUSY && pattern == 0,
          "consumed client event bits do not reappear");

    test_pid = 101;
    set_event.index = 1;
    set_event.bits = 0x40;
    Check(Call(0x493, sessions[0], &set_event, sizeof(set_event)) == OK,
          "session sets an independent admitted event index");
    test_pid = 202;
    event.index = 1;
    event.desired = 0x40;
    event.mode = 0x12;
    pattern = 0;
    Check(Call(0x491, clients[0], &event, 32) == OK && pattern == 0x40,
          "independent event index retains and clears its own pattern");
    event.index = 0;
    event.desired = 1;
    pattern = 9;
    Check(Call(0x491, clients[0], &event, 32) == KERNEL_ERROR_EBUSY && pattern == 0,
          "second event index does not alter the first index");

    uint32_t event_timeout = 250000;
    EventArgs blocking {0, 0, 6, 0x21, 0, Address(&pattern), Address(&event_timeout)};
    pattern = 0;
    auto waiter = std::async(std::launch::async, [&] { test_pid = 203; return Call(0x490, clients[1], &blocking, sizeof(blocking)); });
    Check(waiter.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout,
          "waitEventFlag blocks without the requested pattern");
    test_pid = 101;
    set_event.index = 0;
    set_event.bits = 2;
    Check(Call(0x493, sessions[1], &set_event, sizeof(set_event)) == OK &&
          waiter.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout,
          "AND wait remains blocked after a partial session set");
    set_event.bits = 4;
    Check(Call(0x493, sessions[1], &set_event, sizeof(set_event)) == OK && waiter.get() == OK &&
          pattern == 6 && event_timeout < 250000 && event_timeout > 0,
          "session set wakes the matching client wait with pattern and remaining timeout");

    test_pid = 204;
    uint32_t expired = 1000;
    EventArgs timed {0, 0, 8, 2, 0, Address(&pattern), Address(&expired)};
    pattern = 9;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EAGAIN && pattern == 0 && expired == 0,
          "finite wait returns the raw kernel timeout and zero remaining time");
    expired = 0;
    pattern = 9;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EAGAIN && pattern == 0 && expired == 0,
          "zero-microsecond wait performs one predicate test then times out");
    timed.mode = 0;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EINVAL, "zero wait condition is rejected");
    timed.mode = 3;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EINVAL, "conflicting wait condition is rejected");
    timed.mode = 0x31;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EINVAL, "conflicting clear modes are rejected");
    timed.mode = 2;
    timed.index = 2;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EINVAL, "event index is bounded by the client config");
    timed.index = 0;
    timed.timeout = 1;
    Check(Call(0x490, clients[2], &timed, sizeof(timed)) == KERNEL_ERROR_EFAULT, "invalid timeout pointer fails before waiting");
    timed.timeout = Address(&expired);
    Check(Call(0x490, clients[2], &timed, sizeof(timed) - 1) == KERNEL_ERROR_EINVAL, "wait ABI length is exact");

    test_pid = 101;
    set_event.index = 2;
    Check(Call(0x493, sessions[2], &set_event, sizeof(set_event)) == KERNEL_ERROR_EINVAL, "session set index is bounded");
    set_event.index = 0;
    set_event.bits = 1;
    Check(Call(0x493, sessions[2], &set_event, sizeof(set_event)) == OK, "session sets event before bad copyout");
    test_pid = 204;
    EventArgs bad_output {0, 0, 1, 0x12, 0, 1, 0};
    Check(Call(0x491, clients[2], &bad_output, 32) == KERNEL_ERROR_EFAULT,
          "poll reports bad output after applying the clear semantics");
    bad_output.output = Address(&pattern);
    pattern = 9;
    Check(Call(0x491, clients[2], &bad_output, 32) == KERNEL_ERROR_EBUSY && pattern == 0,
          "bad output does not roll back consumed event state");
    test_pid = 202;
    Check(Call(0x493, sessions[2], &set_event, sizeof(set_event)) == KERNEL_ERROR_EBADF,
          "foreign process cannot set a session event");
    test_pid = 999;
    Check(Call(0x491, clients[0], &event, 32) == KERNEL_ERROR_EBADF,
          "foreign process cannot poll another client's event state");
    test_pid = 101;
    for (int i = 0; i < 3; ++i) {
        out = 0;
        Check(Call(0x468, sessions[i], args, 8) == OK && out == user_data[i], "each session returns its own cmd 4 user data");
    }
    out = untouched;
    test_pid = 202;
    Rejected(sessions[0], args, 8, Libs::Posix::POSIX_ENOENT);
    test_pid = 101;
    Rejected(sessions[0], nullptr, 0, Libs::Posix::POSIX_EFAULT);
    uint64_t bad[1] {1};
    Rejected(sessions[0], bad, 8, Libs::Posix::POSIX_EFAULT);
    Rejected(sessions[0], reinterpret_cast<void*>(1), 8, Libs::Posix::POSIX_EFAULT);
    auto* readonly = static_cast<uint64_t*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD previous = 0;
    Check(readonly && VirtualProtect(readonly, 4096, PAGE_READONLY, &previous), "read-only user data fixture");
    bad[0] = Address(readonly);
    Rejected(sessions[0], bad, 8, Libs::Posix::POSIX_EFAULT);
    Check(*readonly == 0 && VirtualFree(readonly, 0, MEM_RELEASE), "read-only output untouched");
    auto* sealed = static_cast<int32_t*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Check(sealed && VirtualProtect(sealed, 4096, PAGE_READONLY, &previous), "read-only result fixture");
    int sealed_status = 0;
    *Libs::Posix::GetErrorAddr() = 0;
    Check(IpmiManager::TryCall(0x468, 0x30000fff, sealed, args, 8, 0x1234, &sealed_status) && sealed_status == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT && out == untouched, "lookup fails before the result is written");
    *Libs::Posix::GetErrorAddr() = 0;
    Check(IpmiManager::TryCall(0x468, sessions[0], sealed, args, 8, 0x1234, &sealed_status) && sealed_status == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT && out == user_data[0], "user data is copied out before the result write fails");
    Check(*sealed == 0 && VirtualFree(sealed, 0, MEM_RELEASE), "read-only result untouched");
    out = untouched;
    std::array<uint64_t, 9> oversized {Address(&out)};
    Check(Call(0x468, sessions[0], oversized.data(), 72) == static_cast<int>(0x800e0001u) && out == untouched,
          "dispatcher rejects more than 0x40 argument bytes in the result");
    oversized[1] = untouched;
    Check(Call(0x468, sessions[0], oversized.data(), 64) == OK && out == user_data[0], "0x468 takes any argument size the dispatcher copies in");
    out = untouched;

    std::array<uint8_t, 48> invoke {};
    const uint32_t method = 2, flags = 1;
    int method_result = 0;
    const uint64_t result_address = Address(&method_result);
    std::memcpy(invoke.data(), &method, 4);
    std::memcpy(invoke.data() + 32, &result_address, 8);
    std::memcpy(invoke.data() + 40, &flags, 4);
    auto Request = [&](int i) {
        return std::async(std::launch::async, [&, i] { test_pid = 202 + i; return Call(0x320, clients[i], invoke.data(), invoke.size()); });
    };
    struct ReplyArgs { int32_t result; uint32_t count; uint64_t outputs; uint32_t flags; uint32_t padding; } reply {7, 0, 0, 1, 0};
    auto Serving = [](int pid) { return IpmiManager::ValidateCurrentRequestPeer(pid); };

    Check(!Serving(202) && !Serving(203) && !Serving(204), "no method request is being served");
    auto pending = Request(0);
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 0x41 && buffers.info[1] >> 32 == scopes[0], "method request from the first client");
    Check(Serving(202) && !Serving(203) && !Serving(204) && !Serving(101) && !Serving(0) && !Serving(-1),
          "only the sender of the request being served is answered");
    Check(!IpmiManager::ValidateCurrentAuthorizationPeer(202), "a method request does not reopen the connect window");
    Check(!std::async(std::launch::async, [] { test_pid = 101; return IpmiManager::ValidateCurrentRequestPeer(202); }).get(),
          "a thread that did not receive the request has no identity");
    test_pid = 202;
    Check(!Serving(202), "the identity belongs to the serving process");
    test_pid = 101;
    out = 0;
    Check(Call(0x468, sessions[0], args, 8) == OK && out == user_data[0], "user data read while the request is served");
    Check(Call(0x232, sessions[0], &reply, sizeof(reply)) == OK && pending.get() == OK && method_result == 7, "request replied");
    Check(!Serving(202), "reply ends the request identity");

    auto second = Request(1);
    buffers.Await(server);
    Check(Serving(203) && !Serving(202), "a later request is tied to its own sender");
    auto first = Request(0);
    auto worker = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        const bool mine = IpmiManager::ValidateCurrentRequestPeer(202) && !IpmiManager::ValidateCurrentRequestPeer(203);
        ReplyArgs answer {8, 0, 0, 1, 0};
        return mine && Call(0x232, sessions[0], &answer, sizeof(answer)) == OK && !IpmiManager::ValidateCurrentRequestPeer(202);
    });
    Check(worker.get() && first.get() == OK, "concurrent server threads hold separate request identities");
    Check(Serving(203) && !Serving(202), "another thread's reply leaves this request intact");

    EventArgs cancelled_wait_args {0, 0, 1, 2, 0, Address(&pattern), 0};
    auto cancelled_wait = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x490, clients[0], &cancelled_wait_args, sizeof(cancelled_wait_args)); });
    Check(cancelled_wait.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout,
          "infinite client event wait blocks before disconnect");
    auto disconnect = std::async(std::launch::async, [&] { test_pid = 202; uint64_t done[1] {Address(&completion)}; return Call(0x310, clients[0], done, 8); });
    auto closer = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        int callback = 0;
        uint64_t value = untouched;
        uint64_t read[1] {Address(&value)};
        int32_t result = 0x5a123456;
        int status = 0;
        const bool disconnected = static_cast<uint32_t>(own.info[1]) == 3 && Call(0x468, sessions[0], read, 8) == OK && value == user_data[0];
        value = untouched;
        const bool destroyed = disconnected && Call(5, sessions[0], nullptr, 0) == OK &&
            Call(0x493, sessions[0], &set_event, sizeof(set_event)) == KERNEL_ERROR_EBADF &&
            IpmiManager::TryCall(0x468, sessions[0], &result, read, 8, 0x1234, &status) && status == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT && value == untouched && result == 0x5a123456;
        return destroyed && Call(0x222, scopes[0], &callback, 4) == OK;
    });
    Check(closer.get() && disconnect.get() == OK && cancelled_wait.get() == KERNEL_ERROR_ESRCH,
          "disconnect cancels the peer event wait while preserving session teardown semantics");
    Check(Serving(203), "another client's disconnect leaves this request intact");
    Check(Call(0x232, sessions[1], &reply, sizeof(reply)) == OK && second.get() == OK && !Serving(203),
          "second request replied before this dispatcher receives another packet");
    uint64_t stop_event[3] {1, 0, 0};
    Check(Call(0x202, server, stop_event, 24) == OK, "server event fixture");
    buffers.Await(server);
    Check(buffers.info[1] == 0xffffffff000000b0ull && !Serving(203) && !IpmiManager::ValidateCurrentRemotePeer(203),
          "a server event does not create a method request identity");

    second = Request(1);
    test_capture_log = true;
    test_log.clear();
    buffers.Await(server);
    test_capture_log = false;
    const auto line = std::find_if(test_log.begin(), test_log.end(), [](const auto& text) { return text.rfind("ORIGINAL_APP_IPMI_RECEIVE ", 0) == 0; });
    Check(line != test_log.end() && line->find(" client=" + std::to_string(scopes[1]) + " pid=203 ") != std::string::npos, "received request line");
    const auto received_request = static_cast<uint32_t>(std::strtoul(line->c_str() + line->find(" request=") + 9, nullptr, 10));
    Check(received_request != 0, "received request id");
    test_log.clear();
    Check(Serving(203), "request served before cancel");
    Check(IpmiScope::CancelRequest(scopes[1], received_request) && !Serving(203), "client cancel ends the request identity");
    Check(Call(0x232, sessions[1], &reply, sizeof(reply)) == KERNEL_ERROR_ECONNRESET && !Serving(203), "cancelled request cannot be answered");

    auto third_worker = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        uint32_t own_method = 0;
        std::memcpy(&own_method, own.bytes.data() + 12, 4);
        return own_method == method && IpmiManager::ValidateCurrentRequestPeer(204) &&
            !IpmiManager::ValidateCurrentRequestPeer(203);
    });
    auto third = Request(2);
    Check(third_worker.get(), "another dispatcher thread owns the third request");
    auto reconnect = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, clients[0], connect, sizeof(connect)); });
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 1 && !Serving(204),
          "this dispatcher receives a connect without taking another worker's method identity");
    const uint32_t reconnect_scope = buffers.info[1] >> 32;
    uint64_t reopen_params[2] {16, user_data[0]};
    uint64_t reopen_args[2] {Address(&object), Address(reopen_params)};
    sessions[0] = Call(4, -1, reopen_args, 16);
    uint32_t reconnect_peer = 0;
    uint64_t peer_args[1] {Address(&reconnect_peer)};
    Check(sessions[0] > 0 && Call(0x302, sessions[0], peer_args, 8) == OK && reconnect_peer == 202 &&
          IpmiManager::ValidateCurrentRemotePeer(202) && !IpmiManager::ValidateCurrentRemotePeer(204),
          "the remote check answers the pending connect peer only");
    FILETIME created {}, exited {}, kernel_time {}, user_time {};
    Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel_time, &user_time) != FALSE, "fixture host birth");
    const uint64_t birth = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    Process::PeerProcess peer;
    test_remote_pid = 202;
    test_remote_host_pid = GetCurrentProcessId();
    test_remote_host_birth = birth;
    Check(IpmiManager::FindCurrentRemotePeer(202, &peer), "the pending connect peer resolves to its own host record");
    test_remote_host_birth = birth + 1;
    Check(!IpmiManager::FindCurrentRemotePeer(202, &peer), "the connect peer refuses a pid record from another process");
    test_remote_pid = 0;
    Check(Call(0x202, server, stop_event, 24) == OK, "server event during the connect");
    buffers.Await(server);
    Check(buffers.info[1] == 0xffffffff000000b0ull && !IpmiManager::ValidateCurrentAuthorizationPeer(202) &&
          !IpmiManager::ValidateCurrentRemotePeer(202), "a later packet ends the connect identity");
    int reopened = 0;
    Check(Call(0x212, reconnect_scope, &reopened, 4) == OK && reconnect.get() == OK, "client reconnects");
    auto fourth = Request(0);
    buffers.Await(server);
    Check(Serving(202) && IpmiManager::ValidateCurrentRemotePeer(202) && !Serving(204) && !IpmiManager::ValidateCurrentRemotePeer(204),
          "request served before teardown");
    test_remote_pid = 202;
    test_remote_host_pid = GetCurrentProcessId();
    test_remote_host_birth = birth;
    Check(IpmiManager::FindCurrentRemotePeer(202, &peer) && peer.pid == 202, "served sender resolves to the pid record of its own host process");
    test_remote_host_pid = GetCurrentProcessId() + 4;
    Check(!IpmiManager::FindCurrentRemotePeer(202, &peer), "a pid record written by another host process is refused");
    test_remote_host_pid = GetCurrentProcessId();
    test_remote_host_birth = birth + 1;
    Check(!IpmiManager::FindCurrentRemotePeer(202, &peer), "a pid record from an earlier process with the same host pid is refused");
    test_remote_host_birth = birth;
    test_remote_pid = 204;
    Check(!IpmiManager::FindCurrentRemotePeer(204, &peer), "a live pid record for an unserved client is refused");
    test_remote_pid = 202;
    int teardown = -1;
    test_remote_lookup = [&] { teardown = Call(1, server, nullptr, 0); };
    Check(!IpmiManager::FindCurrentRemotePeer(202, &peer) && teardown == OK && !Serving(202) && !IpmiManager::ValidateCurrentRemotePeer(202),
          "server teardown between the transaction check and the pid record lookup ends the request identity");
    Check(Call(0x232, sessions[0], &reply, sizeof(reply)) == KERNEL_ERROR_EBADF && !Serving(202),
          "a stale worker reply after server teardown is rejected and drops its local context");
    test_remote_pid = 0;
    out = untouched;
    // Kyty policy: sessions go with their server. The kernel only has cmd 5 and the process sweep.
    Rejected(sessions[0], args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(sessions[2], args, 8, Libs::Posix::POSIX_ENOENT);
    Rejected(sessions[1], args, 8, Libs::Posix::POSIX_ENOENT);
    Check(fourth.get() == KERNEL_ERROR_ECONNRESET && third.get() == KERNEL_ERROR_ECONNRESET && second.get() == KERNEL_ERROR_ECONNRESET,
          "teardown releases waiting clients");

    create[1] = Address("SceTtsFixtureIpc");
    create[2] = Address(server_config.data());
    const int other = Call(0, 0, create, sizeof(create));
    create[2] = Address(client_params.data());
    test_pid = 205;
    const int client = Call(2, 0, create, sizeof(create));
    test_pid = 101;
    Check(other > 0 && client > 0, "non SysAv fixture");
    auto opening = std::async(std::launch::async, [&] { test_pid = 205; return Call(0x400, client, connect, sizeof(connect)); });
    buffers.Await(other);
    uint64_t params[2] {16, 5};
    uint64_t session_args[2] {Address(&object), Address(params)};
    const int session = Call(4, -1, session_args, 16);
    int callback = 0;
    Check(session > 0 && Call(0x212, buffers.info[1] >> 32, &callback, 4) == OK && opening.get() == OK, "non SysAv session");
    auto request = std::async(std::launch::async, [&] { test_pid = 205; return Call(0x320, client, invoke.data(), invoke.size()); });
    buffers.Await(other);
    out = 0;
    Check(!Serving(205) && Call(0x468, session, args, 8) == OK && out == 5,
          "user data works on any server but the remote identity is only for the SysAv server");
    Check(Call(0x232, session, &reply, sizeof(reply)) == OK && request.get() == OK && Call(1, other, nullptr, 0) == OK, "non SysAv cleanup");
    for (int i = 0; i < 3; ++i) {
        test_pid = 202 + i;
        Check(Call(3, clients[i], nullptr, 0) == OK, "user data fixture client cleanup");
    }
    test_pid = 205;
    Check(Call(3, client, nullptr, 0) == OK, "non SysAv client cleanup");
    test_pid = 101;
    test_partial_auth = false;
    test_authorization = {};
}

int RunCrossHostEventClient(int argc, char** argv) {
    if (argc != 4 || std::strcmp(argv[1], "--cross-host-event-client") != 0) return -1;
    using namespace Libs::LibKernel;
    char* end = nullptr;
    const auto raw_pipe = std::strtoull(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0') return 20;
    const HANDLE pipe = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(raw_pipe));
    uint32_t client = 0, server = 0, generation = 0;
    if (!IpmiScope::OpenClient(argv[2], 777, &client, &server, 2) ||
        IpmiScope::ResetClientEvents(client, 2, &generation) != IpmiScope::EventStatus::Matched) return 21;
    uint64_t current = 0;
    if (IpmiScope::PollClientEvent(client, 1, 6, 1, generation, &current) !=
        IpmiScope::EventStatus::Pending) return 22;
    DWORD written = 0;
    if (!WriteFile(pipe, &client, sizeof(client), &written, nullptr) || written != sizeof(client)) return 23;
    const auto start = std::chrono::steady_clock::now();
    if (!IpmiScope::WaitClientEventHint(client, 1000)) return 24;
    const auto elapsed = std::chrono::steady_clock::now() - start;
    if (elapsed >= std::chrono::milliseconds(500)) return 25;
    const auto status = IpmiScope::PollClientEvent(client, 1, 6, 1, generation, &current);
    return status == IpmiScope::EventStatus::Matched && current == 6 ? 0 : 26;
}

void CheckIpmiEventScopeLifetimes() {
    using namespace Libs::LibKernel;
    uint32_t server = 0, client = 0, actual_server = 0;
    bool duplicate = false;
    Check(IpmiScope::Register("SceEventGenerationFixture", 101, &server, &duplicate) && !duplicate,
          "event generation fixture server");
    Check(IpmiScope::OpenClient("SceEventGenerationFixture", 202, &client, &actual_server, 2) &&
          actual_server == server, "event generation fixture client");
    uint32_t old_generation = 0, new_generation = 0;
    Check(IpmiScope::ResetClientEvents(client, 2, &old_generation) == IpmiScope::EventStatus::Matched &&
          IpmiScope::CancelClientEvents(client) == IpmiScope::EventStatus::Matched &&
          IpmiScope::ResetClientEvents(client, 2, &new_generation) == IpmiScope::EventStatus::Matched &&
          old_generation != new_generation, "disconnect and reconnect create distinct event generations");
    uint64_t current = 0;
    Check(IpmiScope::PollClientEvent(client, 0, 1, 2, old_generation, &current) ==
          IpmiScope::EventStatus::Missing, "old waiter cannot cross a disconnect and reconnect generation");
    Check(IpmiScope::SetClientEvent(server, client, 0, 1) == IpmiScope::EventStatus::Matched &&
          IpmiScope::PollClientEvent(client, 0, 1, 2, new_generation, &current) ==
          IpmiScope::EventStatus::Matched && current == 1,
          "new generation receives its own server event");
    Check(IpmiScope::CloseClient(client) &&
          IpmiScope::PollClientEvent(client, 0, 1, 2, new_generation, &current) ==
          IpmiScope::EventStatus::Missing, "client close removes event state");
    Check(IpmiScope::Unregister(server), "event generation fixture cleanup");

    Check(IpmiScope::Register("SceEventServerLossFixture", 101, &server, &duplicate),
          "server loss fixture server");
    Check(IpmiScope::OpenClient("SceEventServerLossFixture", 203, &client, &actual_server, 1) &&
          IpmiScope::ResetClientEvents(client, 1, &new_generation) == IpmiScope::EventStatus::Matched,
          "server loss fixture client");
    Check(IpmiScope::Unregister(server) &&
          IpmiScope::PollClientEvent(client, 0, 1, 2, new_generation, &current) ==
          IpmiScope::EventStatus::Missing, "server loss removes client event state");
}

void CheckCrossHostIpmiEvents() {
    using namespace Libs::LibKernel;
    constexpr const char* service = "SceCrossHostEventFixture";
    uint32_t server = 0;
    bool duplicate = false;
    Check(IpmiScope::Register(service, 101, &server, &duplicate) && !duplicate,
          "cross-host event server registration");
    SECURITY_ATTRIBUTES security {sizeof(security), nullptr, TRUE};
    HANDLE read_pipe = nullptr, write_pipe = nullptr;
    Check(CreatePipe(&read_pipe, &write_pipe, &security, 0) &&
          SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0), "cross-host event pipe");
    std::array<wchar_t, 32768> executable {};
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    Check(length != 0 && length < executable.size(), "cross-host event executable path");
    std::wstring command = L"\"" + std::wstring(executable.data(), length) +
        L"\" --cross-host-event-client " + std::wstring(service, service + std::strlen(service)) +
        L" " + std::to_wstring(reinterpret_cast<uintptr_t>(write_pipe));
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup {sizeof(startup)};
    PROCESS_INFORMATION process {};
    Check(CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                         nullptr, nullptr, &startup, &process), "cross-host event child process");
    CloseHandle(write_pipe);
    write_pipe = nullptr;
    uint32_t client = 0;
    DWORD read = 0;
    Check(ReadFile(read_pipe, &client, sizeof(client), &read, nullptr) && read == sizeof(client) && client != 0,
          "cross-host event client identity");
    Sleep(50);
    Check(IpmiScope::SetClientEvent(server, client, 1, 6) == IpmiScope::EventStatus::Matched,
          "cross-host server sets shared event bits");
    const DWORD waited = WaitForSingleObject(process.hProcess, 5000);
    if (waited == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 25);
        WaitForSingleObject(process.hProcess, 5000);
    }
    DWORD exit_code = 0;
    Check(waited == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0,
          "cross-host client observes named mapping and wake event");
    Check(IpmiScope::SetClientEvent(server, client, 1, 1) == IpmiScope::EventStatus::Missing,
          "dead client owner is reaped with its event state");
    Check(IpmiScope::Unregister(server), "cross-host event server cleanup");
    CloseHandle(read_pipe);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

int main(int argc, char** argv) {
    using namespace Libs::LibKernel;
    // A failed Check must not park an unattended run on the debug CRT abort dialog.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    const int cross_host_child = RunCrossHostEventClient(argc, argv);
    if (cross_host_child >= 0) return cross_host_child;
    if (argc == 2 && std::strcmp(argv[1], "--puputil-admission-only") == 0) {
        _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", "1");
        const std::string scope = "puputil_" + std::to_string(GetCurrentProcessId());
        _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", scope.c_str());
        CheckPupUtilDiagnosticAdmission();
        std::puts("IpmiManagerTests: PupUtil diagnostic admission passed");
        return 0;
    }
    std::array<uint8_t, 0x38> native_config {};
    auto Store64 = [&](size_t offset, uint64_t value) { std::memcpy(native_config.data() + offset, &value, 8); };
    auto Store32 = [&](size_t offset, uint32_t value) { std::memcpy(native_config.data() + offset, &value, 4); };
    Store64(0, 0x38);
    Store64(8, 0xf00);
    Store64(0x10, 0xf00);
    Store32(0x18, 0);
    Store32(0x1c, 1);
    Store32(0x20, 1);
    Store64(0x30, 0x4f18c8);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == 0, "SysAv server config");
    Store64(0, 0x37);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == 0, "shorter declared config accepted");
    Store64(0, 0x39);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == KERNEL_ERROR_EINVAL, "oversize declared config");
    Store64(0, 0x38);
    Store64(8, 0x2001);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == KERNEL_ERROR_EINVAL, "first limit bound");
    Store64(8, 0x2000);
    Store64(0x10, 0x100001);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == KERNEL_ERROR_EINVAL, "second limit bound");
    Store64(0x10, 0x100000);
    Store32(0x20, 2);
    Check(IpmiManager::ValidateServerConfig(native_config.data()) == KERNEL_ERROR_EINVAL, "boolean fields");
    Store32(0x20, 0);

    AuthInfo::Record auth_info {};
    auto StoreAuth64 = [&](size_t offset, uint64_t value) { std::memcpy(auth_info.data() + offset, &value, 8); };
    StoreAuth64(0, 0x4800000010000004ull);
    StoreAuth64(8, 1ull << 62);
    Check(IpmiManager::ValidateServerAuthorization("SceSysAvControlIpc", auth_info) == KERNEL_ERROR_ENOSYS,
          "native rejected authority");
    StoreAuth64(0, 0x3800000000000011ull);
    StoreAuth64(8, 0);
    Check(IpmiManager::ValidateServerAuthorization("SceSysAvControlIpc", auth_info) == KERNEL_ERROR_EPERM,
          "Sce server requires system capability");
    StoreAuth64(8, 1ull << 62);
    Check(IpmiManager::ValidateServerAuthorization("SceSysAvControlIpc", auth_info) == 0,
          "source-backed system server policy");
    Check(IpmiManager::ValidateServerAuthorization("guest.ipc", auth_info) == KERNEL_ERROR_EPERM,
          "non-Sce server rejects system capability");
    StoreAuth64(8, 0);
    Check(IpmiManager::ValidateServerAuthorization("guest.ipc", auth_info) == 0,
          "non-Sce server accepts non-system capability");

    _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", "1");
    const std::string shared_scope = "test_" + std::to_string(GetCurrentProcessId());
    _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", shared_scope.c_str());
    CheckIpmiEventScopeLifetimes();
    CheckCrossHostIpmiEvents();
    CheckAdmissionDecisionTrace();
    CheckTraceReporting();
    CheckPartialAuthorization();
    CheckPupUtilDiagnosticAdmission();
    CheckCreationNames();
    CheckServerDirectoryCapacity();
    CheckDuplicateRegistrationRace();
    CheckClientConfig();
    CheckServerPost();
    CheckSessionUserData();
    uint64_t object = 1;
    std::array<uint64_t, 42> client_params {};
    client_params[0] = 336;
    client_params[1] = 1;
    client_params[2] = client_params[3] = 0x100;
    const char name[] = "SceSysAvControlIpc";
    uint64_t client_create[3] {Address(&object), Address(name), Address(client_params.data())};
    test_pid = 202;
    int client = Call(2, 0, client_create, sizeof(client_create));
    Check(client > 0, "allocate disconnected client before any server");
    std::array<char, 32> disconnected_name {};
    uint64_t name_args[1] {Address(disconnected_name.data())};
    Check(Call(0x46a, client, name_args, sizeof(name_args)) == 0 && std::strcmp(disconnected_name.data(), name) == 0,
          "disconnected client retains its service name");
    int completion = -1;
    uint32_t zero_timeout = 0;
    uint64_t connect[4] {0, 0, Address(&completion), Address(&zero_timeout)};
    for (int i = 0; i < 80; ++i) {
        Check(Call(0x400, client, connect, sizeof(connect)) == KERNEL_ERROR_ESRCH && completion == -1,
              "absent service probe preserves completion and allocates no transport");
    }
    uint32_t absent_timeout = 3000;
    connect[3] = Address(&absent_timeout);
    test_capture_log = true;
    test_log.clear();
    Check(Call(0x400, client, connect, sizeof(connect)) == KERNEL_ERROR_EAGAIN && completion == -1,
          "finite absent-service wait expires without completion");
    const auto wait_identity = "ORIGINAL_APP_IPMI_CONNECT_WAIT pid=202 host_tid=" + std::to_string(GetCurrentThreadId()) + " ";
    Check(std::count_if(test_log.begin(), test_log.end(), [&](const auto& line) {
              return line.find(wait_identity) == 0 && line.find("timeout_us=3000 timeout_pointer=1 server_present=0") != std::string::npos;
          }) == 1,
          "absent-service wait records its calling thread once without changing completion");
    const auto failed_identity = "ORIGINAL_APP_IPMI_CONNECT_IDENTITY pid=202 handle=" + std::to_string(client) +
                                 " client=0 request=0 transport=80020023 service_hex=5363655379734176436f6e74726f6c497063\n";
    const auto identity_line = std::find(test_log.begin(), test_log.end(), failed_identity);
    Check(identity_line != test_log.end() && identity_line + 1 != test_log.end() &&
              *(identity_line + 1) == "ORIGINAL_APP_IPMI_CONNECT pid=202 client=0 request=0 transport=80020023 callback=80020023\n",
          "failed connect names its service on a separate line and keeps the exact connect record");
    test_capture_log = false;
    test_log.clear();
    connect[0] = 1;
    connect[1] = 1;
    connect[3] = Address(&zero_timeout);
    Check(Call(0x400, client, connect, sizeof(connect)) == KERNEL_ERROR_EFAULT && completion == -1,
          "connect copies payload before absent-service lookup");
    connect[0] = connect[1] = 0;
    int unbound = Call(2, 0, client_create, sizeof(client_create));
    Check(unbound > 0 && Call(3, unbound, nullptr, 0) == 0 && Call(3, unbound, nullptr, 0) == KERNEL_ERROR_EBADF,
          "disconnected unbound client has an owned closeable lifetime");
    test_pid = 101;
    Check(Call(3, client, nullptr, 0) == KERNEL_ERROR_EBADF, "disconnected client preserves process ownership");
    StoreAuth64(8, 1ull << 62);
    test_auth_info = auth_info;
    test_has_auth_info = true;
    const char sysav_name[] = "SceSysAvControlIpc";
    uint64_t sysav_create[3] {Address(&object), Address(sysav_name), Address(native_config.data())};
    int sysav_server = Call(0, 0, sysav_create, sizeof(sysav_create));
    Check(sysav_server > 0, "authenticated SysAv fixture server");
    std::array<uint8_t, 64> server_trace {};
    std::memcpy(server_trace.data(), &sysav_server, sizeof(sysav_server));
    test_capture_log = true;
    Check(Call(0x10, 0x1f01, server_trace.data(), server_trace.size()) == OK &&
          test_log.back().find("name_hex=5363655379734176436f6e74726f6c49706300") != std::string::npos,
          "trace resolves metadata only from an existing owned server");
    test_pid = 202;
    Check(Call(0x10, 0x1f01, server_trace.data(), server_trace.size()) == OK &&
          test_log.back().find("name_hex=0000000000000000000000000000000000000000000000000000000000000000") != std::string::npos,
          "foreign server trace does not expose metadata or change server ownership");
    test_pid = 101;
    Check(Call(1, sysav_server, nullptr, 0) == 0, "authenticated SysAv fixture cleanup");
    Check(Call(0x10, 0x1f01, server_trace.data(), server_trace.size()) == OK &&
          test_log.back().find("name_hex=0000000000000000000000000000000000000000000000000000000000000000") != std::string::npos,
          "stale server trace completes as a report without reviving the object");
    test_capture_log = false;
    test_log.clear();
    StoreAuth64(8, 0);
    test_auth_info = auth_info;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_EPERM, sysav_name);
    test_has_auth_info = false;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_ENOSYS, sysav_name);
    sysav_create[2] = 1;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_ENOSYS, sysav_name);
    test_has_auth_info = true;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_EPERM, sysav_name);
    StoreAuth64(8, 1ull << 62);
    test_auth_info = auth_info;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_EFAULT, sysav_name);
    sysav_create[2] = Address(native_config.data());
    Store64(0, 0x39);
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_EINVAL, sysav_name);
    Store64(0, 0x38);
    StoreAuth64(0, 0x4800000010000004ull);
    test_auth_info = auth_info;
    CheckServerRejected(sysav_create, sizeof(sysav_create), Libs::Posix::POSIX_ENOSYS, sysav_name);
    StoreAuth64(0, 0x3800000000000011ull);
    test_has_auth_info = false;
    uint64_t server_params[7] {56, 0, 0, 0, 0, 0, Address(&object)};
    uint64_t create[3] {Address(&object), Address(name), Address(server_params)};
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_ENOSYS, name);
    CheckServerRejected(create, 23, Libs::Posix::POSIX_EINVAL, name);
    CheckServerRejected(reinterpret_cast<void*>(1), 24, Libs::Posix::POSIX_EFAULT, name);
    int status = 0;
    Check(IpmiManager::TryCall(0, 0, reinterpret_cast<int32_t*>(1), create, 24, 0, &status) && status == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT, "invalid result pointer");
    StoreAuth64(8, 1ull << 62);
    test_auth_info = auth_info;
    test_has_auth_info = true;
    int server = Call(0, 0, create, sizeof(create));
    Check(server > 0, "create fixture server");
    uint32_t admitted = 0, admitted_owner = 0, admitted_host = 0;
    Check(IpmiScope::Lookup(name, &admitted, &admitted_owner, &admitted_host), "existing admitted server identity");
    CheckServerRejected(create, sizeof(create), Libs::Posix::POSIX_EEXIST);
    uint32_t retained = 0, retained_owner = 0, retained_host = 0;
    Check(IpmiScope::Lookup(name, &retained, &retained_owner, &retained_host) &&
          retained == admitted && retained_owner == admitted_owner && retained_host == admitted_host,
          "duplicate rejection preserves the exact admitted server identity");
    create[2] = Address(client_params.data());
    test_pid = 202;
    uint64_t missing[3] {Address(&object), Address("SceSysCoreApp2"), Address(client_params.data())};
    unbound = Call(2, 0, missing, sizeof(missing));
    Check(unbound > 0 && Call(3, unbound, nullptr, 0) == 0, "allocate and delete client without App2 server");
    missing[1] = Address("SceAudioSystemIpcServer");
    unbound = Call(2, 0, missing, sizeof(missing));
    Check(unbound > 0 && Call(3, unbound, nullptr, 0) == 0,
          "non-App client allocation also precedes server registration");
    Check(Call(0x7fffffff, client, nullptr, 0) == KERNEL_ERROR_ENOSYS,
          "unsupported operation on client returns an error");
    std::array<char, 32> failed_name;
    failed_name.fill('x');
    uint64_t failed_name_args[1] {Address(failed_name.data())};
    Check(Call(0x46a, static_cast<int32_t>(0x8002004e), failed_name_args, sizeof(failed_name_args)) == KERNEL_ERROR_EBADF &&
              failed_name[0] == 'x' && failed_name[31] == 'x',
          "failed server ID cannot query or overwrite a name");
    std::array<uint8_t, 48> invoke {};
    const uint32_t method = 0xabcdef01;
    std::memcpy(invoke.data(), &method, 4);
    int method_result = 0;
    const uint64_t result_address = Address(&method_result);
    std::memcpy(invoke.data() + 32, &result_address, 8);
    const uint32_t flags = 1;
    std::memcpy(invoke.data() + 40, &flags, 4);
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_ENOTCONN, "invocation before connection");
    uint64_t session_params[2] {16, 0};
    uint64_t create_session[2] {Address(&object), Address(session_params)};
    Check(Call(4, -1, create_session, 16) == KERNEL_ERROR_EINVAL, "session requires received connect");
    auto pending = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, client, connect, 32); });
    test_pid = 101;
    ServerBuffers buffers;
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 1, "connect packet type");
    const uint32_t scope_client = buffers.info[1] >> 32;
    Check(Call(4, 0, create_session, 16) == KERNEL_ERROR_EINVAL, "session rejects wrong kid");
    int session = Call(4, -1, create_session, 16);
    Check(session > 0, "session created in receive context");
    Check(Call(4, -1, create_session, 16) == KERNEL_ERROR_EEXIST, "duplicate session");
    uint32_t peer = 0;
    uint64_t peer_args[1] {Address(&peer)};
    Check(!IpmiManager::ValidateCurrentAuthorizationPeer(202),
          "peer authorization requires the peer query");
    Check(Call(0x302, session, peer_args, 8) == 0 && peer == 202, "guest peer identity");
    Check(IpmiManager::ValidateCurrentAuthorizationPeer(202) &&
          !IpmiManager::ValidateCurrentAuthorizationPeer(101) &&
          !IpmiManager::ValidateCurrentAuthorizationPeer(203),
          "peer authorization is exact and connect-scoped");
    Check(IpmiManager::ValidateCurrentRemotePeer(202) && !IpmiManager::ValidateCurrentRemotePeer(203), "remote check takes the connect peer");
    int callback = 0;
    Check(Call(0x212, scope_client + 1, &callback, 4) == KERNEL_ERROR_EINVAL, "mismatched connect reply");
    Check(Call(0x212, scope_client, &callback, 4) == 0, "fixture callback reply");
    Check(!IpmiManager::ValidateCurrentAuthorizationPeer(202) && !IpmiManager::ValidateCurrentRemotePeer(202),
          "connect reply revokes peer authorization");
    Check(pending.get() == 0 && completion == 0, "connect waits callback");
    Check(Call(0x212, scope_client, &callback, 4) == KERNEL_ERROR_EINVAL, "duplicate connect reply");
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_EBADF, "foreign guest owner");
    test_pid = 202;
    std::array<uint8_t, 48> diagnostic_invoke {};
    const uint32_t diagnostic_method = 0x30009;
    const uint32_t diagnostic_flag = 1;
    int diagnostic_result = 0x12345678;
    const uint64_t diagnostic_result_address = Address(&diagnostic_result);
    std::memcpy(diagnostic_invoke.data(), &diagnostic_method, 4);
    std::memcpy(diagnostic_invoke.data() + 32, &diagnostic_result_address, 8);
    std::memcpy(diagnostic_invoke.data() + 40, &diagnostic_flag, 4);
    _putenv_s("KYTY_DIAGNOSTIC_SHELLUI_RNPS_INVOKE", "1");
    test_capture_log = true;
    test_log.clear();
    uint32_t diagnostic_count = 11;
    std::memcpy(diagnostic_invoke.data() + 4, &diagnostic_count, 4);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EINVAL,
          "RNPS diagnostic preserves invalid count result");
    diagnostic_count = 0;
    const uint32_t diagnostic_bad_flag = 2;
    std::memcpy(diagnostic_invoke.data() + 4, &diagnostic_count, 4);
    std::memcpy(diagnostic_invoke.data() + 40, &diagnostic_bad_flag, 4);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EINVAL,
          "RNPS diagnostic preserves invalid flag result");
    const uint64_t diagnostic_null = 0;
    std::memcpy(diagnostic_invoke.data() + 40, &diagnostic_flag, 4);
    std::memcpy(diagnostic_invoke.data() + 32, &diagnostic_null, 8);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves invalid method-result result");
    const uint32_t diagnostic_one = 1;
    std::memcpy(diagnostic_invoke.data() + 32, &diagnostic_result_address, 8);
    std::memcpy(diagnostic_invoke.data() + 4, &diagnostic_one, 4);
    std::memcpy(diagnostic_invoke.data() + 16, &diagnostic_null, 8);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves invalid input descriptor result");
    uint64_t diagnostic_input[2] {0, 4};
    const uint64_t diagnostic_input_address = Address(diagnostic_input);
    std::memcpy(diagnostic_invoke.data() + 16, &diagnostic_input_address, 8);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves invalid input payload result");
    diagnostic_count = 0;
    std::memcpy(diagnostic_invoke.data() + 4, &diagnostic_count, 4);
    std::memcpy(diagnostic_invoke.data() + 8, &diagnostic_one, 4);
    std::memcpy(diagnostic_invoke.data() + 24, &diagnostic_null, 8);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves invalid output descriptor result");
    uint64_t diagnostic_output[3] {0, 4, 0};
    const uint64_t diagnostic_output_address = Address(diagnostic_output);
    std::memcpy(diagnostic_invoke.data() + 24, &diagnostic_output_address, 8);
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves invalid output buffer result");
    const std::array<std::string, 7> diagnostic_stages {
        "stage=header_count", "stage=header_flag", "stage=method_result",
        "stage=input_descriptor", "stage=input_payload", "stage=output_descriptor",
        "stage=output_buffer",
    };
    for (const auto& stage: diagnostic_stages) {
        Check(std::count_if(test_log.begin(), test_log.end(), [&](const auto& line) {
            return line.rfind("SHELLUI_RNPS_IPMI_PROVENANCE ", 0) == 0 &&
                   line.find(stage) != std::string::npos &&
                   line.find("pointer_domain=") != std::string::npos;
        }) == 1, "RNPS diagnostic emits one bounded stage classification");
    }
    Check(std::any_of(test_log.begin(), test_log.end(), [](const auto& line) {
        return line.rfind("SHELLUI_RNPS_IPMI_PROVENANCE ", 0) == 0 &&
               line.find("stage=output_buffer") != std::string::npos &&
               line.find("pointer_domain=invalid") != std::string::npos;
    }), "RNPS diagnostic classifies invalid output buffer without exposing it");
    std::array<uint8_t, 0x48b> diagnostic_managed_output {};
    diagnostic_output[0] = Address(diagnostic_managed_output.data());
    diagnostic_output[1] = diagnostic_managed_output.size();
    test_non_guest_address = diagnostic_output[0];
    test_non_guest_size = diagnostic_output[1];
    test_log.clear();
    Check(Call(0x320, client, diagnostic_invoke.data(), diagnostic_invoke.size()) == KERNEL_ERROR_EFAULT,
          "RNPS diagnostic preserves unowned-host rejection result");
    Check(test_log.size() == 1 && test_log[0].find("pointer_domain=unowned") != std::string::npos,
          "RNPS diagnostic rejects arbitrary host memory without exposing it");
    test_non_guest_address = 0;
    test_non_guest_size = 0;
    _putenv_s("KYTY_DIAGNOSTIC_SHELLUI_RNPS_INVOKE", "");
    test_capture_log = false;
    uint32_t excessive = 11;
    std::memcpy(invoke.data() + 4, &excessive, 4);
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_EINVAL, "count limit");
    excessive = 0;
    std::memcpy(invoke.data() + 4, &excessive, 4);
    const uint32_t bad_flag = 2;
    std::memcpy(invoke.data() + 40, &bad_flag, 4);
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_EINVAL, "invoke flag is 0 or 1");
    std::memcpy(invoke.data() + 40, &flags, 4);
    auto request =std::async(std::launch::async, [&] { test_pid = 202; return Call(0x320, client, invoke.data(), invoke.size()); });
    test_pid = 101;
    const auto bound = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int poll_result = KERNEL_ERROR_EAGAIN;
    while (poll_result == KERNEL_ERROR_EAGAIN && std::chrono::steady_clock::now() < bound) poll_result = buffers.Receive(server, 8);
    Check(poll_result == KERNEL_ERROR_EMSGSIZE, "small receive error");
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 0x41, "request survives small receive");
    Check(Call(5, session, nullptr, 0) == KERNEL_ERROR_EBUSY, "pending session cannot disappear");
    struct ReplyArgs { int32_t result; uint32_t count; uint64_t outputs; uint32_t flags; uint32_t padding; } reply {-123, 0, 0, 2, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == KERNEL_ERROR_EINVAL, "reply flag is 0 or 1");
    reply.flags = 1;
    reply.count = 11;
    Check(Call(0x232, session, &reply, sizeof(reply)) == KERNEL_ERROR_EINVAL, "reply count limit");
    reply.count = 0;
    Check(Call(0x232, session, &reply, sizeof(reply)) == 0, "fixture method reply");
    Check(request.get() == 0 && method_result == -123, "method and transport errors stay separate");
    Check(Call(0x232, session, &reply, sizeof(reply)) == KERNEL_ERROR_EINVAL, "duplicate method reply");

    struct ManagedRnpsBuffers {
        int32_t method_result = 0x12345678;
        std::array<char, 10> title_id {'N', 'P', 'X', 'S', '4', '0', '0', '8', '7', '\0'};
        std::array<uint8_t, 0x48b> output {};
        std::array<uint64_t, 2> input {};
        std::array<uint64_t, 3> output_descriptor {};
    } managed;
    managed.input = {Address(managed.title_id.data()), managed.title_id.size()};
    managed.output_descriptor = {Address(managed.output.data()), managed.output.size(), 0};
    std::array<uint8_t, 48> managed_invoke {};
    const uint32_t managed_method = 0x30009;
    const uint32_t managed_count = 1;
    const uint64_t managed_input_address = Address(managed.input.data());
    const uint64_t managed_output_address = Address(managed.output_descriptor.data());
    const uint64_t managed_result_address = Address(&managed.method_result);
    std::memcpy(managed_invoke.data(), &managed_method, 4);
    std::memcpy(managed_invoke.data() + 4, &managed_count, 4);
    std::memcpy(managed_invoke.data() + 8, &managed_count, 4);
    std::memcpy(managed_invoke.data() + 16, &managed_input_address, 8);
    std::memcpy(managed_invoke.data() + 24, &managed_output_address, 8);
    std::memcpy(managed_invoke.data() + 32, &managed_result_address, 8);
    std::memcpy(managed_invoke.data() + 40, &flags, 4);
    auto StartManaged = [&] {
        return std::async(std::launch::async, [&] {
            test_pid = 202;
            test_non_guest_address = Address(&managed);
            test_non_guest_size = sizeof(managed);
            test_jemspace_address = Address(&managed);
            test_jemspace_size = sizeof(managed);
            const int result = Call(0x320, client, managed_invoke.data(), managed_invoke.size());
            test_non_guest_address = 0;
            test_non_guest_size = 0;
            test_jemspace_address = 0;
            test_jemspace_size = 0;
            return result;
        });
    };
    std::array<uint8_t, 16> managed_expected {};
    for (size_t i = 0; i < managed_expected.size(); ++i) managed_expected[i] = static_cast<uint8_t>(0xa0 + i);

    auto managed_success = StartManaged();
    test_pid = 101;
    buffers.Await(server);
    uint32_t received_managed_method = 0;
    std::memcpy(&received_managed_method, buffers.bytes.data() + 12, 4);
    Check(received_managed_method == managed_method &&
              std::memcmp(buffers.bytes.data() + 28, managed.title_id.data(), managed.title_id.size()) == 0 &&
              buffers.info[0] + managed_expected.size() <= buffers.bytes.size(),
          "RNPS managed-buffer request reaches the production path");
    std::memcpy(buffers.bytes.data() + buffers.info[0], managed_expected.data(), managed_expected.size());
    uint64_t managed_reply_output[3] {Address(buffers.bytes.data() + buffers.info[0]),
                                      managed_expected.size(), managed_expected.size()};
    reply = {0, 1, Address(managed_reply_output), 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == OK && managed_success.get() == OK &&
              managed.method_result == 0 && managed.output_descriptor[2] == managed_expected.size() &&
              std::memcmp(managed.output.data(), managed_expected.data(), managed_expected.size()) == 0,
          "registered Jemspace RNPS input and output complete with exact payload and actual length");

    managed.method_result = 0x12345678;
    managed.output.fill(0x5a);
    managed.output_descriptor[2] = 0;
    auto managed_method_error = StartManaged();
    test_pid = 101;
    buffers.Await(server);
    uint64_t empty_reply_output[3] {0, 0, 0};
    reply = {static_cast<int32_t>(0x81850008u), 1, Address(empty_reply_output), 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == OK && managed_method_error.get() == OK &&
              static_cast<uint32_t>(managed.method_result) == 0x81850008u && managed.output_descriptor[2] == 0 &&
              std::all_of(managed.output.begin(), managed.output.end(), [](uint8_t value) { return value == 0x5a; }),
          "RNPS method error remains separate from transport success and leaves zero-length output untouched");

    managed.method_result = 0x12345678;
    managed.output.fill(0x6b);
    managed.output_descriptor[2] = 0;
    auto managed_freed_before_reply = StartManaged();
    test_pid = 101;
    buffers.Await(server);
    std::memcpy(buffers.bytes.data() + buffers.info[0], managed_expected.data(), managed_expected.size());
    managed_reply_output[0] = Address(buffers.bytes.data() + buffers.info[0]);
    managed_reply_output[1] = managed_expected.size();
    managed_reply_output[2] = managed_expected.size();
    test_jemspace_live = false;
    reply = {0, 1, Address(managed_reply_output), 1, 0};
    const int freed_reply_result = Call(0x232, session, &reply, sizeof(reply));
    const int freed_invoke_result = managed_freed_before_reply.get();
    test_jemspace_live = true;
    Check(freed_reply_result == OK && freed_invoke_result == KERNEL_ERROR_EFAULT &&
              managed.method_result == 0x12345678 && managed.output_descriptor[2] == 0 &&
              std::all_of(managed.output.begin(), managed.output.end(), [](uint8_t value) { return value == 0x6b; }),
          "Jemspace release after queue is revalidated at copyout without publishing partial results");

    struct StackRnpsOutcome { int transport; uint32_t method_result; };
    auto stack_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        struct StackBuffers {
            int32_t method_result = 0x12345678;
            std::array<char, 10> title_id {'N', 'P', 'X', 'S', '4', '0', '0', '8', '7', '\0'};
            std::array<uint64_t, 2> input {};
        } stack;
        stack.input = {Address(stack.title_id.data()), stack.title_id.size()};
        std::array<uint8_t, 48> stack_invoke {};
        const uint32_t stack_method = 0x3000e;
        const uint32_t stack_count = 1;
        const uint64_t stack_input = Address(stack.input.data());
        const uint64_t stack_result = Address(&stack.method_result);
        std::memcpy(stack_invoke.data(), &stack_method, 4);
        std::memcpy(stack_invoke.data() + 4, &stack_count, 4);
        std::memcpy(stack_invoke.data() + 16, &stack_input, 8);
        std::memcpy(stack_invoke.data() + 32, &stack_result, 8);
        std::memcpy(stack_invoke.data() + 40, &flags, 4);
        test_non_guest_address = Address(&stack);
        test_non_guest_size = sizeof(stack);
        test_stack_address = Address(&stack);
        test_stack_size = sizeof(stack);
        const int transport = Call(0x320, client, stack_invoke.data(), stack_invoke.size());
        const uint32_t result = static_cast<uint32_t>(stack.method_result);
        test_non_guest_address = 0;
        test_non_guest_size = 0;
        test_stack_address = 0;
        test_stack_size = 0;
        return StackRnpsOutcome {transport, result};
    });
    test_pid = 101;
    buffers.Await(server);
    uint32_t stack_method = 0;
    std::memcpy(&stack_method, buffers.bytes.data() + 12, 4);
    reply = {static_cast<int32_t>(0x81850008u), 0, 0, 1, 0};
    const int stack_reply = Call(0x232, session, &reply, sizeof(reply));
    const auto stack_outcome = stack_pending.get();
    Check(stack_method == 0x3000e && stack_reply == OK && stack_outcome.transport == OK &&
              stack_outcome.method_result == 0x81850008u,
          "current native-thread stack RNPS spans preserve transport and method-result semantics");

    std::array<uint8_t, 48> first_invoke {};
    std::array<uint8_t, 48> second_invoke {};
    const uint32_t first_method = 0x30008;
    const uint32_t second_method = 0x3000f;
    const uint32_t one_output = 1;
    int first_result = -1;
    int second_result = -1;
    const uint64_t first_result_address = Address(&first_result);
    const uint64_t second_result_address = Address(&second_result);
    std::array<int32_t, 20> user_ids {};
    std::array<int32_t, 20> expected_user_ids {};
    for (size_t i = 0; i < expected_user_ids.size(); ++i) expected_user_ids[i] = static_cast<int32_t>(100 + i);
    uint64_t user_output[3] {Address(user_ids.data()), sizeof(user_ids), 0};
    const uint64_t user_output_address = Address(user_output);
    std::memcpy(first_invoke.data(), &first_method, 4);
    std::memcpy(first_invoke.data() + 32, &first_result_address, 8);
    std::memcpy(first_invoke.data() + 40, &flags, 4);
    std::memcpy(second_invoke.data(), &second_method, 4);
    std::memcpy(second_invoke.data() + 8, &one_output, 4);
    std::memcpy(second_invoke.data() + 24, &user_output_address, 8);
    std::memcpy(second_invoke.data() + 32, &second_result_address, 8);
    std::memcpy(second_invoke.data() + 40, &flags, 4);

    struct ConcurrentReplyOutcome {
        uint32_t method;
        bool identity;
        int nested_receive;
        int invalid_handle;
        int reply;
        int duplicate_reply;
    };
    std::promise<void> first_received;
    std::promise<void> second_received;
    std::promise<void> release_first;
    std::promise<void> release_second;
    auto first_received_wait = first_received.get_future();
    auto second_received_wait = second_received.get_future();
    auto release_first_wait = release_first.get_future().share();
    auto release_second_wait = release_second.get_future().share();
    auto first_server = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        uint32_t own_method = 0;
        std::memcpy(&own_method, own.bytes.data() + 12, 4);
        first_received.set_value();
        const int nested_receive = own.Receive(server);
        release_first_wait.wait();
        ReplyArgs answer {0x1234, 0, 0, 1, 0};
        const bool identity = IpmiManager::ValidateCurrentRequestPeer(202);
        const int invalid_handle = Call(0x232, 0x3000ffff, &answer, sizeof(answer));
        const int result = Call(0x232, session, &answer, sizeof(answer));
        const int duplicate = Call(0x232, session, &answer, sizeof(answer));
        return ConcurrentReplyOutcome {own_method, identity, nested_receive, invalid_handle, result, duplicate};
    });
    auto first_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x320, client, first_invoke.data(), first_invoke.size());
    });
    first_received_wait.wait();

    auto second_server = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        uint32_t own_method = 0;
        std::memcpy(&own_method, own.bytes.data() + 12, 4);
        const bool output_valid = own.info[0] + sizeof(expected_user_ids) <= own.bytes.size();
        if (output_valid) std::memcpy(own.bytes.data() + own.info[0], expected_user_ids.data(), sizeof(expected_user_ids));
        second_received.set_value();
        const int nested_receive = own.Receive(server);
        release_second_wait.wait();
        uint64_t output[3] {Address(own.bytes.data() + own.info[0]), sizeof(expected_user_ids), sizeof(expected_user_ids)};
        ReplyArgs answer {0, 1, Address(output), 1, 0};
        const bool identity = output_valid && IpmiManager::ValidateCurrentRequestPeer(202);
        const int invalid_handle = Call(0x232, 0x3000ffff, &answer, sizeof(answer));
        const int result = Call(0x232, session, &answer, sizeof(answer));
        const int duplicate = Call(0x232, session, &answer, sizeof(answer));
        return ConcurrentReplyOutcome {own_method, identity, nested_receive, invalid_handle, result, duplicate};
    });
    auto second_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x320, client, second_invoke.data(), second_invoke.size());
    });
    second_received_wait.wait();

    test_pid = 101;
    reply = {0, 0, 0, 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == KERNEL_ERROR_EINVAL,
          "a dispatcher thread cannot reply to another worker's request");
    test_pid = 999;
    Check(Call(0x232, session, &reply, sizeof(reply)) == KERNEL_ERROR_EBADF,
          "a foreign process cannot reply on the owned session");
    test_pid = 101;
    Check(Call(5, session, nullptr, 0) == KERNEL_ERROR_EBUSY,
          "session destruction cannot overtake concurrent outstanding requests");
    test_pid = 202;
    int busy_completion = 0x12345678;
    uint64_t busy_disconnect[1] {Address(&busy_completion)};
    Check(Call(0x310, client, busy_disconnect, sizeof(busy_disconnect)) == KERNEL_ERROR_EBUSY &&
              busy_completion == 0x12345678,
          "disconnect cannot overtake concurrent active invokes");
    Check(Call(3, client, nullptr, 0) == KERNEL_ERROR_EBUSY,
          "client destruction cannot overtake concurrent active invokes");
    test_pid = 101;

    release_second.set_value();
    const auto second_outcome = second_server.get();
    Check(second_outcome.method == second_method && second_outcome.identity &&
              second_outcome.nested_receive == KERNEL_ERROR_EBUSY &&
              second_outcome.invalid_handle == KERNEL_ERROR_EBADF && second_outcome.reply == OK &&
              second_outcome.duplicate_reply == KERNEL_ERROR_EINVAL && second_pending.get() == OK &&
              second_result == 0 && user_output[2] == sizeof(user_ids) && user_ids == expected_user_ids,
          "a later same-session request replies first with its exact output and cannot reply twice");
    test_pid = 202;
    Check(Call(0x310, client, busy_disconnect, sizeof(busy_disconnect)) == KERNEL_ERROR_EBUSY,
          "the remaining request retains lifecycle exclusion after an out-of-order reply");
    test_pid = 101;
    release_first.set_value();
    const auto first_outcome = first_server.get();
    Check(first_outcome.method == first_method && first_outcome.identity &&
              first_outcome.nested_receive == KERNEL_ERROR_EBUSY &&
              first_outcome.invalid_handle == KERNEL_ERROR_EBADF && first_outcome.reply == OK &&
              first_outcome.duplicate_reply == KERNEL_ERROR_EINVAL && first_pending.get() == OK &&
              first_result == 0x1234,
          "the earlier same-session request remains owned by its worker and replies independently");

    std::array<uint8_t, 48> malformed_invoke {};
    std::array<uint8_t, 48> surviving_invoke {};
    const uint32_t malformed_method = 0x30010;
    const uint32_t surviving_method = 0x30011;
    int malformed_result = 0x55;
    int surviving_result = -1;
    std::array<uint8_t, 8> malformed_output {};
    uint64_t malformed_descriptor[3] {Address(malformed_output.data()), malformed_output.size(), 0};
    const uint64_t malformed_descriptor_address = Address(malformed_descriptor);
    const uint64_t malformed_result_address = Address(&malformed_result);
    const uint64_t surviving_result_address = Address(&surviving_result);
    std::memcpy(malformed_invoke.data(), &malformed_method, 4);
    std::memcpy(malformed_invoke.data() + 8, &one_output, 4);
    std::memcpy(malformed_invoke.data() + 24, &malformed_descriptor_address, 8);
    std::memcpy(malformed_invoke.data() + 32, &malformed_result_address, 8);
    std::memcpy(malformed_invoke.data() + 40, &flags, 4);
    std::memcpy(surviving_invoke.data(), &surviving_method, 4);
    std::memcpy(surviving_invoke.data() + 32, &surviving_result_address, 8);
    std::memcpy(surviving_invoke.data() + 40, &flags, 4);

    std::promise<void> malformed_received;
    std::promise<void> surviving_received;
    std::promise<void> release_malformed;
    std::promise<void> release_surviving;
    auto malformed_received_wait = malformed_received.get_future();
    auto surviving_received_wait = surviving_received.get_future();
    auto release_malformed_wait = release_malformed.get_future().share();
    auto release_surviving_wait = release_surviving.get_future().share();
    auto malformed_server = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        uint32_t own_method = 0;
        std::memcpy(&own_method, own.bytes.data() + 12, 4);
        malformed_received.set_value();
        release_malformed_wait.wait();
        std::array<uint8_t, 9> oversized {};
        uint64_t output[3] {Address(oversized.data()), oversized.size(), oversized.size()};
        ReplyArgs answer {0, 1, Address(output), 1, 0};
        return std::pair {own_method, Call(0x232, session, &answer, sizeof(answer))};
    });
    auto malformed_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x320, client, malformed_invoke.data(), malformed_invoke.size());
    });
    malformed_received_wait.wait();
    auto surviving_server = std::async(std::launch::async, [&] {
        test_pid = 101;
        ServerBuffers own;
        own.Await(server);
        uint32_t own_method = 0;
        std::memcpy(&own_method, own.bytes.data() + 12, 4);
        surviving_received.set_value();
        release_surviving_wait.wait();
        ReplyArgs answer {0x4567, 0, 0, 1, 0};
        return std::pair {own_method, Call(0x232, session, &answer, sizeof(answer))};
    });
    auto surviving_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x320, client, surviving_invoke.data(), surviving_invoke.size());
    });
    surviving_received_wait.wait();
    release_malformed.set_value();
    const auto malformed_outcome = malformed_server.get();
    Check(malformed_outcome.first == malformed_method && malformed_outcome.second == OK &&
              malformed_pending.get() == KERNEL_ERROR_EBADMSG && malformed_result == 0x55 &&
              malformed_descriptor[2] == 0,
          "a malformed client copyout releases only its concurrent request without partial results");
    test_pid = 202;
    Check(Call(0x310, client, busy_disconnect, sizeof(busy_disconnect)) == KERNEL_ERROR_EBUSY,
          "surviving invoke retains lifecycle exclusion after peer failure");
    test_pid = 101;
    release_surviving.set_value();
    const auto surviving_outcome = surviving_server.get();
    Check(surviving_outcome.first == surviving_method && surviving_outcome.second == OK &&
              surviving_pending.get() == OK && surviving_result == 0x4567,
          "a concurrent peer request completes independently after malformed client copyout");

    uint64_t pool_event[3] {1, 0, 0};
    int pool_events = 0;
    for (;;) {
        int32_t post_result = 0x5a123456;
        int post_status = 0;
        *Libs::Posix::GetErrorAddr() = 0;
        Check(IpmiManager::TryCall(0x202, server, &post_result, pool_event, sizeof(pool_event),
                                   0, &post_status),
              "packet-pool post is handled");
        if (post_status != OK) {
            Check(*Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOMEM &&
                      post_result == 0x5a123456 && pool_events > 0,
                  "packet pool reports bounded exhaustion without logical result overwrite");
            break;
        }
        Check(post_result == OK && ++pool_events <= 32, "packet events fill the bounded pool");
    }
    test_pid = 202;
    first_result = 0x1357;
    Check(Call(0x320, client, first_invoke.data(), first_invoke.size()) == KERNEL_ERROR_EAGAIN &&
              first_result == 0x1357,
          "invoke reports packet-pool exhaustion without copying a method result");
    test_pid = 101;
    for (int i = 0; i < pool_events; ++i) {
        Check(buffers.Receive(server) == OK && buffers.info[1] == 0xffffffff000000b0ull,
              "packet-pool fixture event drains exactly once");
    }
    auto recovered_pending = std::async(std::launch::async, [&] {
        test_pid = 202;
        return Call(0x320, client, first_invoke.data(), first_invoke.size());
    });
    buffers.Await(server);
    reply = {0x2468, 0, 0, 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == OK && recovered_pending.get() == OK &&
              first_result == 0x2468,
          "invoke lease is released after packet-pool exhaustion");

    const char payload[] = {'a', 'b', 'c'};
    std::array<char, 8> output {};
    uint64_t input_descriptor[2] {Address(payload), sizeof(payload)};
    uint64_t output_descriptor[3] {Address(output.data()), output.size(), 0};
    const uint64_t input_address = Address(input_descriptor), output_address = Address(output_descriptor);
    const uint32_t one = 1;
    std::memcpy(invoke.data() + 4, &one, 4);
    std::memcpy(invoke.data() + 8, &one, 4);
    std::memcpy(invoke.data() + 16, &input_address, 8);
    std::memcpy(invoke.data() + 24, &output_address, 8);
    // 0x232 does not see the client capacity or count; both are rejected by the waiting client with EBADMSG.
    auto overlong = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x320, client, invoke.data(), invoke.size()); });
    buffers.Await(server);
    const char long_payload[] = "abcdefghi";
    uint64_t long_output[3] {Address(long_payload), 3, 9};
    reply = {77, 1, Address(long_output), 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == 0, "reply is not bounded by the client capacity in 0x232");
    Check(overlong.get() == KERNEL_ERROR_EBADMSG && output_descriptor[2] == 0 && output_descriptor[1] == 8 &&
              output[0] == 0 && method_result == -123,
          "overlong reply fails in the waiting client without partial results");
    auto miscounted = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x320, client, invoke.data(), invoke.size()); });
    buffers.Await(server);
    reply = {78, 0, 0, 1, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == 0, "reply count is not compared in 0x232");
    Check(miscounted.get() == KERNEL_ERROR_EBADMSG && output_descriptor[2] == 0 && method_result == -123,
          "reply count mismatch fails in the waiting client");
    auto repeated = std::async(std::launch::async, [&] {
        test_pid = 202;
        for (int i = 0; i < 100; ++i) {
            output_descriptor[2] = 0;
            Check(Call(0x320, client, invoke.data(), invoke.size()) == 0, "repeated request reply");
            Check(output_descriptor[2] == 3 && output_descriptor[1] == output.size() &&
                      std::memcmp(output.data(), payload, 3) == 0 && method_result == i,
                  "reply actual lengths and bytes copied");
        }
    });
    for (int i = 0; i < 100; ++i) {
        buffers.Await(server);
        Check(static_cast<uint32_t>(buffers.info[1]) == 0x41 && buffers.info[0] == 40 &&
                  std::memcmp(buffers.bytes.data() + 28, payload, 3) == 0,
              "unaligned input framing and separate outputs");
        std::memcpy(buffers.bytes.data() + buffers.info[0], payload, 3);
        // Odd replies use the raw responder shape {ptr, len, len} with flag 0 (libSceIpmi 0x3880).
        uint64_t server_output[3] {Address(buffers.bytes.data() + buffers.info[0]), i & 1 ? 3u : 8u, 3};
        reply = {i, 1, Address(server_output), i & 1 ? 0u : 1u, 0};
        Check(Call(0x232, session, &reply, sizeof(reply)) == 0, "fixture output reply");
    }
    repeated.get();
    const uint32_t raw = 0, init_method = 0, service_id = 0x00080001;
    uint64_t service_input[2] {Address(&service_id), sizeof(service_id)};
    uint64_t empty_output[3] {0, 0, 0x5a5a};
    const uint64_t service_address = Address(service_input), empty_address = Address(empty_output);
    std::memcpy(invoke.data(), &init_method, 4);
    std::memcpy(invoke.data() + 16, &service_address, 8);
    std::memcpy(invoke.data() + 24, &empty_address, 8);
    std::memcpy(invoke.data() + 40, &raw, 4);
    // InitService shape (libSceNpCommon 0x43a0 via IpmiClient 0x2dd0): raw flag 0, one 4-byte input, one null zero-capacity output.
    auto initialize = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x320, client, invoke.data(), invoke.size()); });
    buffers.Await(server);
    uint32_t received_method = 1, received_service = 0;
    std::memcpy(&received_method, buffers.bytes.data() + 12, 4);
    std::memcpy(&received_service, buffers.bytes.data() + 28, 4);
    Check(static_cast<uint32_t>(buffers.info[1]) == 0x51 && buffers.info[0] == 40 && received_method == 0 &&
              received_service == service_id,
          "raw invoke reaches the server as kind 0x51 with the framing");
    uint64_t raw_output[3] {Address(buffers.bytes.data() + buffers.info[0]), 0, 0};
    reply = {0, 1, Address(raw_output), 0, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == 0, "raw responder reply");
    Check(initialize.get() == 0 && method_result == 0 && empty_output[0] == 0 && empty_output[1] == 0 && empty_output[2] == 0,
          "raw invoke returns the server result and stores the actual output length");
    method_result = 5;
    auto raw_overlong = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x320, client, invoke.data(), invoke.size()); });
    buffers.Await(server);
    uint64_t raw_long[3] {Address(payload), 3, 3};
    reply = {0, 1, Address(raw_long), 0, 0};
    Check(Call(0x232, session, &reply, sizeof(reply)) == 0 && raw_overlong.get() == KERNEL_ERROR_EBADMSG && method_result == 5,
          "raw reply larger than the zero-capacity output is rejected by the client");
    test_pid = 202;
    uint64_t null_input[2] {0, 4};
    const uint64_t null_input_address = Address(null_input);
    std::memcpy(invoke.data() + 16, &null_input_address, 8);
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_EFAULT, "null input with nonzero length faults before send");
    std::memcpy(invoke.data() + 16, &service_address, 8);
    uint64_t null_output[3] {0, 4, 0};
    const uint64_t null_output_address = Address(null_output);
    std::memcpy(invoke.data() + 24, &null_output_address, 8);
    Check(Call(0x320, client, invoke.data(), invoke.size()) == KERNEL_ERROR_EFAULT, "null output with nonzero capacity faults before send");
    test_pid = 101;
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "faulted invokes queue nothing");
    test_pid = 202;
    uint64_t disconnect_args[1] {Address(&completion)};
    auto disconnect = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x310, client, disconnect_args, 8); });
    test_pid = 101;
    buffers.Await(server);
    Check(static_cast<uint32_t>(buffers.info[1]) == 3, "disconnect delivered to server");
    Check(Call(5, session, nullptr, 0) == 0, "fixture server destroys session");
    Check(Call(0x222, scope_client, &callback, 4) == 0 && disconnect.get() == 0, "disconnect waits callback");
    test_pid = 202;
    uint32_t actual_server = 0, actual_owner = 0;
    Check(IpmiScope::QueryClient(scope_client, &actual_server, &actual_owner) == IpmiScope::ClientStatus::Live && actual_owner == 202,
          "disconnected transport remains owned");
    _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", "");
    Check(IpmiScope::QueryClient(scope_client, &actual_server, &actual_owner) == IpmiScope::ClientStatus::Unavailable,
          "unavailable transport is distinct from proven missing endpoint");
    completion = -2024;
    Check(Call(0x400, client, connect, 32) == KERNEL_ERROR_ENOSYS && completion == -2024,
          "unavailable transport preserves disconnected KID and completion");
    Check(Call(3, client, nullptr, 0) == KERNEL_ERROR_EAGAIN,
          "uncertain transport cleanup cannot discard the owned endpoint");
    _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", shared_scope.c_str());
    auto restored = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, client, connect, 32); });
    test_pid = 101;
    buffers.Await(server);
    Check(buffers.info[1] >> 32 == scope_client, "temporary transport failure preserves exact endpoint identity");
    callback = -20;
    Check(Call(0x212, scope_client, &callback, 4) == 0 && restored.get() == 0 && completion == -20,
          "restored endpoint receives negative callback without connecting");
    callback = 0;
    test_pid = 202;
    for (int i = 0; i < 80; ++i) {
        uint32_t short_timeout = 2000;
        connect[3] = Address(&short_timeout);
        Check(Call(0x400, client, connect, 32) == KERNEL_ERROR_ETIMEDOUT, "timed out request reclaimed");
    }
    Check(Call(3, client, nullptr, 0) == 0, "destroy disconnected client");
    Check(Call(3, client, nullptr, 0) == KERNEL_ERROR_EBADF, "stale client rejected");
    test_pid = 101;
    Check(buffers.Receive(server) == KERNEL_ERROR_EAGAIN, "cancelled connects leave queue empty");
    Check(Call(1, server, nullptr, 0) == 0, "destroy server");
    Check(buffers.Receive(server) == KERNEL_ERROR_EBADF, "stale server rejected");
    create[2] = Address(server_params);
    server = Call(0, 0, create, 24);
    Check(server > 0, "new server after teardown");
    test_pid = 202;
    create[2] = Address(client_params.data());
    client = Call(2, 0, create, 24);
    connect[3] = Address(&zero_timeout);
    auto abandoned = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, client, connect, 32); });
    test_pid = 101;
    buffers.Await(server);
    Check(Call(1, server, nullptr, 0) == 0, "destroy server during connect");
    Check(abandoned.get() == KERNEL_ERROR_ECONNRESET, "peer death wakes blocked client");
    Check(Call(4, -1, create_session, 16) == KERNEL_ERROR_ECONNRESET, "stale receive context cannot create session");
    create[2] = Address(server_params);
    server = Call(0, 0, create, 24);
    Check(server > 0, "replacement server has a new generation");
    auto retried = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, client, connect, 32); });
    buffers.Await(server);
    callback = -17;
    Check(Call(0x212, buffers.info[1] >> 32, &callback, 4) == 0 && retried.get() == 0 && completion == -17,
          "same disconnected KID rebinds after peer death and receives callback status");
    callback = 0;
    Check(Call(1, server, nullptr, 0) == 0, "replacement server cleanup");
    test_pid = 202;
    Check(Call(3, client, nullptr, 0) == 0, "close client after peer died");
    test_pid = 101;
    create[2] = Address(server_params);
    server = Call(0, 0, create, 24);
    Check(server > 0, "server for late callback fixture");
    test_pid = 202;
    create[2] = Address(client_params.data());
    client = Call(2, 0, create, 24);
    uint32_t finite_timeout = 100000;
    connect[3] = Address(&finite_timeout);
    auto late = std::async(std::launch::async, [&] { test_pid = 202; return Call(0x400, client, connect, 32); });
    test_pid = 101;
    buffers.Await(server);
    const uint32_t late_client = buffers.info[1] >> 32;
    Check(late.get() == KERNEL_ERROR_ETIMEDOUT, "received connect can time out");
    Check(Call(4, -1, create_session, 16) == KERNEL_ERROR_ECONNRESET, "cancelled received request cannot create session");
    Check(Call(0x212, late_client, &callback, 4) == KERNEL_ERROR_ECONNRESET, "late reply cannot revive timed out connection");
    Check(Call(1, server, nullptr, 0) == 0, "late fixture server cleanup");
    test_pid = 202;
    Check(Call(3, client, nullptr, 0) == 0, "late fixture client cleanup");
    client = Call(2, 0, create, 24);
    Check(client > 0, "allocate client after server disappears");
    completion = -12345;
    connect[3] = 0;
    auto waiting = std::async(std::launch::async, [&] {
        test_pid = 202;
        for (;;) {
            const int result = Call(0x400, client, connect, 32);
            if (result != KERNEL_ERROR_EBUSY) return result;
            std::this_thread::yield();
        }
    });
    uint64_t probe[4] {0, 0, Address(&completion), Address(&zero_timeout)};
    const auto wait_bound = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (;;) {
        const int result = Call(0x400, client, probe, sizeof(probe));
        if (result == KERNEL_ERROR_EBUSY) break;
        Check(result == KERNEL_ERROR_ESRCH && std::chrono::steady_clock::now() < wait_bound,
              "pending connect starts within fixture deadline");
        std::this_thread::yield();
    }
    Check(waiting.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout && completion == -12345,
          "null-timeout connect parks until server appears");
    Check(Call(3, client, nullptr, 0) == KERNEL_ERROR_EBUSY, "pending connect owns client until operation completes");
    test_pid = 101;
    create[2] = Address(server_params);
    server = Call(0, 0, create, 24);
    Check(server > 0, "register server after connect has begun");
    buffers.Await(server);
    Check(Call(0x212, buffers.info[1] >> 32, &callback, 4) == 0 && waiting.get() == 0 && completion == 0,
          "late registration delivers pending connect and reply");
    Check(Call(1, server, nullptr, 0) == 0, "late registration fixture server cleanup");
    test_pid = 202;
    Check(Call(3, client, nullptr, 0) == 0, "late registration fixture client cleanup");
    auto* readonly = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(readonly != nullptr, "read-only fixture allocation");
    DWORD previous = 0;
    Check(VirtualProtect(readonly, 4096, PAGE_READONLY, &previous), "read-only fixture protection");
    Check(IpmiManager::TryCall(0, 0, static_cast<int32_t*>(readonly), create, 23, 0, &status) && status == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT, "read-only result rejected before creation");
    Check(VirtualFree(readonly, 0, MEM_RELEASE), "read-only fixture cleanup");
    std::puts("IpmiManagerTests: all cases passed");
}
#else
int main() { std::puts("IpmiManagerTests: Windows shared transport required"); }
#endif
