#if defined(_WIN32)
class RegistryTrapEnvironment {
public:
  RegistryTrapEnvironment() {
    constexpr const char* names[] = {
        "KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE",
        "KYTY_DIAGNOSTIC_REGMGR_KERNEL_TABLE",
        "KYTY_REGMGR_LIVE_SNAPSHOT",
        "KYTY_REGMGR_LIVE_SNAPSHOT_SHA256",
        "KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS",
        "KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_SYSCTL",
        "KYTY_DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS",
        "KYTY_DIAGNOSTIC_AGC_NATIVE_KEVENT_AUDIT",
        "KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD",
        "KYTY_DIAGNOSTIC_SYSCORE_NATIVE_KQUEUE_BACKEND",
        "KYTY_DIAGNOSTIC_SYSCORE_RFORK_AUDIT",
        "KYTY_DIAGNOSTIC_SYSCORE_EXECVE_AUDIT",
        "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP",
        "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
        "KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10",
        "KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK",
        "KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS",
        "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
        "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY",
        "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET"};
    for (const auto* name: names) {
      const auto* value = std::getenv(name);
      saved.push_back({name, value != nullptr, value == nullptr ? "" : value});
      Check(_putenv_s(name, "") == 0, "clear inherited wrapper diagnostic setting");
    }
  }

  ~RegistryTrapEnvironment() {
    for (const auto& entry: saved) {
      Check(_putenv_s(entry.name, entry.present ? entry.value.c_str() : "") == 0,
            "restore wrapper diagnostic setting");
    }
  }

  KYTY_CLASS_NO_COPY(RegistryTrapEnvironment);

private:
  struct Saved {
    const char* name;
    bool present;
    std::string value;
  };
  std::vector<Saved> saved;
};
#endif
