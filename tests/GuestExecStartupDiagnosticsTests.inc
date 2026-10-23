// ExecImage launches "<exe> --game <host> --sysroot <sysroot> --exec-child <token>"; the test executable plays the child selected by KYTY_TEST_GUEST_EXEC_STARTUP_MODE.
int RunGuestExecStartupDiagnosticsChild(int argc, char** argv) {
  if (argc != 7 || std::strcmp(argv[1], "--game") != 0 || std::strcmp(argv[5], "--exec-child") != 0) return -1;
#if defined(_WIN32)
  const char* mode = std::getenv("KYTY_TEST_GUEST_EXEC_STARTUP_MODE");
  if (mode == nullptr) return 90;
  if (std::strcmp(mode, "early") == 0) {
    std::fputs("startup-diagnostics early child\n", stderr);
    return Libs::LibKernel::Process::InitializeExecChild(std::string(argv[6]) + "0") ? 91 : 1;
  }
  if (!Libs::LibKernel::Process::InitializeExecChild(argv[6])) return 92;
  if (std::strcmp(mode, "exit") == 0) {
    std::printf("startup-diagnostics exit child request accepted\n");
    return 42;
  }
  Emulator::RunOptions options;
  Libs::LibKernel::Process::ApplyExecChildOptions(&options);
  if (const char* expected_root = std::getenv("KYTY_TEST_GUEST_EXEC_APP0_ROOT");
      expected_root != nullptr && expected_root[0] != '\0') {
    std::filesystem::path image;
    const bool require_package_identity =
        std::getenv("KYTY_TEST_GUEST_EXEC_REQUIRE_PACKAGE_IDENTITY") != nullptr;
    const bool package_identity =
        Libs::LibKernel::Process::IsExecChildApp0Package("NPXS40087");
    if (options.app0_dir != std::filesystem::path(expected_root) ||
        Common::PathToGenericString(options.elf) != "/app0/eboot.bin" ||
        !Libs::LibKernel::Process::ResolveExecChildImagePath("/app0/eboot.bin", &image) ||
        !Libs::LibKernel::Process::IsExecChildImagePath(image) ||
        package_identity != require_package_identity ||
        Libs::LibKernel::Process::IsExecChildApp0Package("NPXS40088") ||
        image != std::filesystem::path(argv[2])) return 95;
  }
  Libs::LibKernel::Process::MarkExecChildStartupStage(3);
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::Load(options.config);
  subsystems.Initialize<Log::Lifecycle>();
  Libs::LibKernel::Process::MarkExecChildStartupStage(4);
  if (std::strcmp(mode, "abort") == 0) return 93;
  LOGF("GUEST_EXEC_STARTUP_TEST_CHILD_LOG_OPEN\n");
  if (std::getenv("KYTY_TEST_GUEST_EXEC_VERIFY_PSM_ROUTE") != nullptr) {
    if (std::getenv("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE") != nullptr) return 96;
    FileSystem::Initialize();
    FileSystem::MountReadOnly(options.app0_dir, "/app0");
    const auto managed = FileSystem::GetRealFilename(
        "/app0/psm/Application/app.exe");
    const auto aot = FileSystem::GetRealFilename(
        "/app0/psm/Application/app.exe.sprx");
    Common::File managed_snapshot;
    std::array<uint8_t, 2> managed_header {};
    uint32_t managed_bytes = 0;
    std::error_code managed_error;
    std::vector<uint8_t> aot_image;
    const char* original_self = std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SELF");
    const HANDLE original_writer = original_self != nullptr
        ? CreateFileW(std::filesystem::path(original_self).c_str(), GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)
        : INVALID_HANDLE_VALUE;
    const bool original_self_locked = original_self != nullptr &&
        original_writer == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_SHARING_VIOLATION;
    if (original_writer != INVALID_HANDLE_VALUE) CloseHandle(original_writer);
    const bool managed_open = FileSystem::OpenPsmShellUiApplicationSnapshot(
        "/app0/psm/Application/app.exe", &managed_snapshot);
    if (managed_open) {
      managed_snapshot.Read(managed_header.data(), managed_header.size(),
                            &managed_bytes, &managed_error);
    }
    const bool route_ok = original_self_locked && !managed.empty() && !aot.empty() &&
        FileSystem::KernelOpen("/app0/psm/Application/app.exe", 1, 0) ==
            Libs::LibKernel::KERNEL_ERROR_EROFS && managed_open &&
        !managed_error && managed_bytes == managed_header.size() &&
        managed_header[0] == 'M' && managed_header[1] == 'Z' &&
        FileSystem::ReadPsmShellUiApplicationSnapshot(
            "/app0/psm/Application/app.exe.sprx", &aot_image) &&
        aot_image.size() == 127876 && aot_image[0] == 0x7f &&
        aot_image[1] == 'E' && aot_image[2] == 'L' && aot_image[3] == 'F';
    managed_snapshot.Close();
    FileSystem::Shutdown();
    Libs::LibKernel::Process::ReleaseValidatedElfForTests();
    FileSystem::Initialize();
    FileSystem::MountReadOnly(options.app0_dir, "/app0");
    const auto rejected_managed = FileSystem::GetRealFilename(
        "/app0/psm/Application/app.exe");
    const auto rejected_aot = FileSystem::GetRealFilename(
        "/app0/psm/Application/app.exe.sprx");
    const int rejected_open = FileSystem::KernelOpen(
        "/app0/psm/Application/app.exe.sprx", 0, 0);
    if (rejected_open >= 0) FileSystem::KernelClose(rejected_open);
    const bool identity_rejection_fail_closed = rejected_managed.empty() &&
        rejected_aot.empty() && rejected_open < 0;
    LOGF("PSM_SHELLUI_PRODUCTION_ROUTE_TEST result=%s managed_bytes=%zu aot_bytes=%zu"
         " original_self_locked=%d guest_write_erofs=1"
         " identity_rejection_fail_closed=%d\n",
         route_ok && identity_rejection_fail_closed ? "verified" : "rejected",
         managed_header.size(), aot_image.size(), original_self_locked ? 1 : 0,
         identity_rejection_fail_closed ? 1 : 0);
    FileSystem::Shutdown();
    if (!route_ok || !identity_rejection_fail_closed) return 96;
  }
  const bool released = Libs::LibKernel::Process::AwaitExecChildCommit(1, 1, 1);
  subsystems.Destroy();
  return released ? 0 : 94;
#else
  return 2;
#endif
}

#if defined(_WIN32)
std::string ReadGuestExecStartupLog(const std::filesystem::path& path) {
  Log::Flush();
  std::ifstream input(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::string GuestExecStartupLine(const std::string& log, const std::string& prefix) {
  const auto found = log.find(prefix);
  if (found == std::string::npos) return {};
  return log.substr(found, log.find('\n', found) - found);
}

int RunGuestExecStartupCase(int pid, const char* mode, const std::filesystem::path& host,
                            const std::filesystem::path& child_log_base, const std::filesystem::path& sysroot,
                            const std::filesystem::path& app0_dir = {},
                            const std::string& app0_elf = {},
                            const std::string& guest_path = "/app0/eboot.bin") {
  namespace Process = Libs::LibKernel::Process;
  Check(_putenv_s("KYTY_TEST_GUEST_EXEC_STARTUP_MODE", mode) == 0, "select the exec startup child mode");
  Emulator::RunOptions options;
  options.config.printf_direction = Config::LogDirection::File;
  options.config.printf_output_file = child_log_base;
  options.sysroot_dir = sysroot;
  Process::ConfigureExecRuntime(options);
  Process::RegisterRforkChild(pid, 1);
  Process::ScopedGuestProcessPid identity(pid);
  FileSystem::ScopedGuestDescriptorTable descriptors;
  return Process::ExecImage(guest_path, host, {"/app0/eboot.bin"}, {}, app0_dir, app0_elf);
}
#endif

void CheckGuestExecStartupDiagnostics(const std::filesystem::path& parent_log) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  TempDirectory temporary;
  const auto host = temporary.Path() / "app0" / "eboot.bin";
  std::filesystem::create_directories(host.parent_path());
  {
    std::ofstream output(host, std::ios::binary);
    const std::string zeros(64, '\0');
    output.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
  }
  Check(std::filesystem::file_size(host) == 64, "write the exec startup host image");
  constexpr const char* timeout_name = "KYTY_DIAGNOSTIC_GUEST_EXEC_PREPARE_TIMEOUT_MS";
  const auto* saved_timeout_raw = std::getenv(timeout_name);
  const bool had_saved_timeout = saved_timeout_raw != nullptr;
  const std::string saved_timeout = had_saved_timeout ? saved_timeout_raw : "";
  Check(_putenv_s(timeout_name, "") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 20000,
        "guest exec preparation timeout defaults to 20 seconds");
  Check(_putenv_s(timeout_name, "240000") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 240000,
        "guest exec preparation timeout accepts the evidenced successor value");
  Check(_putenv_s(timeout_name, "300000") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 300000,
        "guest exec preparation timeout accepts the bounded maximum");
  Check(_putenv_s(timeout_name, "19999") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 20000 &&
            _putenv_s(timeout_name, "300001") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 20000 &&
            _putenv_s(timeout_name, "240000x") == 0 && Kernel::Process::ExecPrepareTimeoutForTests() == 20000,
        "guest exec preparation timeout rejects out-of-range and malformed values");
  Check(_putenv_s(timeout_name, had_saved_timeout ? saved_timeout.c_str() : "") == 0,
        "restore the guest exec preparation timeout environment");
  const auto package_root =
      temporary.Path() / "system_ex" / "app" / "NPXS40087";
  const auto package_eboot = package_root / "eboot.bin";
  std::filesystem::create_directories(package_root / "psm" / "Application");
  std::vector<uint8_t> package_self(128, 0x53);
  std::memcpy(package_self.data(), "SELF", 4);
  {
    std::ofstream output(package_eboot, std::ios::binary);
    output.write(reinterpret_cast<const char*>(package_self.data()),
                 static_cast<std::streamsize>(package_self.size()));
  }
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUEST_EXECVE", "1") == 0, "enable guest exec for startup diagnostics");
  FileSystem::Initialize();
  FileSystem::MountReadOnly(temporary.Path(), "/");
  const auto short_base = temporary.Path() / "startup.log";
  const auto sysroot = temporary.Path() / "sysroot";

  Check(RunGuestExecStartupCase(7401, "early", host, short_base,
            std::filesystem::path(std::wstring(33000, L's'))) == Kernel::KERNEL_ERROR_EAGAIN,
        "a command line CreateProcess rejects returns EAGAIN");
  auto log = ReadGuestExecStartupLog(parent_log);
  auto line = GuestExecStartupLine(log, "GUEST_EXEC_CHILD_CREATE_FAILED guest_pid=7401 ");
  Check(!line.empty() && line.find(" win32_error=0") == std::string::npos &&
            log.find("GUEST_EXEC_PREPARING guest_pid=7401 ") == std::string::npos,
        "creation failure is logged with its win32 error and no child is prepared");
  std::printf("GuestExecStartupDiagnosticsTests: create_failure=pass\n");

  Check(RunGuestExecStartupCase(7402, "early", host, short_base, sysroot) == Kernel::KERNEL_ERROR_ENOEXEC,
        "a child that returns before mapping the handoff yields ENOEXEC");
  log = ReadGuestExecStartupLog(parent_log);
  line = GuestExecStartupLine(log, "GUEST_EXEC_PREPARATION_FAILED guest_pid=7402 ");
  Check(line.find(" state=0 ") != std::string::npos && line.find(" reason=child_exited_before_prepared ") != std::string::npos,
        "early child return is classified as exited before prepared");
  line = GuestExecStartupLine(log, "GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=7402 ");
  Check(line.find(" created=1 startup_stage=0(not_started) outcome=exited exit_code=0x00000001 ") != std::string::npos,
        "early child return keeps stage 0 and exit code 1");
  line = GuestExecStartupLine(log, "GUEST_EXEC_CHILD_OUTPUT guest_pid=7402 ");
  Check(line.find("startup-diagnostics early child\\n") != std::string::npos, "early child stderr is captured");
  Check(GuestExecStartupLine(log, "GUEST_EXEC_CHILD_COMMAND guest_pid=7402 ").find("--exec-child <redacted>") != std::string::npos,
        "child command line is logged with the endpoint redacted");
  std::printf("GuestExecStartupDiagnosticsTests: early_return=pass stderr_capture=pass token_redacted=pass\n");

  Check(RunGuestExecStartupCase(7403, "exit", host, short_base, sysroot) == Kernel::KERNEL_ERROR_ENOEXEC,
        "a child that exits nonzero after accepting the request yields ENOEXEC");
  log = ReadGuestExecStartupLog(parent_log);
  line = GuestExecStartupLine(log, "GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=7403 ");
  Check(line.find(" startup_stage=2(request_accepted) outcome=exited exit_code=0x0000002a ") != std::string::npos,
        "nonzero child exit keeps stage 2 and exit code 42");
  Check(GuestExecStartupLine(log, "GUEST_EXEC_CHILD_OUTPUT guest_pid=7403 ").find("request accepted\\n") != std::string::npos,
        "nonzero child stdout is captured");
  std::printf("GuestExecStartupDiagnosticsTests: nonzero_exit=pass stdout_capture=pass\n");

  // no longPathAware manifest here, so the nested child log path fails like a ShellCore exec child's
  const auto deep = temporary.Path() / std::string(150, 'd');
  std::filesystem::create_directories(deep);
  const auto long_base = deep / (std::string(90, 'x') + ".log");
  Check(long_base.wstring().size() >= 260, "construct a child log path beyond MAX_PATH");
  Check(RunGuestExecStartupCase(7404, "abort", host, long_base, sysroot) == Kernel::KERNEL_ERROR_ENOEXEC,
        "a child that aborts opening its log yields ENOEXEC");
  log = ReadGuestExecStartupLog(parent_log);
  line = GuestExecStartupLine(log, "GUEST_EXEC_PREPARATION_FAILED guest_pid=7404 ");
  Check(line.find(" wait=1 state=0 error=0x80020008 reason=child_exited_before_prepared ") != std::string::npos,
        "log-open abort reproduces the wait=1 state=0 ENOEXEC signature");
  line = GuestExecStartupLine(log, "GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=7404 ");
  Check(line.find(" startup_stage=3(runtime_init) outcome=exited exit_code=0x00000003 ") != std::string::npos,
        "log-open abort keeps stage 3 and the abort exit code");
  Check(GuestExecStartupLine(log, "GUEST_EXEC_CHILD_OUTPUT guest_pid=7404 ").find("spdlog fatal error") != std::string::npos,
        "log-open abort message is captured before any child log exists");
  bool child_log_exists = false;
  for (const auto& entry: std::filesystem::directory_iterator(deep)) {
    if (entry.path().filename().string().find(".exec-7404-") != std::string::npos) child_log_exists = true;
  }
  Check(!child_log_exists, "log-open abort leaves no child log");
  std::printf("GuestExecStartupDiagnosticsTests: abort_before_log=pass exit_code=pass output_capture=pass\n");

  const auto split_package_root = temporary.Path() / "NPXS40087";
  const auto decrypted_host = temporary.Path() / "decrypted" / "eboot.elf";
  std::filesystem::create_directories(split_package_root / "psm" / "Application");
  std::filesystem::create_directories(decrypted_host.parent_path());
  std::array<uint8_t, 64> decrypted_elf {};
  decrypted_elf[0] = 0x7f;
  decrypted_elf[1] = 'E';
  decrypted_elf[2] = 'L';
  decrypted_elf[3] = 'F';
  decrypted_elf[4] = 2;
  decrypted_elf[5] = 1;
  decrypted_elf[16] = 0x10;
  decrypted_elf[17] = 0xfe;
  decrypted_elf[18] = 0x3e;
  {
    std::ofstream output(decrypted_host, std::ios::binary);
    output.write(reinterpret_cast<const char*>(decrypted_elf.data()),
                 static_cast<std::streamsize>(decrypted_elf.size()));
  }
  Check(std::filesystem::file_size(decrypted_host) == decrypted_elf.size(),
        "create a separately pinned exec image for the split app0 handoff fixture");
  Check(_putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT", split_package_root.string().c_str()) == 0,
        "publish the expected app0 root to the exec child fixture");
  Check(RunGuestExecStartupCase(7405, "success", decrypted_host, short_base, sysroot,
                                split_package_root, "/app0/eboot.bin",
                                "/system_ex/app/NPXS40087/eboot.bin") == OK,
        "a child that opens its log and commits is accepted");
  Check(_putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT", "") == 0,
        "clear the expected app0 root fixture");
  Libs::LibKernel::Process::ReleaseCommittedExecChild(7405);
  bool exited = false;
  for (int i = 0; i < 300 && !exited; ++i) {
    log = ReadGuestExecStartupLog(parent_log);
    exited = log.find("GUEST_EXEC_HOST_EXIT guest_pid=7405 ") != std::string::npos;
    if (!exited) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  Check(exited && GuestExecStartupLine(log, "GUEST_EXEC_HOST_EXIT guest_pid=7405 ").find(" host_code=0x00000000 ") != std::string::npos,
        "committed child is released and exits cleanly");
  Check(log.find("GUEST_EXEC_IMAGE_COMMITTED guest_pid=7405 ") != std::string::npos &&
            log.find("GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=7405 ") == std::string::npos &&
            log.find("GUEST_EXEC_PREPARATION_FAILED guest_pid=7405 ") == std::string::npos,
        "successful startup emits no failure diagnostics");
  std::string child_log;
  for (const auto& entry: std::filesystem::directory_iterator(temporary.Path())) {
    if (entry.path().filename().string().starts_with("startup.log.exec-7405-")) {
      std::ifstream input(entry.path(), std::ios::binary);
      child_log.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
  }
  Check(child_log.find("GUEST_EXEC_STARTUP_TEST_CHILD_LOG_OPEN") != std::string::npos &&
            child_log.find("GUEST_EXEC_IMAGE_RELEASED guest_pid=7405 ") != std::string::npos,
        "successful child writes its own log");
  std::printf("GuestExecStartupDiagnosticsTests: successful_startup=pass child_log=pass\n");

  Check(_putenv_s("KYTY_TEST_GUEST_EXEC_STARTUP_MODE", "success") == 0 &&
            _putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT", package_root.string().c_str()) == 0,
        "arm the production execve preflight child fixture");
  const auto overlay_manifest = temporary.Path() / "decrypted-overlay.txt";
  const auto package_hash = Kernel::AuthInfo::DigestHex(
      Kernel::AuthInfo::Sha256(package_self.data(), package_self.size()));
  const auto decrypted_hash = Kernel::AuthInfo::DigestHex(
      Kernel::AuthInfo::Sha256(decrypted_elf.data(), decrypted_elf.size()));
  std::string overlay_text = "/system_ex/app/NPXS40087/eboot.bin " +
      std::to_string(package_self.size()) + " " + package_hash + " " +
      std::to_string(decrypted_elf.size()) + " " + decrypted_hash + " " +
      Common::PathToString(decrypted_host) + "\n";
  {
    std::ofstream output(overlay_manifest, std::ios::binary);
    output.write(overlay_text.data(), static_cast<std::streamsize>(overlay_text.size()));
  }
  const auto overlay_manifest_hash = Kernel::AuthInfo::DigestHex(
      Kernel::AuthInfo::Sha256(overlay_text.data(), overlay_text.size()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST",
                  overlay_manifest.string().c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST_SHA256",
                      overlay_manifest_hash.c_str()) == 0,
        "pin the production preflight decrypted-overlay fixture");
  Emulator::RunOptions preflight_options;
  preflight_options.config.printf_direction = Config::LogDirection::File;
  preflight_options.config.printf_output_file = short_base;
  preflight_options.sysroot_dir = sysroot;
  Libs::LibKernel::Process::ConfigureExecRuntime(preflight_options);
  Libs::LibKernel::Process::RegisterRforkChild(7406, 1);
  Libs::LibKernel::Process::SetRforkChildAppExec(
      7406, "/app0/eboot.bin", "/system_ex/app/NPXS40087/eboot.bin");
  void* guest = nullptr;
  Check(Libs::LibKernel::Memory::KernelMapNamedFlexibleMemory(
            &guest, 0x4000, 3, 0, "execve_preflight_fixture") == OK,
        "map the execve preflight guest request");
  auto* bytes = static_cast<uint8_t*>(guest);
  constexpr char guest_path[] = "/app0/eboot.bin";
  std::memcpy(bytes, guest_path, sizeof(guest_path));
  const uint64_t guest_address = reinterpret_cast<uint64_t>(guest);
  const uint64_t argv[] = {guest_address, 0};
  const uint64_t envp[] = {0};
  std::memcpy(bytes + 0x100, argv, sizeof(argv));
  std::memcpy(bytes + 0x200, envp, sizeof(envp));
  {
    Libs::LibKernel::Process::ScopedGuestProcessPid identity(7406);
    FileSystem::ScopedGuestDescriptorTable descriptors;
    const auto reply = Libs::NativeKernelBridge::PreflightSyscoreExecve(
        {0x3b, {guest_address, guest_address + 0x100, guest_address + 0x200}});
    Check(reply.value == OK && reply.posix_errno == 0,
          "the production execve preflight captures the pre-overlay package root");
  }
  Check(Libs::LibKernel::Memory::KernelMunmap(guest_address, 0x4000) == OK,
        "release the execve preflight guest request");
  Libs::LibKernel::Process::ReleaseCommittedExecChild(7406);
  exited = false;
  for (int i = 0; i < 300 && !exited; ++i) {
    log = ReadGuestExecStartupLog(parent_log);
    exited = log.find("GUEST_EXEC_HOST_EXIT guest_pid=7406 ") != std::string::npos;
    if (!exited) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  Check(exited &&
            log.find("SYSCORE_GUEST_EXECVE_APP0_PROVIDER guest_pid=7406 ") != std::string::npos &&
            log.find("SYSCORE_GUEST_EXECVE_DECRYPTED_OVERLAY guest_pid=7406 ") != std::string::npos &&
            log.find("GUEST_EXEC_IMAGE_COMMITTED guest_pid=7406 ") != std::string::npos,
        "the production preflight handoff commits with distinct package-root and image identities");
  Check(_putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST_SHA256", "") == 0,
        "clear the production execve preflight child fixture");
  std::printf("GuestExecStartupDiagnosticsTests: production_execve_app0_handoff=pass\n");

  size_t production_route_commands = 0;
  const char* production_package = std::getenv(
      "KYTY_TEST_GUEST_EXEC_PSM_PACKAGE_ROOT");
  const char* production_eboot = std::getenv(
      "KYTY_TEST_GUEST_EXEC_PSM_EBOOT_ELF");
  const char* production_self_root = std::getenv(
      "KYTY_TEST_GUEST_EXEC_PSM_SELF_ROOT");
  const bool require_production_route =
      std::getenv("KYTY_TEST_GUEST_EXEC_REQUIRE_PSM_PRODUCTION_ROUTE") != nullptr;
  Check(!require_production_route ||
            (production_package != nullptr && production_package[0] != '\0' &&
             production_eboot != nullptr && production_eboot[0] != '\0' &&
             production_self_root != nullptr && production_self_root[0] != '\0'),
        "required production PSM route inputs are present");
  if (production_package != nullptr && production_package[0] != '\0' &&
      production_eboot != nullptr && production_eboot[0] != '\0' &&
      production_self_root != nullptr && production_self_root[0] != '\0') {
    const auto production_root = std::filesystem::path(production_package);
    const auto production_image = std::filesystem::path(production_eboot);
    const char* prior_self_root = std::getenv(
        "KYTY_DIAGNOSTIC_ORIGINAL_SELF_BOOT_ROOT");
    const std::string saved_self_root = prior_self_root != nullptr ? prior_self_root : "";
    Check(_putenv_s("KYTY_TEST_GUEST_EXEC_STARTUP_MODE", "success") == 0 &&
              _putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT",
                        production_root.string().c_str()) == 0 &&
              _putenv_s("KYTY_TEST_GUEST_EXEC_VERIFY_PSM_ROUTE", "1") == 0 &&
              _putenv_s("KYTY_TEST_GUEST_EXEC_REQUIRE_PACKAGE_IDENTITY", "1") == 0 &&
              _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SELF_BOOT_ROOT",
                        production_self_root) == 0 &&
              std::getenv("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE") == nullptr,
          "arm the exact production PSM application route child fixture");
    const int production_result = RunGuestExecStartupCase(
        7407, "success", production_image, short_base, sysroot,
        production_root, "/app0/eboot.bin",
        "/system_ex/app/NPXS40087/eboot.bin");
    std::printf("GuestExecStartupDiagnosticsTests: production_route_exec_result=0x%08x\n",
                static_cast<uint32_t>(production_result));
    if (production_result != OK) {
      log = ReadGuestExecStartupLog(parent_log);
      std::printf("GuestExecStartupDiagnosticsTests: production_route_diagnostic=%s\n",
                  GuestExecStartupLine(log,
                      "GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=7407 ").c_str());
      std::printf("GuestExecStartupDiagnosticsTests: production_route_output=%s\n",
                  GuestExecStartupLine(log,
                      "GUEST_EXEC_CHILD_OUTPUT guest_pid=7407 ").c_str());
    }
    Check(production_result == OK,
          "the exact production PSM application route child is admitted");
    Libs::LibKernel::Process::ReleaseCommittedExecChild(7407);
    exited = false;
    for (int i = 0; i < 300 && !exited; ++i) {
      log = ReadGuestExecStartupLog(parent_log);
      exited = log.find("GUEST_EXEC_HOST_EXIT guest_pid=7407 ") != std::string::npos;
      if (!exited) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::string production_child_log;
    for (const auto& entry: std::filesystem::directory_iterator(temporary.Path())) {
      if (entry.path().filename().string().starts_with("startup.log.exec-7407-")) {
        std::ifstream input(entry.path(), std::ios::binary);
        production_child_log.assign(std::istreambuf_iterator<char>(input),
                                    std::istreambuf_iterator<char>());
      }
    }
    Check(exited && production_child_log.find(
              "PSM_SHELLUI_PRODUCTION_ROUTE_TEST result=verified ") !=
              std::string::npos && production_child_log.find(
              " identity_rejection_fail_closed=1 ") != std::string::npos,
          "the exec child consumes exact pinned managed and AOT snapshots");
    Check(_putenv_s("KYTY_TEST_GUEST_EXEC_APP0_ROOT", "") == 0 &&
              _putenv_s("KYTY_TEST_GUEST_EXEC_VERIFY_PSM_ROUTE", "") == 0 &&
              _putenv_s("KYTY_TEST_GUEST_EXEC_REQUIRE_PACKAGE_IDENTITY", "") == 0 &&
              _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SELF_BOOT_ROOT",
                        saved_self_root.c_str()) == 0,
          "clear the exact production PSM application route child fixture");
    production_route_commands = 1;
    std::printf("GuestExecStartupDiagnosticsTests: production_psm_shellui_route=pass"
                " identity_rejection_fail_closed=pass\n");
  }

  Check(!require_production_route || production_route_commands == 1,
        "required production PSM route fixture executed");

  size_t commands = 0;
  for (auto at = log.find("--exec-child "); at != std::string::npos; at = log.find("--exec-child ", at + 1)) {
    Check(log.compare(at + 13, 10, "<redacted>") == 0, "the --exec-child argument is never logged unredacted");
    ++commands;
  }
  // 7401 fails in CreateProcess, before the command line is logged.
  Check(commands == 5 + production_route_commands,
        "every launched child logged its redacted command line");
  std::printf("GuestExecStartupDiagnosticsTests: token_absent=pass\n");
  FileSystem::Shutdown();
#endif
}
