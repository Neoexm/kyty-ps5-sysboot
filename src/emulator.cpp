#include "emulator.h"

#include "common/abi.h"
#include "common/assert.h"
#include "common/emulatorConfig.h"
#include "common/file.h"
#include "common/logging/log.h"
#include "common/profiler.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "common/subsystems.h"
#include "common/systemInfo.h"
#include "common/threads.h"
#include "graphics/presentation/window.h"
#include "kernel/envelopeSecureProcessor.h"
#include "kernel/fileSystem.h"
#include "kernel/capturedRootMetadata.h"
#include "kernel/capturedDirectory.h"
#include "kernel/execProcess.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "kernel/sectorBacking.h"
#include "kytyGitVersion.h"
#include "libs/agc.h"
#include "libs/audio.h"
#include "libs/controller.h"
#include "libs/libs.h"
#include "libs/network.h"
#include "loader/elf.h"
#include "loader/runtimeLinker.h"
#include "loader/systemContent.h"
#include "loader/timer.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#endif
#include <thread>

namespace Emulator {

static void PrintSystemInfo() {
	const Common::SystemInfo info = Common::GetSystemInfo();

#if defined(__APPLE__)
	static constexpr auto platform_name = "macOS";
#elif KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	static constexpr auto platform_name = "Windows";
#elif KYTY_PLATFORM == KYTY_PLATFORM_LINUX
	static constexpr auto platform_name = "Linux";
#else
	static constexpr auto platform_name = "Unknown";
#endif

	LOGF("Build\n"
	     "  version: %s\n\n"
	     "Host\n"
	     "  os:      %s\n"
	     "  cpu:     %s\n"
	     "  threads: %u\n\n",
	     KYTY_BUILD_LABEL, platform_name, info.ProcessorName.c_str(),
	     std::thread::hardware_concurrency());
}

static void KytyClose() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		void*      trace[20] {};
		const auto frames = CaptureStackBackTrace(0, 20, trace, nullptr);
		std::printf("SYSCORE_EMULATOR_ATEXIT_ENTRY thread_id=%lu"
		            " frame_count=%u guest_code_not_yet_cleared\n",
		            static_cast<unsigned long>(GetCurrentThreadId()),
		            static_cast<unsigned>(frames));
		for (USHORT i = 0; i < frames; ++i) {
			std::printf("SYSCORE_EMULATOR_ATEXIT_FRAME index=%u address=%p\n",
			            static_cast<unsigned>(i), trace[i]);
		}
		std::fflush(stdout);
	}
#endif
	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();

	rt->Clear();

	LOGF("done!\n");

	Common::Subsystems::EmergencyShutdownActive();
}

static void MountOrCreateDir(const std::filesystem::path& dir, const std::string& point) {
	if (!Common::File::IsDirectoryExisting(dir)) {
		Common::File::CreateDirectories(dir);
	}

	EXIT_NOT_IMPLEMENTED(!Common::File::IsDirectoryExisting(dir));

	Libs::LibKernel::FileSystem::Mount(dir, point);
	auto dir_text = Common::PathToString(dir);
	LOGF("Mounted %s -> %s\n", point.c_str(), dir_text.c_str());
}

static void MountSandboxDirs() {
	std::string title_id;
	if (!Loader::SystemContentParamSfoGetString("TITLE_ID", &title_id) || title_id.empty()) {
		title_id = "UNKNOWN";
	}

	MountOrCreateDir("_DownloadData/" + title_id, "/download0");
	MountOrCreateDir("_TempData/" + title_id, "/temp0");
	MountOrCreateDir("_TempData/" + title_id, "/temp");
}

static bool ClearDirectoryContents(const std::filesystem::path& dir) {
	bool ok = true;

	for (const auto& entry: Common::File::GetDirEntries(dir)) {
		if (entry.name == "." || entry.name == "..") {
			continue;
		}

		auto path = dir / entry.name;

		if (entry.is_file) {
			Common::File::RemoveReadonly(path);
			ok = Common::File::DeleteFile(path) && ok;
		} else {
			ok = ClearDirectoryContents(path) && ok;
			ok = Common::File::DeleteDirectory(path) && ok;
		}
	}

	return ok;
}

static void ClearDebugTextureFolder() {
	const std::string debug_texture_folder = "_Textures";

	if (!Common::File::IsDirectoryExisting(debug_texture_folder)) {
		Common::File::CreateDirectories(debug_texture_folder);
		return;
	}

	if (!ClearDirectoryContents(debug_texture_folder)) {
		LOGF_COLOR(Log::Color::BrightYellow, "TextureDump: failed to completely clear %s\n",
		           debug_texture_folder.c_str());
	}
}

static void Init(const Config::ConfigOptions& cfg, const std::filesystem::path& param_json,
                 Common::Subsystems& subsystems) {
	EXIT_IF(!Common::Thread::IsMainThread());

	subsystems.Initialize<Config::Lifecycle>();
	Config::Load(cfg);
	subsystems.Initialize<Log::Lifecycle>();
	Libs::LibKernel::Process::MarkExecChildStartupStage(4);

	if (Common::File::IsFileExisting(param_json)) {
		Loader::SystemContentLoadParamSfo(param_json);
		if (const auto flexible_memory_size = Loader::SystemContentGetFlexibleMemorySize();
		    flexible_memory_size != 0) {
			Libs::LibKernel::Memory::SetFlexibleMemorySize(flexible_memory_size);
		}
	}

	// Initialization order is explicit; destruction is automatic and reversed.
	subsystems.Initialize<Loader::Timer::Lifecycle>();
	subsystems.Initialize<Libs::LibKernel::PthreadLifecycle>();
	subsystems.Initialize<Profiler::Lifecycle>();
	subsystems.Initialize<Libs::Network::Lifecycle>();
	subsystems.Initialize<Libs::LibKernel::Memory::Lifecycle>();
	subsystems.Initialize<Libs::LibKernel::FileSystem::Lifecycle>();
	subsystems.Initialize<Libs::Controller::Lifecycle>();
	subsystems.Initialize<Libs::Audio::Lifecycle>();
	subsystems.Initialize<Libs::Graphics::Lifecycle>();
}

static Loader::Program* LoadElf(const std::filesystem::path& elf, bool dbg_print_reloc = false,
                                const std::filesystem::path& save_name = {}) {
	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();

	auto* program = rt->LoadProgram(
	    Libs::LibKernel::FileSystem::GetRealFilename(Common::PathToGenericString(elf)));

	if (dbg_print_reloc) {
		program->dbg_print_reloc = true;
	}

	if (!save_name.empty()) {
		rt->SaveProgram(program, Libs::LibKernel::FileSystem::GetRealFilename(
		                             Common::PathToGenericString(save_name)));
	}
	return program;
}

static void Execute(const std::filesystem::path& game_patch) {
	auto           patch_path = game_patch;
	Common::Thread guest_thread(
	    [](void* param) {
		    auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
		    rt->Execute(*static_cast<const std::filesystem::path*>(param));
	    },
	    &patch_path);
	Libs::Graphics::WindowRun();
	std::quick_exit(0);
}

void Run(const RunOptions& options) {
	Libs::LibKernel::Process::ConfigureExecRuntime(options);
	if (options.app0_dir.empty()) {
		EXIT("app0 directory is required\n");
	}

	if (options.elf.empty()) {
		EXIT("ELF is required\n");
	}

	const auto         param_json = options.app0_dir / "sce_sys" / "param.json";
	Libs::Graphics::WindowSetProcessImage(Common::PathToGenericString(options.elf.filename()));
	Common::Subsystems subsystems(true);
	Libs::LibKernel::Process::MarkExecChildStartupStage(3);
	Init(options.config, param_json, subsystems);
	std::string                                        envelope_provider_error;
	Libs::LibKernel::EnvelopeSecureProcessor::Provider envelope_provider_kind =
	    Libs::LibKernel::EnvelopeSecureProcessor::Provider::None;
	const auto envelope_provider =
	    Libs::LibKernel::EnvelopeSecureProcessor::ConfigureProductionBackendFromEnvironment(
	        &envelope_provider_error, &envelope_provider_kind);
	if (envelope_provider ==
	    Libs::LibKernel::EnvelopeSecureProcessor::ConfigurationStatus::Invalid) {
		EXIT("Envelope provider configuration rejected: %s\n", envelope_provider_error.c_str());
	}
	if (envelope_provider ==
	    Libs::LibKernel::EnvelopeSecureProcessor::ConfigurationStatus::Configured) {
		LOGF("SBL_ENVELOPE_PROVIDER_CONFIGURED provider=%s protocol=1 authenticated=1 offline=%d\n",
		     Libs::LibKernel::EnvelopeSecureProcessor::ProviderName(envelope_provider_kind),
		     envelope_provider_kind == Libs::LibKernel::EnvelopeSecureProcessor::Provider::Local
		         ? 1
				 : 0);
	}
	Libs::LibKernel::Process::MarkExecChildStartupStage(5);
	if (!Libs::LibKernel::Process::IsExecChild()) {
		Libs::LibKernel::Process::InstallRootOriginalSelf(options);
		Libs::LibKernel::Process::PublishToScope();
	}

	if (!Libs::LibKernel::Process::IsExecChild()) {
		ClearDebugTextureFolder();
	}

	PrintSystemInfo();
	std::string title_id;
	if (Loader::SystemContentParamSfoGetString("TITLE_ID", &title_id) && !title_id.empty()) {
		Log::WriteToConsoleAndLog(fmt::format("Title ID: {}\n", title_id));
	}

	int ok = atexit(KytyClose);
	EXIT_NOT_IMPLEMENTED(ok != 0);

	// Guest threads are still running, so skip KytyClose() and only flush emergency state.
	ok = at_quick_exit(Common::Subsystems::EmergencyShutdownActive);
	EXIT_NOT_IMPLEMENTED(ok != 0);

	if (Libs::LibKernel::Process::IsExecChild()) {
		Libs::LibKernel::FileSystem::MountReadOnly(options.app0_dir, "/app0");
		Libs::LibKernel::FileSystem::MountReadOnly(options.app0_dir, "/hostapp");
	} else {
		Libs::LibKernel::FileSystem::Mount(options.app0_dir, "/app0");
		Libs::LibKernel::FileSystem::Mount(options.app0_dir, "/hostapp");
	}

	MountSandboxDirs();
	// writable trees live outside the sysroot so guest writes stay out of the dump
	if (const char* state_dir = std::getenv("KYTY_DIAGNOSTIC_WRITABLE_STATE_DIR");
	    state_dir != nullptr) {
		// /<word>/priv/mms with an empty word; must precede /priv, first matching mount wins
		MountOrCreateDir(std::filesystem::path(state_dir) / "system_data" / "priv" / "mms",
		                 "/priv/mms");
		for (const char* name: {"system_data", "priv", "user"}) {
			MountOrCreateDir(std::filesystem::path(state_dir) / name, std::string("/") + name);
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH") != nullptr) {
		static constexpr std::pair<const char*, const char*> entries[] = {
		    {"SYSTEM", "/dev/ssd0.system"},
		    {"SYSTEM_B", "/dev/ssd0.system_b"},
		    {"SYSTEM_EX", "/dev/ssd0.system_ex"},
		    {"SYSTEM_EX_B", "/dev/ssd0.system_ex_b"},
		    {"SYSTEM_DATA", "/dev/ssd0.system_data"},
		    {"SYSTEM_DATA_B", "/dev/ssd0.system_data_b"},
		    {"UPDATE", "/dev/ssd0.update"},
		    {"UPDATE_B", "/dev/ssd0.update_b"},
		    {"PREINST", "/dev/ssd0.preinst"},
		    {"PREINST_B", "/dev/ssd0.preinst_b"},
		    {"RNPS", "/dev/lvd0"},
		    {"USER", "/dev/ssd0.user"},
		};
		for (const auto& [suffix, device]: entries) {
			std::string key = std::string("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH_") + suffix;
			const char* host_root = std::getenv(key.c_str());
			if (host_root == nullptr) continue;
			const int result = Libs::LibKernel::FileSystem::RegisterDiagnosticPartitionPassthrough(
			    device, Common::PathFromUtf8(host_root));
			if (result != 0) {
				EXIT("Diagnostic passthrough registration failed for %s host_root=%s "
				     "result=0x%08x\n",
				     device, host_root, static_cast<uint32_t>(result));
			}
		}
	}
	if (const char* fixture = std::getenv("KYTY_DIAGNOSTIC_BFS_USER_FIXTURE"); fixture != nullptr) {
		// No SSD hash for a fixture: empty overlay and sha256 skip the check. Capacity() is the
		// sector-aligned size SCFSTAT reports for NSID1.
		Libs::LibKernel::SectorBacking::Result open_result;
		auto backing = Libs::LibKernel::SectorBacking::OpenCapturedPrefix(
		    Common::PathFromUtf8(fixture), {}, {}, &open_result);
		if (!backing || open_result != Libs::LibKernel::SectorBacking::Result::Ok) {
			EXIT("KYTY_DIAGNOSTIC_BFS_USER_FIXTURE open failed path=%s result=%d\n", fixture,
			     static_cast<int>(open_result));
		}
		const uint64_t bytes  = backing->Capacity();
		const int      result = Libs::LibKernel::FileSystem::RegisterDiagnosticSectorPayload(
		    "/dev/ssd0.user", std::shared_ptr<Libs::LibKernel::SectorBacking>(std::move(backing)));
		if (result != 0) {
			EXIT("KYTY_DIAGNOSTIC_BFS_USER_FIXTURE registration failed path=%s result=0x%08x\n",
			     fixture, static_cast<uint32_t>(result));
		}
		LOGF("NON_AUTHENTIC BFS fixture bound to /dev/ssd0.user path=%s bytes=%" PRIu64 "\n",
		     fixture, bytes);
	}
	if (!options.sysroot_dir.empty()) {
		Libs::LibKernel::FileSystem::MountReadOnly(options.sysroot_dir, "/");
		LOGF("Mounted / -> %s\n", Common::PathToString(options.sysroot_dir).c_str());
	}
	if (const char* capture = std::getenv("KYTY_PS5_CAPTURED_ROOT_KERNEL"); capture != nullptr) {
		if (options.sysroot_dir.empty()) EXIT("Captured root metadata requires --sysroot\n");
		const auto load_started = std::chrono::steady_clock::now();
		const int  result =
		    Libs::LibKernel::CapturedRootMetadata::Load(Common::PathFromUtf8(capture));
		const auto load_us = std::chrono::duration_cast<std::chrono::microseconds>(
		                         std::chrono::steady_clock::now() - load_started)
		                         .count();
		if (result != 0)
			EXIT("Captured root metadata rejected: 0x%08x\n", static_cast<uint32_t>(result));
		LOGF("CAPTURED_ROOT_METADATA_READY profile=13.60-live root_nodes=24 directories=17"
		     " whole_kernel_sha256_verified=1"
		     " startup_cache_hit=%u source_hash_revalidated=%u load_us=%" PRId64 "\n",
		     Libs::LibKernel::CapturedRootMetadata::LastLoadUsedStartupCache() ? 1u : 0u,
		     Libs::LibKernel::CapturedRootMetadata::LastLoadUsedStartupCache() ? 0u : 1u, load_us);
	}
	if (const char* directory = std::getenv("KYTY_PS5_INITIAL_SYSTEM_TMP_DIR");
	    directory != nullptr) {
		if (options.sysroot_dir.empty()) {
			EXIT("KYTY_PS5_INITIAL_SYSTEM_TMP_DIR requires --sysroot\n");
		}
		const int result = Libs::LibKernel::FileSystem::MountInitialSystemTmpDirectory(
		    options.sysroot_dir, Common::PathFromUtf8(directory));
		if (result != 0) {
			EXIT("Initial /system_tmp directory configuration failed: 0x%08x\n",
			     static_cast<uint32_t>(result));
		}
	}
	if (const char* manifest = std::getenv("KYTY_PS5_CAPTURED_STORAGE_MANIFEST");
	    manifest != nullptr) {
		const char* digest       = std::getenv("KYTY_PS5_CAPTURED_STORAGE_SHA256");
		const auto  load_started = std::chrono::steady_clock::now();
		const int  result = Libs::LibKernel::CapturedDirectory::Load(Common::PathFromUtf8(manifest),
		                                                             digest ? digest : "");
		const auto load_us = std::chrono::duration_cast<std::chrono::microseconds>(
		                         std::chrono::steady_clock::now() - load_started)
		                         .count();
		if (result != 0)
			EXIT("Captured storage manifest rejected: 0x%08x\n", static_cast<uint32_t>(result));
		const bool  cache_hit = Libs::LibKernel::CapturedDirectory::LastLoadUsedStartupCache();
		const char* relocated = std::getenv("KYTY_PS5_CAPTURED_STORAGE_ROOT");
		LOGF("CAPTURED_STORAGE_READY manifest=%s whole_manifest_sha256_verified=1"
		     " startup_cache_hit=%u source_hash_revalidated=%u load_us=%" PRId64
		     " storage_root=%s\n",
		     manifest, cache_hit ? 1u : 0u, cache_hit ? 0u : 1u, load_us,
		     relocated != nullptr && relocated[0] != '\0' ? relocated : "recorded");
	}
	if (const char* supplement = std::getenv("KYTY_PS5_CAPTURED_STORAGE_SUPPLEMENT");
	    supplement != nullptr) {
		const char* digest = std::getenv("KYTY_PS5_CAPTURED_STORAGE_SUPPLEMENT_SHA256");
		const int   result = Libs::LibKernel::CapturedDirectory::Supplement(
		    Common::PathFromUtf8(supplement), digest ? digest : "");
		if (result != 0)
			EXIT("Captured storage supplement rejected: 0x%08x\n", static_cast<uint32_t>(result));
		LOGF(
		    "CAPTURED_STORAGE_SUPPLEMENT_READY supplement=%s sha256=%s console_observed_inodes=1\n",
		    supplement, digest);
	}

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
	if (Libs::LibKernel::Process::IsExecChild() &&
	    !Libs::LibKernel::Process::InstallExecChildReadOnlyProviders()) {
		return;
	}
	Libs::InitAll(rt->Symbols());
	if (Libs::LibKernel::Process::IsExecChild() &&
	    !Libs::LibKernel::Process::InstallExecChildDescriptors()) {
		return;
	}
	Libs::LibKernel::Process::MarkExecChildStartupStage(6);

	if (!Libs::LibKernel::Process::IsExecChild() &&
	    std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SELF") != nullptr) {
		// validated before /app0 was mounted; recheck against what the loader resolved
		const auto loaded =
		    Libs::LibKernel::FileSystem::GetRealFilename(Common::PathToGenericString(options.elf));
		if (!Libs::LibKernel::Process::RootOriginalSelfIsLoadedFile(loaded)) {
			LOGF("ROOT_ORIGINAL_SELF_LOAD_MISMATCH elf=%s loaded=%s\n",
			     Common::PathToGenericString(options.elf).c_str(),
			     Common::PathToString(loaded).c_str());
			EXIT("root original SELF is not the loaded ELF\n");
		}
		LOGF("ROOT_ORIGINAL_SELF_LOAD_MATCH elf=%s loaded=%s\n",
		     Common::PathToGenericString(options.elf).c_str(),
		     Common::PathToString(loaded).c_str());
	}
	if (std::getenv("KYTY_DIAGNOSTIC_ROOT_SELF_VALIDATE_ONLY") != nullptr) {
		LOGF("ROOT_SELF_VALIDATE_ONLY\n");
		return;
	}

	auto* main_program = LoadElf(options.elf);
	Libs::LibKernel::Process::MarkExecChildStartupStage(7);
	// Needed modules and relocation are the child's own rtld work; the parent's spawn doesn't wait
	// for them.
	Libs::LibKernel::Process::SignalExecChildImageCommitted(rt->GetEntry());
	if (!options.sysroot_dir.empty() && !main_program->elf->IsStaticExec()) {
		rt->LoadNeededModules(main_program);
	}
	Libs::LibKernel::Process::MarkExecChildStartupStage(8);

	const bool relocate_only = std::getenv("KYTY_DIAGNOSTIC_MODULE_RELOCATE_ONLY") != nullptr;
	if (relocate_only || std::getenv("KYTY_DIAGNOSTIC_MODULE_LOAD_ONLY") != nullptr) {
		if (relocate_only) rt->RelocateAll();
		rt->LogExecLoadPhases("load_only");
		LOGF("MODULE_LOAD_ONLY entry=0x%016" PRIx64 " relocated=%u"
		     "\n",
		     main_program->elf->GetEntry(), relocate_only ? 1u : 0u);
		rt->Clear();
		return;
	}

	if (main_program->elf->IsStaticExec() &&
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_LOAD_ONLY") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT STATIC_EXEC_LOAD_ONLY entry=0x%016" PRIx64 "\n",
		     main_program->elf->GetEntry());
		return;
	}
	if (main_program->elf->IsStaticExec() &&
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		EXIT("Unintercepted native static PS5 syscalls cannot execute safely on Windows\n");
	}
	Execute(options.game_patch);
}

} // namespace Emulator
