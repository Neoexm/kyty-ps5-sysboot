#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "kernel/fileSystem.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"
#include "loader/runtimeLinker.h"

#include <array>
#include <mutex>
#include <string>
#include <unordered_map>

namespace Libs {

LIB_VERSION("Sysmodule", 1, "Sysmodule", 1, 1);

namespace LibKernel {
struct ModuleInfoForUnwind;
int KYTY_SYSV_ABI KernelGetModuleInfoForUnwind(uint64_t addr, int flags, ModuleInfoForUnwind* info);
int KYTY_SYSV_ABI KernelLoadModuleByName(const char* module_name, size_t args, const void* argp,
                                         uint32_t flags, int* res);
int KYTY_SYSV_ABI KernelUnloadModuleByHandle(int32_t handle, int* res);
} // namespace LibKernel

namespace Sysmodule {

static KYTY_SYSV_ABI int SysmoduleGetModuleInfoForUnwind(uint64_t addr, int flags,
                                                         LibKernel::ModuleInfoForUnwind* info) {
	return LibKernel::KernelGetModuleInfoForUnwind(addr, flags, info);
}

// libSceSysmodule.sprx 13.60 module table. Deps load back to front, so the module is last and alone
// gets the caller's args.
static std::vector<const char*> SysmoduleNames(uint32_t id) {
	switch (id) {
		case 0x84: return {"libSceFont.native"};
		case 0x85:
			return {"libSceResourceArbitrator", "libSceIpmi", "libSceAvcap2",
			        "libSceVideoRecording.native"};
		case 0x95: return {"libSceIpmi", "libSceIme"};
		case 0x98: return {"libSceFontFt"};
		case 0x99: return {"libSceFreeTypeOt"};
		case 0xd4: return {"libSceHmd"};
		case 0xfb: return {"libSceBluetoothHid"};
		case 0x12a: return {"libSceHmd2"};
		case 0x80000017: return {"libSceHidControl"};
		case 0x8000001a: return {"libSceIpmi", "libSceMbus", "libSceCamera"};
		case 0x8000001f: return {"libSceRegMgr"};
		case 0x80000021: return {"libSceIpmi", "libSceIpmi", "libSceMbus", "libSceAvSetting"};
		case 0x80000022:
			return {"libSceIpmi", "libSceMbus",      "libSceIpmi",    "libSceIpmi",
			        "libSceMbus", "libSceAvSetting", "libSceVideoOut"};
		case 0x80000080:
			return {"libSceIpmi", "libSceMbus",      "libSceIpmi",     "libSceIpmi",
			        "libSceMbus", "libSceAvSetting", "libSceVideoOut", "libSceAgcDriver"};
		case 0x80000086: return {"libSceAgcVsh"};
		case 0x8000008a: return {"libSceComposite"};
		case 0x80000029: return {"libSceDipsw"};
		case 0x800000d3: return {"libScePubSubClientShared"};
		case 0x800000d4: return {"libSceSisrSys"};
		case 0x80000010: return {"libSceIpmi", "libSceRegMgr", "libSceSystemService"};
		case 0x8000008e: return {"libSceShareInternal.native"};
		case 0x80000076: return {"libSceRnpsAppMgr"};
		case 0x800000c5: return {"libScePlayAreaEditor"};
		case 0x800000c6: return {"libSceCloudMessaging"};
		default: return {};
	}
}

// handles of rows loaded by id, by name; the sprx's own table isn't written, so its exports can't
// answer
struct LoadedModule {
	int      handle;
	uint64_t references;
};

static std::recursive_mutex                          g_loaded_mutex;
static std::unordered_map<std::string, LoadedModule> g_loaded;

static bool HasModuleSearchRoot() {
	static constexpr std::array<const char*, 4> roots = {"/system_ex/priv_ex/lib",
	                                                     "/system_ex/common_ex/lib",
	                                                     "/system/priv/lib", "/system/common/lib"};
	for (const auto* root: roots) {
		if (LibKernel::FileSystem::KernelCheckReachability(root) == 0) {
			return true;
		}
	}
	return false;
}

static int SysmoduleLoad(uint32_t id, size_t arg_size, const void* arg, int* ret) {
	// Without a mounted sysroot there are no firmware files, and the HLE libraries are all a game
	// gets.
	if (!HasModuleSearchRoot()) {
		return 0;
	}

	const auto names = SysmoduleNames(id);
	for (size_t i = 0; i < names.size(); i++) {
		const bool self   = i + 1 == names.size();
		int        result = 0;
		const int  handle = LibKernel::KernelLoadModuleByName(names[i], self ? arg_size : 0,
		                                                      self ? arg : nullptr, 0, &result);
		if (self && ret != nullptr) {
			*ret = result;
		}
		if (handle < 0) {
			return handle;
		}
		if (self && (id == 0x84 || id == 0x98)) {
			Common::Singleton<Loader::RuntimeLinker>::Instance()->EnableOriginalFontProvider(
			    handle);
		}

		std::lock_guard lock(g_loaded_mutex);
		const auto      found = g_loaded.find(names[i]);
		if (found != g_loaded.end() && found->second.handle == handle) {
			++found->second.references;
		} else {
			g_loaded[names[i]] = {handle, 1};
		}
	}

	return 0;
}

// Native handle/is-loaded lookup: 0x805a1001 and the handle untouched for an unloaded row, else 0
// and the handle.
static int SysmoduleFind(uint32_t id, int* handle) {
	// Without a mounted sysroot there are no firmware files, and the HLE libraries are all a game
	// gets.
	if (!HasModuleSearchRoot()) {
		return 0;
	}
	if ((id & 0x7fffffffu) == 0) {
		return static_cast<int32_t>(0x805a1000u);
	}

	const auto names = SysmoduleNames(id);
	if (names.empty()) {
		return static_cast<int32_t>(0x805a1001u);
	}

	int loaded_handle = -1;
	{
		std::lock_guard lock(g_loaded_mutex);
		const auto      it = g_loaded.find(names.back());
		if (it == g_loaded.end() || it->second.references == 0)
			return static_cast<int32_t>(0x805a1001u);
		loaded_handle = it->second.handle;
	}
	if (Common::Singleton<Loader::RuntimeLinker>::Instance()->FindProgramById(loaded_handle) ==
	    nullptr) {
		return static_cast<int32_t>(0x805a1001u);
	}
	if (handle != nullptr) {
		*handle = loaded_handle;
	}

	return 0;
}

static KYTY_SYSV_ABI int SysmoduleLoadModule(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return SysmoduleLoad(id, 0, nullptr, nullptr);
}

static KYTY_SYSV_ABI int SysmoduleLoadModuleInternal(uint32_t id) {
	PRINT_NAME();

	LOGF("\t id = 0x%08x\n", id);

	return SysmoduleLoad(id, 0, nullptr, nullptr);
}

static KYTY_SYSV_ABI int SysmoduleUnloadModule(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	if (id == 0) {
		return static_cast<int32_t>(0x805a1000u);
	}
	if (!HasModuleSearchRoot()) {
		return 0;
	}
	if (id != 0x84 && id != 0x98 && id != 0x99) {
		return LibKernel::KERNEL_ERROR_ENOSYS;
	}
	const auto      names = SysmoduleNames(id);
	std::lock_guard lock(g_loaded_mutex);
	const auto      found = g_loaded.find(names.front());
	if (found == g_loaded.end() || found->second.references == 0 ||
	    Common::Singleton<Loader::RuntimeLinker>::Instance()->FindProgramById(
	        found->second.handle) == nullptr) {
		return static_cast<int32_t>(0x805a1001u);
	}
	const int  handle   = found->second.handle;
	int        result   = 0;
	const int  unloaded = LibKernel::KernelUnloadModuleByHandle(handle, &result);
	const auto current  = g_loaded.find(names.front());
	if (current != g_loaded.end() && current->second.handle == handle &&
	    current->second.references != 0) {
		--current->second.references;
	}
	return unloaded;
}

static KYTY_SYSV_ABI int SysmoduleLoadModuleInternalWithArg(uint32_t id, size_t arg_size,
                                                            const void* arg, int reserved,
                                                            int* ret) {
	PRINT_NAME();

	LOGF("\t id       = 0x%08x\n"
	     "\t arg      = 0x%016" PRIx64 "\n"
	     "\t arg_size = %" PRIu64 "\n"
	     "\t reserved = %d\n",
	     id, reinterpret_cast<uint64_t>(arg), static_cast<uint64_t>(arg_size), reserved);

	if (reserved != 0) {
		return static_cast<int32_t>(0x805a1000u);
	}
	if (ret != nullptr) {
		*ret = 0;
	}

	return SysmoduleLoad(id, arg_size, arg, ret);
}

static KYTY_SYSV_ABI int SysmoduleIsLoaded(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return SysmoduleFind(id, nullptr);
}

static KYTY_SYSV_ABI int SysmoduleIsLoadedInternal(uint32_t id) {
	PRINT_NAME();

	const int result = SysmoduleFind(id, nullptr);

	LOGF("\t id = 0x%08x, is_loaded = 0x%08x\n", id, static_cast<uint32_t>(result));

	return result;
}

static KYTY_SYSV_ABI int SysmoduleGetModuleHandleInternal(uint32_t id, int* handle) {
	PRINT_NAME();

	const int result = SysmoduleFind(id, handle);

	LOGF("\t id = 0x%08x, get_handle = 0x%08x\n", id, static_cast<uint32_t>(result));

	return result;
}

} // namespace Sysmodule

LIB_DEFINE(InitSysmodule_1) {
	LIB_FUNC("4fU5yvOkVG4", Sysmodule::SysmoduleGetModuleInfoForUnwind);
	LIB_FUNC("eR2bZFAAU0Q", Sysmodule::SysmoduleUnloadModule);
	LIB_FUNC("hHrGoGoNf+s", Sysmodule::SysmoduleLoadModuleInternalWithArg);
	LIB_FUNC("g8cM39EUZ6o", Sysmodule::SysmoduleLoadModule);
	LIB_FUNC("39iV5E1HoCk", Sysmodule::SysmoduleLoadModuleInternal);
	LIB_FUNC("CU8m+Qs+HN4", LibKernel::KernelLoadModuleByName);
	LIB_FUNC("fMP5NHUOaMk", Sysmodule::SysmoduleIsLoaded);
	LIB_FUNC("ynFKQ5bfGks", Sysmodule::SysmoduleIsLoadedInternal);
	LIB_FUNC("D8cuU4d72xM", Sysmodule::SysmoduleGetModuleHandleInternal);
}

} // namespace Libs
