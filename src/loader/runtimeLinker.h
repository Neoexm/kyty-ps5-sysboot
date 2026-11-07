#ifndef EMULATOR_INCLUDE_EMULATOR_LOADER_RUNTIMELINKER_H_
#define EMULATOR_INCLUDE_EMULATOR_LOADER_RUNTIMELINKER_H_

#include "common/abi.h"
#include "common/common.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "loader/symbolDatabase.h"

#include <filesystem>
#include <memory>
#include <unordered_map>
#include <vector>

namespace Loader {

class Elf64;
struct Elf64_Sym;
struct Elf64_Rela;
class RuntimeLinker;

// Per-OS-thread guest FS base, set before entering the statically linked pthread bootstrap on a
// Kyty guest stack.
void SetSysAvNativeThreadFsBase(uint64_t guest_tls_base);
void SetMiniSyscoreNativeThreadFsBase(uint64_t guest_tls_base);

// fs:[disp] emulation in the exception handler consults this base on exec-child guest threads; 0
// disables it.
void     SetExecNativeThreadFsBase(uint64_t guest_tcb);
uint64_t ExecNativeThreadFsBase();

using module_func_t                          = KYTY_SYSV_ABI int (*)(size_t args, const void* argp);
using application_heap_free_func_t           = KYTY_SYSV_ABI void (*)(void*);
using application_heap_malloc_func_t         = KYTY_SYSV_ABI void* (*)(uint64_t);
using application_heap_posix_memalign_func_t = KYTY_SYSV_ABI int (*)(void**, uint64_t, uint64_t);

struct ModuleId {
	bool operator==(const ModuleId& other) const {
		return version_major == other.version_major && version_minor == other.version_minor &&
		       name == other.name;
	}

	std::string id;
	int         version_major;
	int         version_minor;
	std::string name;
};

struct LibraryId {
	bool operator==(const LibraryId& other) const {
		return version == other.version && name == other.name;
	}

	std::string id;
	int         version;
	std::string name;
};

struct ThreadLocalStorage {
	struct Block {
		uint8_t*                     ptr        = nullptr;
		application_heap_free_func_t free_func  = nullptr;
		bool                         vm_alloc   = false;
		uint64_t                     alloc_size = 0;
	};

	~ThreadLocalStorage();

	uint64_t image_vaddr   = 0;
	uint64_t init_size     = 0;
	uint64_t image_size    = 0;
	uint64_t tcb_offset    = 0;
	uint64_t handler_vaddr = 0;

	std::vector<uint8_t>           init_image;
	std::unordered_map<int, Block> tlss;
	Common::Mutex                  mutex;
};

struct DynamicInfo {
	void*    hash_table      = nullptr;
	uint64_t hash_table_size = 0;

	char*    str_table      = nullptr;
	uint64_t str_table_size = 0;

	Elf64_Sym* symbol_table            = nullptr;
	uint64_t   symbol_table_total_size = 0;
	uint64_t   symbol_table_entry_size = 0;

	uint64_t init_vaddr          = 0;
	uint64_t fini_vaddr          = 0;
	uint64_t init_array_vaddr    = 0;
	uint64_t fini_array_vaddr    = 0;
	uint64_t preinit_array_vaddr = 0;
	uint64_t init_array_size     = 0;
	uint64_t fini_array_size     = 0;
	uint64_t preinit_array_size  = 0;

	Elf64_Rela* jmprela_table      = nullptr;
	uint64_t    jmprela_table_size = 0;

	Elf64_Rela* rela_table            = nullptr;
	uint64_t    rela_table_total_size = 0;
	uint64_t    rela_table_entry_size = 0;

	uint64_t relative_count = 0;

	uint64_t debug   = 0;
	uint64_t textrel = 0;
	uint64_t flags   = 0;

	const char* so_name = nullptr;

	std::vector<ModuleId>  export_modules;
	std::vector<ModuleId>  import_modules;
	std::vector<LibraryId> export_libs;
	std::vector<LibraryId> import_libs;
};

struct Program {
	Program();
	~Program();

	enum class ModuleState { NotStarted, Starting, Started, StartFailed, Stopping, Stopped };

	struct NeededModule {
		std::string name;
		Program*    provider = nullptr;
	};

	int32_t                      unique_id = -1;
	RuntimeLinker*               rt        = nullptr;
	uint32_t                     load_count = 0; // Successful sceKernelLoadStartModule calls.
	bool                            process_owned = false;
	std::vector<NeededModule>       needed_modules;
	ModuleState                     module_state           = ModuleState::NotStarted;
	bool                            native_init_attempted  = false;
	bool                            original_font_provider = false;
	uint32_t                        active_module_calls    = 0;
	uint32_t                        pending_thread_atexit  = 0;
	bool                            module_unload_pending  = false;
	int                             module_start_result    = 0;
	int                             module_stop_result     = 0;
	std::filesystem::path        file_name;
	std::unique_ptr<Elf64>       elf;
	std::unique_ptr<DynamicInfo> dynamic_info;
	uint64_t                     base_vaddr        = 0;
	uint64_t                     base_size         = 0;
	uint64_t                     base_size_aligned = 0;
	uint64_t                     mapped_size       = 0;
	uint64_t instruction_trampoline_size = 0;
	std::vector<uint32_t>           host_exception_code_tokens;
	std::vector<uint64_t>           original_ud2_sites;
	std::unique_ptr<SymbolDatabase> export_symbols;
	std::unique_ptr<SymbolDatabase> import_symbols;
	ThreadLocalStorage              tls;
	bool                            fail_if_global_not_resolved = true;
	bool                            dbg_print_reloc             = false;
	std::vector<uint8_t>            rela_bits;
	uint64_t                        proc_param_vaddr            = 0;
};

class RuntimeLinker {
public:
	RuntimeLinker();
	virtual ~RuntimeLinker();
	void Clear();

	KYTY_CLASS_NO_COPY(RuntimeLinker);

	void DbgDump(const std::string& folder);

	Program* LoadProgram(const std::filesystem::path& elf_name);
	Program* LoadProgram(const std::filesystem::path& elf_name, std::vector<uint8_t> image);
	void     LoadNeededModules(Program* program);
	void     SaveMainProgram(const std::filesystem::path& elf_name);
	void     SaveProgram(Program* program, const std::filesystem::path& elf_name);
	int      AcquireProgram(Program* program);
	int      ReleaseProgram(Program* program, bool* retained);
	int      UnloadProgram(Program* program);
	int32_t  AcquireThreadAtexit(uint64_t address, bool* mapped_owner = nullptr);
	void     ReleaseThreadAtexit(int32_t owner);
	void     ReleaseThreadAtexitByAddr(uint64_t address);

	[[nodiscard]] uint64_t GetEntry();
	[[nodiscard]] uint64_t GetProcParam();

	void RelocateAll();
	void LogExecLoadPhases(const char* point);
	bool EnableOriginalFontProvider(int32_t handle);
	void RelocateProgram(Program* program);

	void  Execute(const std::filesystem::path& game_patch = {});
	int   StartModule(Program* program, size_t args, const void* argp, module_func_t func);
	int   StopModule(Program* program, size_t args, const void* argp, module_func_t func);
	void  StopAllModules();
	void  DeleteTlss(int thread_id);
	void  DiscardTlssForExec(int thread_id);
	void  SetApplicationHeapApi(void* const api[10]);
	void* ApplicationHeapMalloc(uint64_t size);
	void* ApplicationHeapMemalign(uint64_t alignment, uint64_t size);

	void Resolve(const std::string& name, SymbolType type, Program* program, SymbolRecord* out_info,
	             bool* bind_self);

	SymbolDatabase* Symbols() { return m_symbols.get(); }

	static uint64_t ReadFromElf(Program* program, uint64_t vaddr);
	Program*        FindProgramByAddr(uint64_t vaddr);
	bool            GetOriginalUd2ProgramInfo(uint64_t vaddr, uint64_t* base_vaddr,
	                                          std::filesystem::path* file_name);
	Program*        FindProgramById(int32_t id);
	Program*        FindProgramByFileName(const std::filesystem::path& elf_name);

	static uint8_t* TlsGetAddr(Program* program);
	static void     DeleteTls(Program* program, int thread_id);

	void StackTrace(uint64_t frame_ptr, uint64_t stack_ptr);

private:
#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
	friend bool TestAgcPoolMallocOutcomeDiagnostic();
	friend bool TestOriginalPadProviderDiagnosticRouting();
#endif
	Program*    LoadProgramImpl(const std::filesystem::path& elf_name, std::vector<uint8_t>* image);
	static void LoadProgramToMemory(Program* program);
	static void ParseProgramDynamicInfo(Program* program);
	static void CreateSymbolDatabase(Program* program);
	static void Relocate(Program* program);
	static void DeleteProgram(Program* program);
	static void SetupTlsHandler(Program* program);
	void        WriteUnresolvedSymbols();
	void        RefreshNeededModules();
	bool        IsProgramReferenced(Program* program);
	bool        IsThreadAtexitReferenced(Program* program);
	int         ProgramUnloadStatus(Program* program);
	int         AcquireShellUiNpCommonPool();
	int         ReleaseShellUiNpCommonPool();

	static const ModuleId*  FindModule(const Program& program, const std::string& id);
	static const LibraryId* FindLibrary(const Program& program, const std::string& id);

	std::vector<Program*>           m_programs;
	std::vector<Program*>           m_needed_modules;
	std::vector<int32_t>            m_module_start_order;
	bool                            m_stopping_all_modules           = false;
	Program*                        m_shellui_npcommon_pool_provider = nullptr;
	uint64_t                        m_shellui_npcommon_pool_release  = 0;
	bool                            m_shellui_npcommon_pool_owned    = false;
	std::unique_ptr<SymbolDatabase> m_symbols;
	Common::Mutex                   m_mutex;

	application_heap_malloc_func_t         m_application_heap_malloc         = nullptr;
	application_heap_free_func_t           m_application_heap_free           = nullptr;
	application_heap_posix_memalign_func_t m_application_heap_posix_memalign = nullptr;
};

#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
bool TestMainEntryUsesGuestStack();
bool TestInitialModuleStageUsesGuestStack();
bool TestModuleRelocationUsesWritableHostMapping();
bool TestAgcPoolMallocOutcomeDiagnostic();
bool TestOriginalPadProviderDiagnosticRouting();
bool TestNativeLibkernelGetdirentriesTrap();
#endif

} // namespace Loader

#endif /* EMULATOR_INCLUDE_EMULATOR_LOADER_RUNTIMELINKER_H_ */
