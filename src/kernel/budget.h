#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_BUDGET_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_BUDGET_H_

#include "common/common.h"

#include <functional>
#include <string>

namespace Libs::LibKernel::Budget {
// One resource line as syscalls 568/570 copy it in and out.
struct Entry {
	uint32_t kind;
	uint32_t unit;
	uint64_t limit;
	uint64_t used;
};
using NameIn     = std::function<int(std::string*)>;
using EntriesIn  = std::function<int(Entry*, uint32_t)>;
using EntriesOut = std::function<int(const Entry*, uint32_t)>;
// These return 0 or a POSIX errno, as the 13.60 kernel handlers do.
int Create(bool has_name, uint32_t ptype, uint32_t count, const NameIn& name_in,
           const EntriesIn& entries_in, const EntriesOut& entries_out, int64_t* retval);
int Delete(int32_t id, int64_t* retval);
int GetResourceLimit(int32_t id, const std::function<int(int32_t*)>& count_in,
                     const EntriesOut& entries_out, const std::function<int(int32_t)>& count_out);
// {1,14,0x51,index}: the two builtin budget slots behind GetBuiltinBudget/SetBuiltinBudget.
int Builtin(uint32_t index, uint64_t old_len, uint64_t new_len,
            const std::function<int(int64_t)>& out, const std::function<int(int64_t*)>& in);
void Fork(int parent_pid, int child_pid);
void Exit(int pid);
bool Ptype(int pid, int32_t* ptype);
} // namespace Libs::LibKernel::Budget
#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_BUDGET_H_ */
