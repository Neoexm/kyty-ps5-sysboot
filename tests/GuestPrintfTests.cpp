#include "libs/guestPrintf.h"
#include "libs/vaContext.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
void Check(bool condition, const char* message) {
	if (!condition) {
		std::fprintf(stderr, "GuestPrintfTests: %s\n", message);
		std::abort();
	}
}

std::string Format(double value, const char* format, size_t capacity, int* written) {
	Libs::VaContext context {};
	char buffer[128] {};
	context.reg_save_area.gp[0] = reinterpret_cast<uint64_t>(buffer);
	context.reg_save_area.gp[1] = capacity;
	context.reg_save_area.gp[2] = reinterpret_cast<uint64_t>(format);
	std::memcpy(&context.reg_save_area.fp[0], &value, sizeof(value));
	context.va_list.gp_offset = 0;
	context.va_list.fp_offset = offsetof(Libs::VaRegSave, fp);
	context.va_list.reg_save_area = &context.reg_save_area;
	context.va_list.overflow_arg_area = nullptr;
	*written = Libs::GetGuestSnprintfCtxFunc()(&context);
	return buffer;
}
}

int main() {
	int written = 0;
	const auto expected = std::string("1.") + std::string(40, '0') + "e+00";
	Check(Format(1.0, "%.40e", 128, &written) == expected, "40 digit exponent format");
	Check(written == static_cast<int>(expected.size()), "40 digit return length");
	const auto fractional = std::string("1.25") + std::string(38, '0') + "e+00";
	Check(Format(1.25, "%.40e", 128, &written) == fractional,
	      "40 digit fractional format");
	Check(written == static_cast<int>(fractional.size()), "fractional return length");
	const auto extended = std::string("1.") + std::string(80, '0') + "e+00";
	Check(Format(1.0, "%.80e", 128, &written) == extended, "80 digit exponent format");
	Check(written == static_cast<int>(extended.size()), "80 digit return length");
	Check(Format(1.0, "%.40e", 8, &written) == expected.substr(0, 7),
	      "truncated exponent format");
	Check(written == static_cast<int>(expected.size()), "truncated return length");
}
