#include <windows.h>

#include "libs/hostInputMbus.h"
#include "libs/hostInputShared.h"

#include <array>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace Shared = Libs::Controller::HostInputShared;
namespace MbusInput = Libs::Mbus::HostInput;

struct Handle {
	HANDLE value = nullptr;
	Handle()     = default;
	explicit Handle(HANDLE value): value(value) {}
	Handle(const Handle&)            = delete;
	Handle& operator=(const Handle&) = delete;
	~Handle() {
		if (value != nullptr) CloseHandle(value);
	}
};

static void Require(bool condition, const std::string& message) {
	if (!condition) throw std::runtime_error(message);
}

static void SetScope(const std::string& scope) {
	Require(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str()) == 0,
	        "set input scope");
	Require(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", scope.empty() ? "" : "1") == 0,
	        "set coordinated mode");
}

static int RunChild(const std::string& scope) {
	SetScope(scope);
	Shared::State pressed;
	pressed.buttons  = 0x00004010;
	pressed.axes[0]  = 0;
	pressed.touch[0] = {7, 1, 640, 480};
	if (Shared::Publish(pressed) == 0) return 10;

	Shared::State released;
	if (Shared::Publish(released) == 0) return 11;
	Sleep(500);
	return 0;
}

static int Observe(const std::string& scope, uint64_t duration_ms) {
	SetScope(scope);
	Shared::Reader reader;
	Shared::State  states[128];
	const auto     deadline = GetTickCount64() + duration_ms;
	while (GetTickCount64() < deadline) {
		const auto count = Shared::Read(&reader, states, 128);
		for (size_t index = 0; index < count; index++) {
			std::cout << "INPUT buttons=0x" << std::hex << states[index].buttons << std::dec
			          << " left_x=" << states[index].axes[0] << '\n';
		}
		Sleep(5);
	}
	return 0;
}

static void RunPublisher(const std::string& scope,
                         const std::function<void()>& inspect = {}) {
	wchar_t executable[32768] {};
	Require(GetModuleFileNameW(nullptr, executable, 32768) != 0, "executable lookup failed");
	const std::wstring  wide_scope(scope.begin(), scope.end());
	auto                command = L"\"" + std::wstring(executable) + L"\" --child " + wide_scope;
	STARTUPINFOW        startup {sizeof(startup)};
	PROCESS_INFORMATION process {};
	Require(CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
	                       nullptr, nullptr, &startup, &process) != FALSE,
	        "publisher process creation failed");
	Handle process_handle(process.hProcess);
	Handle thread_handle(process.hThread);
	if (inspect) inspect();
	if (WaitForSingleObject(process_handle.value, 5000) == WAIT_TIMEOUT) {
		TerminateProcess(process_handle.value, 12);
		throw std::runtime_error("publisher process timed out");
	}
	DWORD exit_code = 0;
	Require(GetExitCodeProcess(process_handle.value, &exit_code) != FALSE && exit_code == 0,
	        "publisher process failed");
}

static void RunMbusContractTests() {
	Require(MbusInput::IsPadDeviceOpenRequest(MbusInput::VIRTUAL_DEVICE_ID,
	                                         MbusInput::VIRTUAL_DEVICE_TYPE, 0),
	        "captured virtual pad open request was rejected");
	Require(!MbusInput::IsPadDeviceOpenRequest(MbusInput::VIRTUAL_DEVICE_ID, 0, 0) &&
	            !MbusInput::IsPadDeviceOpenRequest(MbusInput::VIRTUAL_DEVICE_ID,
	                                               MbusInput::VIRTUAL_DEVICE_TYPE, 1) &&
	            !MbusInput::IsPadDeviceOpenRequest(MbusInput::VIRTUAL_DEVICE_ID + 1,
	                                               MbusInput::VIRTUAL_DEVICE_TYPE, 0),
	        "non-exact virtual pad open request was accepted");
	std::cout << "PASS exact virtual pad device-open contract\n";

	auto condition = MbusInput::ControllerCondition();
	Require(MbusInput::IsControllerCondition(condition.data()),
	        "exact controller condition was rejected");
	for (const size_t offset: {size_t {0}, size_t {0x0c}, size_t {0x10}, size_t {0xc8},
	                           size_t {0xff}}) {
		auto changed = condition;
		changed[offset] ^= 1;
		Require(!MbusInput::IsControllerCondition(changed.data()),
		        "non-exact controller condition was accepted");
	}
	Require(!MbusInput::IsControllerCondition(nullptr), "null controller condition was accepted");

	std::array<uint8_t, MbusInput::RECORD_SIZE> record {};
	record.fill(0xa5);
	MbusInput::FillControllerRecord(record.data());
	std::array<uint8_t, MbusInput::RECORD_SIZE> expected {};
	std::memcpy(expected.data(), &MbusInput::VIRTUAL_DEVICE_ID,
	            sizeof(MbusInput::VIRTUAL_DEVICE_ID));
	std::memcpy(expected.data() + 0x0c, &MbusInput::CONTROLLER_CLASS,
	            sizeof(MbusInput::CONTROLLER_CLASS));
	std::memcpy(expected.data() + 0x10, &MbusInput::CONTROLLER_SUBTYPE,
	            sizeof(MbusInput::CONTROLLER_SUBTYPE));
	std::memcpy(expected.data() + 0xc8, &MbusInput::CONTROLLER_ASSIGNMENT,
	            sizeof(MbusInput::CONTROLLER_ASSIGNMENT));
	Require(record == expected, "controller record contained unsupported fields");
	Require(MbusInput::VIRTUAL_DEVICE_ID ==
	            static_cast<uint64_t>(static_cast<int64_t>(Libs::Controller::HOST_INPUT_CONTROLLER_ID)),
	        "controller record has a second host-input identity");
	std::cout << "PASS exact MBus controller query and record contract\n";
}

static void RunMbusBondContractTests() {
	Require(MbusInput::VIRTUAL_BOND_DEVICE_ID != MbusInput::VIRTUAL_DEVICE_ID,
	        "virtual BOND reused PSM controller identity");
	auto condition = MbusInput::AllDeviceCondition();
	Require(MbusInput::IsAllDeviceCondition(condition.data()),
	        "original ShellUI all-device condition was rejected");
	Require(!MbusInput::IsAllDeviceCondition(MbusInput::ControllerCondition().data()) &&
	            !MbusInput::IsAllDeviceCondition(nullptr),
	        "different MBus condition was accepted as all-device");
	std::array<uint8_t, MbusInput::RECORD_SIZE> expected_condition {};
	std::memset(expected_condition.data(), 0xff, 16);
	for (const size_t offset: {size_t {0x18}, size_t {0x28}, size_t {0x38}, size_t {0x48},
	                           size_t {0x58}, size_t {0x68}, size_t {0x78}, size_t {0x88},
	                           size_t {0x98}, size_t {0xa8}, size_t {0xb8}}) {
		std::memset(expected_condition.data() + offset, 0xff, 4);
	}
	std::memset(expected_condition.data() + 0xc8, 0xff, 4);
	Require(condition == expected_condition, "all-device condition had unsupported fields");
	for (const size_t offset: {size_t {0}, size_t {0x0f}, size_t {0x18}, size_t {0x1b},
	                           size_t {0x1c}, size_t {0xb8}, size_t {0xc8}, size_t {0xff}}) {
		auto changed = condition;
		changed[offset] ^= 1;
		Require(!MbusInput::IsAllDeviceCondition(changed.data()),
		        "non-exact all-device condition was accepted");
	}

	std::array<uint8_t, MbusInput::RECORD_SIZE> record {};
	record.fill(0xa5);
	Require(MbusInput::IsBondDeviceLookup(MbusInput::VIRTUAL_BOND_DEVICE_ID, record.data(),
	                                      MbusInput::RECORD_SIZE),
	        "virtual BOND by-id lookup was rejected");
	Require(!MbusInput::IsBondDeviceLookup(MbusInput::VIRTUAL_DEVICE_ID, record.data(),
	                                       MbusInput::RECORD_SIZE) &&
	            !MbusInput::IsBondDeviceLookup(MbusInput::VIRTUAL_BOND_DEVICE_ID, nullptr,
	                                           MbusInput::RECORD_SIZE) &&
	            !MbusInput::IsBondDeviceLookup(MbusInput::VIRTUAL_BOND_DEVICE_ID, record.data(),
	                                           MbusInput::RECORD_SIZE - 1),
	        "non-exact BOND by-id lookup was accepted");
	MbusInput::FillBondUsbRecord(record.data());
	std::array<uint8_t, MbusInput::RECORD_SIZE> expected_record {};
	std::memcpy(expected_record.data(), &MbusInput::VIRTUAL_BOND_DEVICE_ID,
	            sizeof(MbusInput::VIRTUAL_BOND_DEVICE_ID));
	std::memcpy(expected_record.data() + 0x08, &MbusInput::BOND_USB_TRANSPORT,
	            sizeof(MbusInput::BOND_USB_TRANSPORT));
	std::memcpy(expected_record.data() + 0x0c, &MbusInput::BOND_CLASS,
	            sizeof(MbusInput::BOND_CLASS));
	Require(record == expected_record, "virtual BOND record contained unsupported fields");
	std::array<uint8_t, MbusInput::RECORD_SIZE * 5> page {};
	page.fill(0xa5);
	int total     = 4;
	int remaining = 0;
	Require(MbusInput::AppendBondUsbRecord(page.data(), 4, 5, &total, &remaining,
	                                       MbusInput::RECORD_SIZE),
	        "BOND record was not appended after four original records");
	Require(total == 5 && remaining == 0,
	        "BOND append returned inconsistent enumeration counts");
	for (size_t offset = 0; offset < MbusInput::RECORD_SIZE * 4; offset++) {
		Require(page[offset] == 0xa5, "BOND append modified an original record");
	}
	Require(std::memcmp(page.data() + MbusInput::RECORD_SIZE * 4, expected_record.data(),
	                    MbusInput::RECORD_SIZE) == 0,
	        "BOND append wrote the wrong final record");

	const auto appended_page = page;
	for (const auto [result, capacity, original_total, original_remaining, size]:
	     {std::array<int, 5> {-1, 5, 4, 0, static_cast<int>(MbusInput::RECORD_SIZE)},
	      std::array<int, 5> {4, 4, 4, 0, static_cast<int>(MbusInput::RECORD_SIZE)},
	      std::array<int, 5> {4, 5, 3, 0, static_cast<int>(MbusInput::RECORD_SIZE)},
	      std::array<int, 5> {4, 5, 5, 0, static_cast<int>(MbusInput::RECORD_SIZE)},
	      std::array<int, 5> {4, 5, 4, 1, static_cast<int>(MbusInput::RECORD_SIZE)},
	      std::array<int, 5> {4, 5, 4, 0, static_cast<int>(MbusInput::RECORD_SIZE) - 1}}) {
		page      = appended_page;
		total     = original_total;
		remaining = original_remaining;
		Require(!MbusInput::AppendBondUsbRecord(page.data(), result, capacity, &total, &remaining,
		                                        static_cast<uint32_t>(size)),
		        "ambiguous BOND append was accepted");
		Require(page == appended_page && total == original_total && remaining == original_remaining,
		        "rejected BOND append changed original results");
	}
	total     = 4;
	remaining = 0;
	Require(!MbusInput::AppendBondUsbRecord(nullptr, 4, 5, &total, &remaining,
	                                        MbusInput::RECORD_SIZE) &&
	            !MbusInput::AppendBondUsbRecord(page.data(), 4, 5, nullptr, &remaining,
	                                            MbusInput::RECORD_SIZE) &&
	            !MbusInput::AppendBondUsbRecord(page.data(), 4, 5, &total, nullptr,
	                                            MbusInput::RECORD_SIZE),
	        "BOND append accepted a null output or count pointer");
	std::cout << "PASS exact ShellUI all-device and virtual BOND lookup contract\n";
}

static void RunTests() {
	RunMbusContractTests();
	RunMbusBondContractTests();
	SetScope({});
	Shared::State standalone;
	Require(Shared::Publish(standalone) == 0, "standalone input created shared state");
	std::cout << "PASS standalone isolation\n";

	const auto scope = "host_input_" + std::to_string(GetCurrentProcessId()) + "_" +
	                   std::to_string(GetTickCount64());
	SetScope(scope);
	Shared::Reader reader;
	Shared::State  states[4];
	Require(Shared::Read(&reader, states, 4) == 0, "fresh input scope was not empty");

	RunPublisher(scope + "_other");
	Require(Shared::Read(&reader, states, 4) == 0, "different input scope leaked state");
	std::cout << "PASS scope isolation\n";

	size_t count = 0;
	RunPublisher(scope, [&] {
		const auto deadline = GetTickCount64() + 400;
		while (GetTickCount64() < deadline && count < 2) {
			count += Shared::Read(&reader, states + count, 4 - count);
			if (count < 2) Sleep(5);
		}
	});
	Require(count == 2, "same-scope input did not preserve press and release");
	Require(states[0].buttons == 0x00004010 && states[0].axes[0] == 0 && states[0].axes[1] == 128 &&
	            states[0].touch[0].down == 1 && states[0].touch[0].id == 7 &&
	            states[0].touch[0].x == 640 && states[0].touch[0].y == 480,
	        "press state was corrupted");
	Require(states[1].buttons == 0 && states[1].axes[0] == 128 && states[1].axes[4] == 0 &&
	            states[1].touch[0].down == 0,
	        "release state was corrupted");
	Require(Shared::Read(&reader, states, 4) == 1 && states[0].buttons == 0,
	        "dead input producer did not clear state");
	Require(Shared::Read(&reader, states, 4) == 0, "input events replayed twice");
	std::cout << "PASS cross-process press, release and neutral axes\n";

	Shared::Reader late_reader;
	const auto     late_count = Shared::Read(&late_reader, states, 4);
	Require(late_count == 1 && states[0].buttons == 0 && states[0].axes[0] == 128,
	        "late reader replayed stale input instead of attaching to current state");
	Require(Shared::Read(&late_reader, states, 4) == 0, "late reader replayed current state twice");
	std::cout << "PASS late reader current-state attachment\n";
}

int main(int argc, char** argv) {
	if (argc == 3 && std::string(argv[1]) == "--child") return RunChild(argv[2]);
	if (argc == 4 && std::string(argv[1]) == "--observe")
		return Observe(argv[2], std::stoull(argv[3]));
	try {
		RunTests();
		std::cout << "PASS all shared host input tests\n";
		return 0;
	} catch (const std::exception& error) {
		std::cerr << "FAIL " << error.what() << '\n';
		return 1;
	}
}
