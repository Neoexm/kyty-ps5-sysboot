// Exercise the production controller with deterministic host output and time.
#include <SDL3/SDL.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
void Check(bool condition, const char* text) {
	if (!condition) {
		std::fprintf(stderr, "ControllerSettingsTests: %s\n", text);
		std::abort();
	}
}

struct Rumble {
	Uint16 large, small;
	Uint32 duration;
};
Uint64                             now = 1000;
std::vector<Rumble>                rumble;
std::vector<Rumble>                haptics;
std::vector<std::array<Uint8, 32>> effects;
bool                               haptics_handles_rumble = false;
SDL_JoystickConnectionState        connection_state = SDL_JOYSTICK_CONNECTION_WIRED;
} // namespace

namespace Fake {
Uint64 GetTicks() {
	return now;
}
SDL_Gamepad* GetGamepadFromID(SDL_JoystickID id) {
	return id == 1 || id == 2 ? reinterpret_cast<SDL_Gamepad*>(static_cast<uintptr_t>(id))
	                          : nullptr;
}
SDL_GamepadType GetGamepadType(SDL_Gamepad*) {
	return SDL_GAMEPAD_TYPE_PS5;
}
SDL_JoystickConnectionState GetGamepadConnectionState(SDL_Gamepad*) {
	return connection_state;
}
bool RumbleGamepad(SDL_Gamepad*, Uint16 large, Uint16 small, Uint32 duration) {
	rumble.push_back({large, small, duration});
	return true;
}
bool SendGamepadEffect(SDL_Gamepad*, const void* data, int size) {
	Check(size == 32, "unexpected DualSense effect size");
	std::array<Uint8, 32> effect {};
	std::memcpy(effect.data(), data, effect.size());
	effects.push_back(effect);
	return true;
}
bool SetGamepadLED(SDL_Gamepad*, Uint8, Uint8, Uint8) {
	return true;
}
bool GamepadHasSensor(SDL_Gamepad*, SDL_SensorType) {
	return false;
}
bool SetGamepadSensorEnabled(SDL_Gamepad*, SDL_SensorType, bool) {
	return true;
}
void CloseGamepad(SDL_Gamepad*) {}
void Delay(Uint32) {}
} // namespace Fake

#define SDL_GetTicks                Fake::GetTicks
#define SDL_GetGamepadFromID        Fake::GetGamepadFromID
#define SDL_GetGamepadType          Fake::GetGamepadType
#define SDL_GetGamepadConnectionState Fake::GetGamepadConnectionState
#define SDL_RumbleGamepad           Fake::RumbleGamepad
#define SDL_SendGamepadEffect       Fake::SendGamepadEffect
#define SDL_SetGamepadLED           Fake::SetGamepadLED
#define SDL_GamepadHasSensor        Fake::GamepadHasSensor
#define SDL_SetGamepadSensorEnabled Fake::SetGamepadSensorEnabled
#define SDL_CloseGamepad            Fake::CloseGamepad
#define SDL_Delay                   Fake::Delay
#include "libs/controller.cpp"
#undef SDL_GetTicks
#undef SDL_GetGamepadFromID
#undef SDL_GetGamepadType
#undef SDL_GetGamepadConnectionState
#undef SDL_RumbleGamepad
#undef SDL_SendGamepadEffect
#undef SDL_SetGamepadLED
#undef SDL_GamepadHasSensor
#undef SDL_SetGamepadSensorEnabled
#undef SDL_CloseGamepad
#undef SDL_Delay

namespace Libs::Controller::DualSenseHaptics {
bool SetVibration(int, uint8_t large_motor, uint8_t small_motor, uint32_t duration_ms) {
	haptics.push_back({large_motor, small_motor, duration_ms});
	return haptics_handles_rumble;
}
void Shutdown() {}
} // namespace Libs::Controller::DualSenseHaptics

namespace Libs::LibKernel {
uint64_t KYTY_SYSV_ABI KernelGetProcessTime() {
	return now * 1000;
}
} // namespace Libs::LibKernel

namespace Loader::Timer {
double GetTimeMs() {
	return static_cast<double>(now);
}
} // namespace Loader::Timer

namespace {
using namespace Libs::Controller;

struct Controller {
	Controller() {
		now                    = 1000;
		haptics_handles_rumble = false;
		connection_state       = SDL_JOYSTICK_CONNECTION_WIRED;
		Initialize();
		Connect(1);
		Check(GetSettingScale(Setting::SpeakerVolume) ==
		              Config::GetControllerSpeakerVolume() / 50.0f &&
		          GetSettingScale(Setting::VibrationIntensity) ==
		              Config::GetControllerVibrationIntensity() / 100.0f &&
		          GetSettingScale(Setting::TriggerEffectIntensity) == 1.0f,
		      "controller initialization retained old settings");
		rumble.clear();
		haptics.clear();
		effects.clear();
	}
	~Controller() { Shutdown(); }
};

DualSenseEffects LastEffect() {
	Check(!effects.empty(), "missing trigger output");
	DualSenseEffects effect {};
	std::memcpy(&effect, effects.back().data(), sizeof(effect));
	return effect;
}

int ZoneStrength(const uint8_t* effect, int zone) {
	const unsigned active = effect[1] | (effect[2] << 8u);
	const uint32_t packed = effect[3] | (effect[4] << 8u) | (effect[5] << 16u) |
	                        (static_cast<uint32_t>(effect[6]) << 24u);
	return (active & (1u << zone)) != 0 ? 1 + ((packed >> (3 * zone)) & 7u) : 0;
}

void SetRumble(uint8_t large, uint8_t small) {
	const PadVibrationParam param {large, small};
	Check(PadSetVibration(1, &param) == 0, "vibration request failed");
}

void TestSettingCycles() {
	Controller controller;
	for (auto setting:
	     {Setting::SpeakerVolume, Setting::VibrationIntensity, Setting::TriggerEffectIntensity}) {
		Check(GetSettingScale(setting) == 1.0f, "initial setting is not strong");
		const std::vector<float> levels = setting == Setting::SpeakerVolume
		                                      ? std::vector<float> {0.0f, 0.02f, 0.12f, 0.42f, 1.0f}
		                                      : std::vector<float> {0.0f, 0.33f, 0.66f, 1.0f};
		for (int cycle = 0; cycle < 2; ++cycle) {
			for (float level: levels) {
				CycleSetting(setting);
				Check(GetSettingScale(setting) == level, "setting did not cycle or wrap");
			}
		}
	}
	CycleSetting(Setting::SpeakerVolume);
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::TriggerEffectIntensity);
}

void TestGlobalControllerLevels() {
	Config::ConfigOptions options;
	options.controller_speaker_volume      = 25;
	options.controller_vibration_intensity = 25;
	Config::Load(options);
	{
		Controller controller;
		Check(GetSettingScale(Setting::SpeakerVolume) == 0.5f &&
		          GetSettingScale(Setting::VibrationIntensity) == 0.25f &&
		          GetSettingScale(Setting::TriggerEffectIntensity) == 1.0f,
		      "global controller levels did not scale their outputs independently");
		SetRumble(200, 100);
		Check(rumble.back().large == 50 * 257 && rumble.back().small == 25 * 257,
		      "global vibration level did not scale rumble");
		CycleSetting(Setting::SpeakerVolume);
		CycleSetting(Setting::VibrationIntensity);
		Check(GetSettingScale(Setting::SpeakerVolume) == 0.0f &&
		          GetSettingScale(Setting::VibrationIntensity) == 0.0f,
		      "cycle hotkeys did not mute globally scaled outputs");
		CycleSetting(Setting::SpeakerVolume);
		CycleSetting(Setting::VibrationIntensity);
		Check(GetSettingScale(Setting::SpeakerVolume) == 0.01f &&
		          GetSettingScale(Setting::VibrationIntensity) == 0.0825f,
		      "cycle hotkeys did not multiply the global controller levels");
		Check(rumble.back().large == 17 * 257 && rumble.back().small == 8 * 257,
		      "cycling vibration did not apply the combined intensity to cached rumble");
	}
	options.controller_speaker_volume = 50;
	Config::Load(options);
	{
		Controller controller;
		Check(GetSettingScale(Setting::SpeakerVolume) == 1.0f,
		      "speaker midpoint did not preserve the previous default level");
	}
	options.controller_speaker_volume = 100;
	Config::Load(options);
	{
		Controller controller;
		Check(GetSettingScale(Setting::SpeakerVolume) == 2.0f,
		      "speaker maximum did not add 6 dB of gain");
		CycleSetting(Setting::SpeakerVolume);
		Check(GetSettingScale(Setting::SpeakerVolume) == 0.0f,
		      "speaker maximum prevented the hotkey from muting");
	}
	options.controller_speaker_volume      = 0;
	options.controller_vibration_intensity = 0;
	Config::Load(options);
	{
		Controller controller;
		Check(GetSettingScale(Setting::SpeakerVolume) == 0.0f &&
		          GetSettingScale(Setting::VibrationIntensity) == 0.0f,
		      "zero global controller levels did not mute outputs");
		SetRumble(200, 100);
		Check(rumble.back().large == 0 && rumble.back().small == 0,
		      "zero global vibration level did not mute motors");
	}
	Config::Load(Config::ConfigOptions {});
}

void TestVibrationLifetime() {
	Controller controller;
	SetRumble(255, 1);
	Check(rumble.size() == 1 && rumble.back().large == 65535 && rumble.back().small == 257 &&
	          rumble.back().duration == 65535,
	      "full vibration changed");
	now += 100;
	CycleSetting(Setting::VibrationIntensity);
	Check(rumble.back().large == 0 && rumble.back().small == 0, "muting did not stop vibration");
	now += 100;
	CycleSetting(Setting::VibrationIntensity);
	Check(rumble.back().large == 84 * 257 && rumble.back().small == 257 &&
	          rumble.back().duration == 65335,
	      "changing intensity lost a small motor or extended the vibration deadline");
	Check(effects.empty(), "vibration intensity resent triggers");
	now              = 1000 + 65535;
	const auto calls = rumble.size();
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::VibrationIntensity);
	Check(rumble.size() == calls || (rumble.back().large == 0 && rumble.back().small == 0),
	      "expired vibration was resurrected");
	SetRumble(0, 0);
	const auto stopped = rumble.size();
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::VibrationIntensity);
	Check(rumble.size() == stopped || (rumble.back().large == 0 && rumble.back().small == 0),
	      "explicitly stopped vibration was resurrected");
}

void TestMaskedTriggersAndValidation() {
	Controller            controller;
	PadTriggerEffectParam param {};
	param.trigger_mask       = 3;
	param.command[0].mode    = 1;
	param.command[0].data[0] = 2;
	param.command[0].data[1] = 8;
	param.command[1].mode    = 2;
	param.command[1].data[0] = 2;
	param.command[1].data[1] = 7;
	param.command[1].data[2] = 6;
	Check(PadSetTriggerEffect(1, &param) == 0, "initial trigger request failed");
	CycleSetting(Setting::TriggerEffectIntensity);
	Check(LastEffect().left_trigger[0] == 5 && LastEffect().right_trigger[0] == 5,
	      "muting did not disable both triggers");
	for (uint32_t mode = 1; mode <= 7; ++mode) {
		auto invalid            = param;
		invalid.command[1]      = {};
		invalid.command[1].mode = mode;
		std::memset(invalid.command[1].data, 255, sizeof(invalid.command[1].data));
		const auto calls = effects.size();
		Check(PadSetTriggerEffect(1, &invalid) == PAD_ERROR_INVALID_ARG && effects.size() == calls,
		      "muting bypassed trigger validation or sent a partial invalid request");
	}
	param.trigger_mask = 4;
	Check(PadSetTriggerEffect(1, &param) == PAD_ERROR_INVALID_ARG, "invalid trigger mask accepted");
	param.trigger_mask       = 1;
	param.command[0].data[1] = 6;
	Check(PadSetTriggerEffect(1, &param) == 0 && LastEffect().enable_bits == 8,
	      "left-only update touched the right trigger");
	CycleSetting(Setting::TriggerEffectIntensity);
	auto effect = LastEffect();
	Check(effect.enable_bits == 12 && effect.left_trigger[0] == 0x21 &&
	          ZoneStrength(effect.left_trigger, 1) == 0 &&
	          ZoneStrength(effect.left_trigger, 2) == 2 && effect.right_trigger[0] == 0x25 &&
	          effect.right_trigger[1] == 0x84 && effect.right_trigger[3] == 1,
	      "masked updates lost a cached trigger or failed to scale its strength");
	CycleSetting(Setting::TriggerEffectIntensity);
	CycleSetting(Setting::TriggerEffectIntensity);
	effect = LastEffect();
	Check(ZoneStrength(effect.left_trigger, 2) == 6 && effect.right_trigger[3] == 5,
	      "restoring strong intensity did not recover original trigger strengths");
	Check(rumble.empty() && haptics.empty(), "trigger intensity resent vibration");
}

void TestIndependentOutputsAndPadSwitch() {
	Controller controller;
	haptics_handles_rumble = true;
	SetRumble(200, 100);
	now += 100;
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::VibrationIntensity);
	Check(rumble.empty() && haptics.back().large == 66 && haptics.back().small == 33 &&
	          haptics.back().duration == 65435,
	      "haptics rumble did not receive scaled motors and remaining duration");
	PadTriggerEffectParam param {};
	param.trigger_mask       = 1;
	param.command[0].mode    = 1;
	param.command[0].data[1] = 8;
	Check(PadSetTriggerEffect(1, &param) == 0, "trigger request failed");
	const auto vibration_calls = haptics.size();
	const auto trigger_calls   = effects.size();
	CycleSetting(Setting::SpeakerVolume);
	Check(haptics.size() == vibration_calls && effects.size() == trigger_calls,
	      "speaker volume resent controller effects");
	Connect(2);
	Disconnect(1);
	Check(GetActiveControllerId() == 2, "active controller did not change");
	haptics.clear();
	effects.clear();
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::TriggerEffectIntensity);
	CycleSetting(Setting::TriggerEffectIntensity);
	Check(effects.empty(), "previous controller's trigger effects leaked to new pad");
	for (const auto& request: haptics) {
		Check(request.large == 0 && request.small == 0,
		      "previous controller's vibration leaked to new pad");
	}
	SetRumble(200, 100);
	Check(PadSetTriggerEffect(1, &param) == 0, "replacement pad trigger request failed");
	EmergencyShutdown();
	Check(GetActiveControllerId() == -1, "released controller remained active");
	haptics.clear();
	effects.clear();
	CycleSetting(Setting::VibrationIntensity);
	CycleSetting(Setting::TriggerEffectIntensity);
	Check(effects.empty(), "released controller received a trigger request");
	for (const auto& request: haptics) {
		Check(request.large == 0 && request.small == 0,
		      "released controller retained a cached vibration");
	}
}

#ifdef _WIN32
void TestPhysicalAttachCount() {
	const auto scope = "controller_attach_" + std::to_string(GetCurrentProcessId()) + "_" +
	                   std::to_string(GetTickCount64());
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str()) == 0,
	      "failed to create physical attach scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
	      "failed to enable physical attach scope");
	Initialize();
	SetHostInputSharedProducer(true);
	GameController reader;
	reader.Connect(HOST_INPUT_CONTROLLER_ID);
	bool connected = false;
	int count = 0;
	reader.GetConnectionInfo(&connected, &count);
	Check(connected && count == 1, "keyboard-only connection count changed");
	PadControllerInformation info {};
	Check(PadGetControllerInformation(1, &info) == 0 && info.connected_count == 1,
	      "keyboard-only pad count changed");

	Connect(1);
	reader.GetConnectionInfo(&connected, &count);
	Check(connected && count == 2, "physical attach was not visible to shared reader");
	g_controller->GetConnectionInfo(&connected, &count);
	Check(connected && count == 2, "physical attach did not update guest connection count");
	Check(PadGetControllerInformation(1, &info) == 0 && info.connected_count == 2,
	      "physical attach did not update guest pad information");
	Connect(1);
	RefreshHostPhysicalConnection();
	Connect(2);
	Disconnect(1);
	reader.GetConnectionInfo(&connected, &count);
	Check(connected && count == 2, "duplicate, remap or second pad changed connection count");

	Disconnect(2);
	reader.GetConnectionInfo(&connected, &count);
	Check(connected && count == 2, "physical detach changed connection count");
	Connect(1);
	reader.GetConnectionInfo(&connected, &count);
	Check(connected && count == 3, "physical reattach was not visible to shared reader");
	g_controller->GetConnectionInfo(&connected, &count);
	Check(connected && count == 3, "physical reattach did not update guest connection count");
	Check(PadGetControllerInformation(1, &info) == 0 && info.connected_count == 3,
	      "physical reattach did not update guest pad information");
	Shutdown();
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", "") == 0,
	      "failed to clear physical attach scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "") == 0,
	      "failed to clear physical attach registry scope");
}

void TestPhysicalInputSharedAcrossProcesses() {
	const auto scope = "controller_settings_" + std::to_string(GetCurrentProcessId()) + "_" +
	                   std::to_string(GetTickCount64());
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str()) == 0,
	      "failed to create shared input scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
	      "failed to enable coordinated input scope");
	{
		Controller controller;
		SetHostInputSharedProducer(true);
		HostInputShared::Reader reader;
		HostInputShared::State  states[8];
		Check(HostInputShared::Read(&reader, states, 8) == 1,
		      "shared input producer did not publish initial state");
		HostPhysicalConnectionInfo physical;
		GetHostPhysicalConnectionInfo(&physical);
		Check(physical.connected && physical.ps5 &&
		          physical.transport == HostConnectionTransport::Wired &&
		          states[0].physical_connected == 1 && states[0].physical_ps5 == 1,
		      "wired PS5 connection metadata was not published");

		Disconnect(1);
		GetHostPhysicalConnectionInfo(&physical);
		Check(!physical.connected && physical.transport == HostConnectionTransport::None,
		      "synthetic keyboard was reported as a physical controller");
		Connect(2);
		SetButton(2, PAD_BUTTON_CROSS, true);
		SetAxis(2, Axis::LeftX, 0);
		SetTouchPad(2, 0, true, 0.5f, 0.5f);
		const auto count = HostInputShared::Read(&reader, states, 8);
		Check(count == 5, "physical controller transition was not forwarded");
		Check(states[0].buttons == 0 && states[0].axes[0] == 128 &&
		          states[1].buttons == 0 && states[1].axes[0] == 128,
		      "controller switch did not publish neutral input");
		Check(states[2].buttons == PAD_BUTTON_CROSS && states[3].axes[0] == 0 &&
		          states[4].touch[0].down == 1,
		      "physical button, axis or touch input was not forwarded");
		SetButton(2, PAD_BUTTON_PS, true);
		Check(HostInputShared::Read(&reader, states, 8) == 1 &&
		          (states[0].buttons & PAD_BUTTON_PS) != 0,
		      "PS button was not forwarded");
		connection_state = SDL_JOYSTICK_CONNECTION_WIRELESS;
		RefreshHostPhysicalConnection();
		Check(HostInputShared::Read(&reader, states, 8) == 1 &&
		          states[0].physical_connected == 1 &&
		          states[0].physical_transport ==
		              static_cast<uint8_t>(HostConnectionTransport::Wireless),
		      "wireless transport change was not published");

		Disconnect(2);
		Check(HostInputShared::Read(&reader, states, 8) == 1 && states[0].buttons == 0 &&
		          states[0].axes[0] == 128 && states[0].touch[0].down == 0 &&
		          states[0].physical_connected == 0 &&
		          states[0].physical_transport ==
		              static_cast<uint8_t>(HostConnectionTransport::None),
		      "unplug did not clear shared physical input");
		SetHostInputSharedProducer(false);
	}
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", "") == 0,
	      "failed to clear shared input scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "") == 0,
	      "failed to clear coordinated input scope");
}

void TestSharedInputProducerExit() {
	const auto scope = "controller_exit_" + std::to_string(GetCurrentProcessId()) + "_" +
	                   std::to_string(GetTickCount64());
	const auto event_name = "Local\\KytyHostInputTest." + scope;
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str()) == 0,
	      "failed to create producer-exit scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
	      "failed to enable producer-exit scope");
	Check(_putenv_s("KYTY_HOST_INPUT_TEST_EVENT", event_name.c_str()) == 0,
	      "failed to set producer-exit event");
	const auto event = CreateEventA(nullptr, TRUE, FALSE, event_name.c_str());
	Check(event != nullptr, "failed to create producer-exit event");

	HostInputShared::State seed;
	Check(HostInputShared::Publish(seed) != 0, "failed to create shared input mapping");
	HostInputShared::Reader reader;
	HostInputShared::State  state[2];
	Check(HostInputShared::Read(&reader, state, 2) == 1,
	      "failed to attach to shared input mapping");

	wchar_t executable[MAX_PATH] {};
	Check(GetModuleFileNameW(nullptr, executable, MAX_PATH) != 0,
	      "failed to find controller test executable");
	std::wstring command = L"\"" + std::wstring(executable) + L"\" --shared-input-child";
	STARTUPINFOW startup {};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION process {};
	Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
	                     nullptr, nullptr, &startup, &process),
	      "failed to start shared input producer");
	CloseHandle(process.hThread);
	bool received = false;
	for (int attempt = 0; attempt < 100; attempt++) {
		if (HostInputShared::Read(&reader, state, 2) == 1 &&
		    state[0].buttons == PAD_BUTTON_PS && state[0].physical_connected == 1) {
			received = true;
			break;
		}
		Sleep(20);
	}
	Check(received, "child producer state did not reach reader");
	Check(SetEvent(event), "failed to release shared input producer");
	Check(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0,
	      "shared input producer did not exit");
	DWORD exit_code = 0;
	Check(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0,
	      "shared input producer failed");
	CloseHandle(process.hProcess);
	Check(HostInputShared::Read(&reader, state, 2) == 1 && state[0].buttons == 0 &&
	          state[0].physical_connected == 0,
	      "dead producer left stale controller state");
	Check(HostInputShared::Read(&reader, state, 2) == 0,
	      "dead producer emitted repeated neutral states");
	HostInputShared::State resumed;
	resumed.buttons = PAD_BUTTON_CROSS;
	Check(HostInputShared::Publish(resumed) != 0 &&
	          HostInputShared::Read(&reader, state, 2) == 1 &&
	          state[0].buttons == PAD_BUTTON_CROSS,
	      "new producer did not resume shared input");
	CloseHandle(event);
	Check(_putenv_s("KYTY_HOST_INPUT_TEST_EVENT", "") == 0,
	      "failed to clear producer-exit event");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", "") == 0,
	      "failed to clear producer-exit scope");
	Check(_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "") == 0,
	      "failed to clear producer-exit registry scope");
}
#endif
} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
	if (argc == 2 && std::strcmp(argv[1], "--shared-input-child") == 0) {
		Libs::Controller::HostInputShared::State state;
		state.buttons = Libs::Controller::PAD_BUTTON_PS;
		state.physical_connected = 1;
		if (Libs::Controller::HostInputShared::Publish(state) == 0) return 2;
		char event_name[256] {};
		if (GetEnvironmentVariableA("KYTY_HOST_INPUT_TEST_EVENT", event_name,
		                            sizeof(event_name)) == 0) return 3;
		const auto event = OpenEventA(SYNCHRONIZE, FALSE, event_name);
		if (event == nullptr) return 4;
		const auto waited = WaitForSingleObject(event, 10000);
		CloseHandle(event);
		return waited == WAIT_OBJECT_0 ? 0 : 5;
	}
#endif
	Config::Initialize();
	TestSettingCycles();
	TestGlobalControllerLevels();
	// Each following test initializes another controller and requires strong defaults.
	TestVibrationLifetime();
	TestMaskedTriggersAndValidation();
	TestIndependentOutputsAndPadSwitch();
#ifdef _WIN32
	TestPhysicalAttachCount();
	TestPhysicalInputSharedAcrossProcesses();
	TestSharedInputProducerExit();
#endif
	Config::Shutdown();
	return 0;
}
