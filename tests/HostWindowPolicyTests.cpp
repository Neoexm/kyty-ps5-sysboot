#define SDL_MAIN_HANDLED
#include "graphics/presentation/window/hostWindowPolicy.h"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace Policy = Libs::Graphics::HostWindowPolicy;

struct Handle {
	HANDLE value = nullptr;
	Handle() = default;
	explicit Handle(HANDLE value): value(value) {}
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
	~Handle() { if (value != nullptr) CloseHandle(value); }
};

static void Require(bool condition, const std::string& message);

struct Broker {
	HWND value = nullptr;
	std::string previous;
	bool had_previous = false;

	Broker() {
		if (const char* saved = std::getenv("KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW"); saved != nullptr) {
			had_previous = true;
			previous = saved;
		}
		value = CreateWindowExW(0, L"STATIC", L"Kyty broker test",
		                        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE, 0, 0, 640, 360,
		                        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
		Require(value != nullptr, "broker window creation failed");
		const auto text = std::to_string(reinterpret_cast<uintptr_t>(value));
		Require(_putenv_s("KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW", text.c_str()) == 0,
		        "broker environment setup failed");
	}

	~Broker() {
		_putenv_s("KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW", had_previous ? previous.c_str() : "");
		if (value != nullptr) DestroyWindow(value);
	}
};

static void Require(bool condition, const std::string& message) {
	if (!condition) throw std::runtime_error(message);
}

static std::wstring Wide(const std::string& text) {
	return {text.begin(), text.end()};
}

static void Pump() {
	SDL_Event event;
	while (SDL_PollEvent(&event)) {}
}

static bool Until(const std::function<bool()>& condition, DWORD timeout = 5000) {
	const auto end = GetTickCount64() + timeout;
	do {
		Pump();
		if (condition()) return true;
		Sleep(5);
	} while (GetTickCount64() < end);
	return condition();
}

struct Window {
	SDL_Window* value = nullptr;
	HWND native = nullptr;
	Policy::Policy policy;

	Window(std::string image, std::string scope, bool coordinated = true, bool show_services = false):
	    policy(Policy::Select(image, scope, coordinated, show_services)) {
		const auto flags = Policy::InitialFlags(false, policy) | SDL_WINDOW_NOT_FOCUSABLE;
		value = SDL_CreateWindow(("Kyty window policy test " + scope).c_str(), 160, 90, flags);
		Require(value != nullptr, std::string("SDL_CreateWindow: ") + SDL_GetError());
		native = static_cast<HWND>(SDL_GetPointerProperty(SDL_GetWindowProperties(value),
		                                                 SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr));
		Require(native != nullptr, "SDL window has no HWND");
	}

	Window(const Window&) = delete;
	Window& operator=(const Window&) = delete;
	~Window() { if (value != nullptr) SDL_DestroyWindow(value); }

	void Apply() {
		Require(Policy::Apply(value, policy, false), std::string("Apply: ") + SDL_GetError());
		native = static_cast<HWND>(SDL_GetPointerProperty(SDL_GetWindowProperties(value),
		                                                SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr));
		Pump();
	}

	bool Visible() const { return IsWindowVisible(native) != FALSE; }
};

struct SharedState {
	uintptr_t window = 0;
	DWORD status = 1;
};

static int RunChild(const std::string& image, const std::string& scope, const std::string& name) {
	Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, Wide(name + ".state").c_str()));
	Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, Wide(name + ".ready").c_str()));
	Handle stop(OpenEventW(SYNCHRONIZE, FALSE, Wide(name + ".stop").c_str()));
	if (!mapping.value || !ready.value || !stop.value) return 10;
	auto* state = static_cast<SharedState*>(MapViewOfFile(mapping.value, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
	if (state == nullptr) return 11;
	int result = 0;
	try {
		Require(SDL_Init(SDL_INIT_VIDEO), std::string("SDL_Init: ") + SDL_GetError());
		{
			Window window(image, scope);
			Require(!window.Visible(), "coordinated child window was visible before Apply");
			window.Apply();
			state->window = reinterpret_cast<uintptr_t>(window.native);
			state->status = 0;
			SetEvent(ready.value);
			while (WaitForSingleObject(stop.value, 5) == WAIT_TIMEOUT) Pump();
		}
		SDL_Quit();
	} catch (const std::exception& e) {
		std::cerr << "child: " << e.what() << '\n';
		state->status = 12;
		SetEvent(ready.value);
		result = 12;
	}
	UnmapViewOfFile(state);
	return result;
}

struct Child {
	Handle mapping;
	Handle ready;
	Handle stop;
	Handle process;
	SharedState* state = nullptr;

	Child(const std::string& image, const std::string& scope, HANDLE job) {
		static unsigned sequence = 0;
		const auto name = "Local\\KytyWindowPolicyTest." + std::to_string(GetCurrentProcessId()) + "." + std::to_string(++sequence);
		mapping.value = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(SharedState), Wide(name + ".state").c_str());
		ready.value = CreateEventW(nullptr, TRUE, FALSE, Wide(name + ".ready").c_str());
		stop.value = CreateEventW(nullptr, TRUE, FALSE, Wide(name + ".stop").c_str());
		Require(mapping.value && ready.value && stop.value, "child IPC creation failed");
		state = static_cast<SharedState*>(MapViewOfFile(mapping.value, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
		Require(state != nullptr, "child state mapping failed");
		*state = {};
		wchar_t executable[32768] {};
		Require(GetModuleFileNameW(nullptr, executable, 32768) != 0, "executable lookup failed");
		auto command = L"\"" + std::wstring(executable) + L"\" --child " + Wide(image) + L" " + Wide(scope) + L" " + Wide(name);
		STARTUPINFOW startup {sizeof(startup)};
		PROCESS_INFORMATION info {};
		Require(CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
		                       nullptr, nullptr, &startup, &info) != FALSE, "child process creation failed");
		process.value = info.hProcess;
		Handle thread(info.hThread);
		if (!AssignProcessToJobObject(job, process.value)) {
			TerminateProcess(process.value, 13);
			throw std::runtime_error("child job assignment failed");
		}
		Require(ResumeThread(thread.value) != static_cast<DWORD>(-1), "child resume failed");
	}

	Child(const Child&) = delete;
	Child& operator=(const Child&) = delete;
	~Child() {
		if (stop.value) SetEvent(stop.value);
		if (process.value && WaitForSingleObject(process.value, 3000) == WAIT_TIMEOUT) {
			TerminateProcess(process.value, 14);
			WaitForSingleObject(process.value, 3000);
		}
		if (state) UnmapViewOfFile(state);
	}

	void Ready() {
		Require(Until([&] { return WaitForSingleObject(ready.value, 0) == WAIT_OBJECT_0 || WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0; }), "child ready timed out");
		Require(WaitForSingleObject(ready.value, 0) == WAIT_OBJECT_0 && state->status == 0 && state->window != 0, "child window setup failed");
	}

	HWND Native() const { return reinterpret_cast<HWND>(state->window); }
	bool Visible() const { return IsWindowVisible(Native()) != FALSE; }
};

struct VisibleCount {
	std::wstring property;
	unsigned count = 0;
};

static BOOL CALLBACK CountWindow(HWND window, LPARAM parameter) {
	auto& count = *reinterpret_cast<VisibleCount*>(parameter);
	if (GetPropW(window, count.property.c_str()) && IsWindowVisible(window)) count.count++;
	return TRUE;
}

static unsigned CountVisible(const std::string& scope) {
	VisibleCount count {Policy::ScopeName(scope)};
	const auto broker = Policy::BrokerWindow();
	const auto ok = broker != nullptr ? EnumChildWindows(broker, CountWindow, reinterpret_cast<LPARAM>(&count))
	                                  : EnumWindows(CountWindow, reinterpret_cast<LPARAM>(&count));
	Require(ok != FALSE, "window enumeration failed");
	return count.count;
}

static void RunTests(HANDLE job) {
	Broker broker;
	Require(Policy::BrokerWindow() == broker.value, "broker environment did not resolve");
	const auto prefix = "window_policy_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetTickCount64());
	const auto startup_policy = Policy::Select("SCESYSAVCONTROL.ELF", prefix, true, false);
	Require(startup_policy.role == Policy::Role::Startup, "image name matching is not case insensitive");
	Require((Policy::InitialFlags(true, startup_policy) & SDL_WINDOW_HIDDEN) != 0, "startup is not initially hidden");
	Require((Policy::InitialFlags(true, startup_policy) & SDL_WINDOW_FULLSCREEN) == 0, "startup inherited fullscreen");
	const auto standalone_policy = Policy::Select("game.elf", prefix, false, false);
	Require((Policy::InitialFlags(true, standalone_policy) & SDL_WINDOW_FULLSCREEN) != 0, "standalone lost fullscreen");
	Require(Policy::Select("orbis_audiod.elf", prefix, true, true).role == Policy::Role::Standalone, "show-services override ignored");
	Require(Policy::Select("orbis_audiod.elf", "", true, false).role == Policy::Role::Standalone, "unscoped launch was changed");
	std::cout << "PASS selection and flags\n";

	{
		Window standalone("game.elf", prefix + "_standalone", false);
		standalone.Apply();
		Require(Until([&] { return standalone.Visible(); }), "standalone window is hidden");
		Window override("orbis_audiod.elf", prefix + "_override", true, true);
		override.Apply();
		Require(Until([&] { return override.Visible(); }), "show-services override window is hidden");
	}
	std::cout << "PASS standalone and override native visibility\n";

	{
		Child service("orbis_audiod.elf", prefix + "_service", job);
		service.Ready();
		Require(!service.Visible(), "background service window is visible");
	}
	std::cout << "PASS background service remains hidden in child process\n";

	{
		const auto scope = prefix + "_handoff";
		Window startup("SceSysAvControl.elf", scope);
		startup.Apply();
		Require(Until([&] { return startup.Visible(); }), "startup window did not show");
		Require(GetAncestor(startup.native, GA_ROOT) == broker.value,
		        "startup did not use the persistent broker window: child=" +
		            std::to_string(reinterpret_cast<uintptr_t>(startup.native)) + " parent=" +
		            std::to_string(reinterpret_cast<uintptr_t>(GetParent(startup.native))) + " root=" +
		            std::to_string(reinterpret_cast<uintptr_t>(GetAncestor(startup.native, GA_ROOT))) +
		            " broker=" + std::to_string(reinterpret_cast<uintptr_t>(broker.value)));
		Window other_scope("SceSysAvControl.elf", prefix + "_other");
		other_scope.Apply();
		Child compositor("AgcCompositor.elf", scope, job);
		compositor.Ready();
		Require(Until([&] { return compositor.Visible() && !startup.Visible(); }), "compositor did not take over startup display");
		Require(GetAncestor(compositor.Native(), GA_ROOT) == broker.value, "compositor replaced the top-level display window");
		Require(other_scope.Visible(), "handoff hid a different boot scope");
		Child late_startup("SceSysAvControl.elf", scope, job);
		late_startup.Ready();
		Require(!late_startup.Visible(), "late startup stole compositor display");
		Require(CountVisible(scope) == 1, "handoff retained multiple visible display windows");
	}
	std::cout << "PASS cross-process handoff, late startup and scope isolation\n";

	{
		const auto scope = prefix + "_reverse";
		Window compositor("AgcCompositor.elf", scope);
		compositor.Apply();
		Child startup("SceSysAvControl.elf", scope, job);
		startup.Ready();
		Require(compositor.Visible() && !startup.Visible(), "compositor-first startup order is wrong");
		Require(CountVisible(scope) == 1, "compositor-first order has multiple displays");
	}
	std::cout << "PASS compositor-first process order\n";

	{
		const auto scope = prefix + "_replacement";
		Window previous("AgcCompositor.elf", scope);
		previous.Apply();
		Child replacement("AgcCompositor.elf", scope, job);
		replacement.Ready();
		Require(Until([&] { return replacement.Visible() && !previous.Visible(); }), "replacement compositor left the old display visible");
		Require(CountVisible(scope) == 1, "replacement compositor has multiple displays");
	}
	std::cout << "PASS compositor replacement\n";

	for (unsigned attempt = 0; attempt < 3; attempt++) {
		const auto scope = prefix + "_race_" + std::to_string(attempt);
		Child startup("SceSysAvControl.elf", scope, job);
		Child compositor("AgcCompositor.elf", scope, job);
		startup.Ready();
		compositor.Ready();
		Require(Until([&] { return compositor.Visible() && !startup.Visible(); }), "concurrent startup left the wrong display visible");
		Require(CountVisible(scope) == 1, "concurrent startup left duplicate displays");
	}
	std::cout << "PASS concurrent process startup (3 attempts)\n";
}

int main(int argc, char** argv) {
	if (argc == 5 && std::string(argv[1]) == "--child") return RunChild(argv[2], argv[3], argv[4]);
	Handle job(CreateJobObjectW(nullptr, nullptr));
	try {
		Require(job.value != nullptr, "test job creation failed");
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		Require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE, "test job setup failed");
		Require(SDL_Init(SDL_INIT_VIDEO), std::string("SDL_Init: ") + SDL_GetError());
		RunTests(job.value);
		SDL_Quit();
		std::cout << "PASS all host window policy tests\n";
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "FAIL " << e.what() << '\n';
		SDL_Quit();
		return 1;
	}
}
