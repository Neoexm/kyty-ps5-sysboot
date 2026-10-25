#pragma once

#include <SDL3/SDL.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif
namespace Libs::Graphics::HostWindowPolicy {

enum class Role : uintptr_t { Standalone, Service, Startup, Compositor };
#ifdef _WIN32
constexpr UINT FOCUS_VISIBLE_CHILD_MESSAGE = WM_APP + 0x4b;
#endif
struct Policy {
	Role        role = Role::Standalone;
	std::string scope;
};
#ifdef _WIN32
inline std::wstring ScopeName(std::string_view scope) {
	uint64_t hash = 0xcbf29ce484222325ull;
	for (unsigned char c: scope)
		hash = (hash ^ c) * 0x100000001b3ull;
	return L"KytyBootDisplay." + std::to_wstring(hash);
}
struct Handoff {
	const wchar_t*    property;
	HWND              window;
	Role              role;
	bool              compositor = false;
	std::vector<HWND> replace;
};
inline BOOL CALLBACK VisitWindow(HWND window, LPARAM parameter) {
	auto& handoff = *reinterpret_cast<Handoff*>(parameter);
	if (window == handoff.window) return TRUE;
	const auto role = reinterpret_cast<uintptr_t>(GetPropW(window, handoff.property));
	if (role == static_cast<uintptr_t>(Role::Compositor)) handoff.compositor = true;
	if (handoff.role == Role::Compositor && (role == static_cast<uintptr_t>(Role::Startup) ||
	                                         role == static_cast<uintptr_t>(Role::Compositor))) {
		handoff.replace.push_back(window);
	}
	return TRUE;
}
inline HWND BrokerWindow() {
	const char* value = std::getenv("KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW");
	if (value == nullptr || *value == '\0') return nullptr;
	char*      end    = nullptr;
	const auto parsed = std::strtoull(value, &end, 0);
	if (end == value || *end != '\0') return nullptr;
	const auto broker = reinterpret_cast<HWND>(static_cast<uintptr_t>(parsed));
	return IsWindow(broker) != FALSE ? broker : nullptr;
}
inline bool AttachToBroker(HWND window, HWND broker) {
	SetLastError(ERROR_SUCCESS);
	const auto previous = SetParent(window, broker);
	if (previous == nullptr && GetLastError() != ERROR_SUCCESS) return false;
	const auto style = static_cast<DWORD_PTR>(GetWindowLongPtrW(window, GWL_STYLE));
	SetLastError(ERROR_SUCCESS);
	const auto child_style = (style & ~(WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX |
	                                    WS_MAXIMIZEBOX | WS_SYSMENU)) |
	                         WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN;
	if (SetWindowLongPtrW(window, GWL_STYLE, static_cast<LONG_PTR>(child_style)) == 0 &&
	    GetLastError() != ERROR_SUCCESS) {
		return false;
	}
	RECT client {};
	if (GetClientRect(broker, &client) == FALSE) return false;
	return SetWindowPos(window, HWND_TOP, 0, 0, client.right - client.left,
	                    client.bottom - client.top, SWP_FRAMECHANGED | SWP_NOACTIVATE) != FALSE;
}
#endif
inline bool Apply(SDL_Window* window, const Policy& policy, bool fullscreen) {
	if (policy.role == Role::Standalone || policy.role == Role::Service) return true;
#ifdef _WIN32
	const auto native = static_cast<HWND>(SDL_GetPointerProperty(
	    SDL_GetWindowProperties(window), SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr));
	if (native == nullptr) return SDL_SetError("missing native host window");
	const auto property   = ScopeName(policy.scope);
	const auto mutex_name = L"Local\\" + property;
	const auto mutex      = CreateMutexW(nullptr, FALSE, mutex_name.c_str());
	if (mutex == nullptr) return SDL_SetError("host display mutex failed: %lu", GetLastError());
	const auto wait = WaitForSingleObject(mutex, 5000);
	if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
		CloseHandle(mutex);
		return SDL_SetError("host display mutex wait failed: %lu", wait);
	}
	bool ok = SetPropW(native, property.c_str(), reinterpret_cast<HANDLE>(policy.role)) != FALSE;
	if (ok) {
		Handoff    handoff {property.c_str(), native, policy.role};
		const auto broker = BrokerWindow();
		if (broker != nullptr) {
			ok = AttachToBroker(native, broker);
			if (ok)
				ok = EnumChildWindows(broker, VisitWindow, reinterpret_cast<LPARAM>(&handoff)) !=
				     FALSE;
		} else {
			ok = EnumWindows(VisitWindow, reinterpret_cast<LPARAM>(&handoff)) != FALSE;
		}
		if (ok && (policy.role == Role::Compositor || !handoff.compositor)) {
			if (fullscreen && policy.role == Role::Compositor && broker == nullptr) {
				ok = SDL_SetWindowFullscreen(window, true);
			}
			if (ok) ok = SDL_ShowWindow(window);
			if (ok) {
				for (auto old: handoff.replace)
					ShowWindowAsync(old, SW_HIDE);
				if (broker != nullptr) PostMessageW(broker, FOCUS_VISIBLE_CHILD_MESSAGE, 0, 0);
			}
		}
	}
	ReleaseMutex(mutex);
	CloseHandle(mutex);
	return ok;
#else
	return true;
#endif
}
} // namespace Libs::Graphics::HostWindowPolicy
