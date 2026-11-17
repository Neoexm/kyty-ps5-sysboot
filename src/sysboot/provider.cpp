#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "sysboot/provider.h"

#include <winsock2.h>
#include <windows.h>

#include "kernel/envelopeConsoleProviderProtocol.h"

#include <ws2tcpip.h>
#include <algorithm>
#include <bcrypt.h>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Sysboot {

namespace {

namespace Protocol = Libs::LibKernel::EnvelopeConsoleProtocol;
using nlohmann::json;

constexpr uint32_t public_size      = 0x300;
constexpr uint32_t salt_size        = 0x20;
constexpr uint32_t min_input        = 0x1D1;
constexpr uint32_t overhead         = 0x1D0;
constexpr size_t   rnps_stage_limit = 0x10000;
constexpr size_t   max_request_ids  = 4096;

constexpr int32_t  transport_success        = 0;
constexpr int32_t  transport_malformed      = 1;
constexpr int32_t  transport_unknown        = 2;
constexpr int32_t  transport_unavailable    = 3;
constexpr int32_t  transport_invalid_native = 4;
constexpr int32_t  transport_internal       = 5;
constexpr uint32_t unavailable_result       = 0xFFFFFFEDu;

enum class Io { Ok, Closed, Timeout, Failed };

bool WinsockReady() {
	static const bool ready = [] {
		WSADATA data {};
		return WSAStartup(MAKEWORD(2, 2), &data) == 0;
	}();
	return ready;
}

// 1 ready, 0 deadline passed or cancelled, -1 socket error
int Wait(SOCKET s, bool for_write, uint64_t deadline, const std::atomic<bool>* cancel) {
	for (;;) {
		if (cancel != nullptr && cancel->load()) return 0;
		const uint64_t now = GetTickCount64();
		if (now >= deadline) return 0;
		const uint64_t slice = std::min<uint64_t>(deadline - now, 100);
		fd_set         ready;
		fd_set         failed;
		FD_ZERO(&ready);
		FD_ZERO(&failed);
		FD_SET(s, &ready);
		FD_SET(s, &failed);
		timeval   tv {0, static_cast<long>(slice * 1000)};
		const int n =
		    select(0, for_write ? nullptr : &ready, for_write ? &ready : nullptr, &failed, &tv);
		if (n == SOCKET_ERROR) return -1;
		if (n > 0) return FD_ISSET(s, &failed) ? -1 : 1;
	}
}

Io SendAll(SOCKET s, const uint8_t* data, size_t size, uint64_t deadline,
           const std::atomic<bool>* cancel) {
	while (size != 0) {
		const int w = Wait(s, true, deadline, cancel);
		if (w != 1) return w == 0 ? Io::Timeout : Io::Failed;
		const int n = send(s, reinterpret_cast<const char*>(data),
		                   static_cast<int>(std::min<size_t>(size, 1u << 20)), 0);
		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
			return Io::Failed;
		}
		data += n;
		size -= static_cast<size_t>(n);
	}
	return Io::Ok;
}

Io RecvExact(SOCKET s, uint8_t* data, size_t size, uint64_t deadline,
             const std::atomic<bool>* cancel) {
	while (size != 0) {
		const int w = Wait(s, false, deadline, cancel);
		if (w != 1) return w == 0 ? Io::Timeout : Io::Failed;
		const int n = recv(s, reinterpret_cast<char*>(data),
		                   static_cast<int>(std::min<size_t>(size, 1u << 20)), 0);
		if (n == 0) return Io::Closed;
		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
			return Io::Failed;
		}
		data += n;
		size -= static_cast<size_t>(n);
	}
	return Io::Ok;
}

SOCKET NewSocket(int family) {
	SOCKET s = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
	                      WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (s == INVALID_SOCKET) return s;
	u_long nonblocking = 1;
	ioctlsocket(s, FIONBIO, &nonblocking);
	return s;
}

// key == nullptr gives plain SHA-256
bool Digest(const std::array<uint8_t, 32>* key, const uint8_t* a, size_t a_size, const uint8_t* b,
            size_t b_size, std::array<uint8_t, 32>* out) {
	BCRYPT_ALG_HANDLE  algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash      = nullptr;
	bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
	                                      key != nullptr ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) >= 0;
	if (ok)
		ok = BCryptCreateHash(algorithm, &hash, nullptr, 0,
		                      key != nullptr ? const_cast<PUCHAR>(key->data()) : nullptr,
		                      key != nullptr ? 32 : 0, 0) >= 0;
	if (ok && a_size != 0)
		ok = BCryptHashData(hash, const_cast<PUCHAR>(a), static_cast<ULONG>(a_size), 0) >= 0;
	// bodies are bounded by rnps_max_input_size, so one ULONG chunk is enough
	if (ok && b_size != 0)
		ok = BCryptHashData(hash, const_cast<PUCHAR>(b), static_cast<ULONG>(b_size), 0) >= 0;
	if (ok) ok = BCryptFinishHash(hash, out->data(), 32, 0) >= 0;
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	return ok;
}

std::string Hex(const uint8_t* data, size_t size) {
	static const char digits[] = "0123456789abcdef";
	std::string       text(size * 2, '0');
	for (size_t i = 0; i < size; i++) {
		text[i * 2]     = digits[data[i] >> 4];
		text[i * 2 + 1] = digits[data[i] & 15];
	}
	return text;
}

int Nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

// lowercase only, as the bridge's [0-9a-f] patterns require
bool Unhex(const std::string& text, std::vector<uint8_t>* out) {
	if (text.size() % 2 != 0) return false;
	const size_t base = out->size();
	out->resize(base + text.size() / 2);
	for (size_t i = 0; i < text.size() / 2; i++) {
		const int high = Nibble(text[i * 2]);
		const int low  = Nibble(text[i * 2 + 1]);
		if (high < 0 || low < 0) return false;
		(*out)[base + i] = static_cast<uint8_t>(high << 4 | low);
	}
	return true;
}

bool LowerHexOfLength(const json& value, size_t length) {
	if (!value.is_string()) return false;
	const auto& text = value.get_ref<const std::string&>();
	return text.size() == length &&
	       std::all_of(text.begin(), text.end(), [](char c) { return Nibble(c) >= 0; });
}

// bool is not an int here, matching Python's type(x) is int
bool Int(const json& value, int64_t* out) {
	if (value.is_number_unsigned()) {
		const auto u = value.get<uint64_t>();
		if (u > static_cast<uint64_t>(INT64_MAX)) return false;
		*out = static_cast<int64_t>(u);
		return true;
	}
	if (!value.is_number_integer()) return false;
	*out = value.get<int64_t>();
	return true;
}

bool U32Hex(const json& value, uint32_t* out) {
	if (!value.is_string()) return false;
	const auto& text = value.get_ref<const std::string&>();
	if (text.size() != 10 || text[0] != '0' || text[1] != 'x') return false;
	uint32_t v = 0;
	for (size_t i = 2; i < 10; i++) {
		const int n = Nibble(text[i]);
		if (n < 0) return false;
		v = v << 4 | static_cast<uint32_t>(n);
	}
	*out = v;
	return true;
}

template <size_t N>
bool ExactKeys(const json& value, const char* const (&keys)[N]) {
	if (!value.is_object() || value.size() != N) return false;
	for (const char* key: keys)
		if (!value.contains(key)) return false;
	return true;
}

bool IsOutcomeUnknown(const json& code) {
	return code.is_string() &&
	       (code == "NATIVE_OUTCOME_UNKNOWN" || code == "REMOTE_OUTCOME_UNKNOWN");
}

bool DispatchedTrue(const json& error) {
	const auto it = error.find("dispatched");
	return it != error.end() && it->is_boolean() && it->get<bool>();
}

struct Outcome {
	int32_t              transport = transport_success;
	int32_t              open      = 0;
	int32_t              ioctl     = 0;
	int32_t              close     = 0;
	uint32_t             operation = unavailable_result;
	int32_t              cleanup   = 0;
	uint32_t             dispatch  = Protocol::dispatch_pre;
	std::vector<uint8_t> output;
};

Outcome Plain(int32_t transport, uint32_t dispatch, int32_t cleanup = 0) {
	Outcome o;
	o.transport = transport;
	o.dispatch  = dispatch;
	o.cleanup   = cleanup;
	return o;
}

} // namespace

bool NativeCall(const NativeTarget& target, const char* op, const json& args, uint32_t timeout_ms,
                const std::atomic<bool>* cancel, json* result, json* error) {
	auto fail = [&](const char* code, const char* message, int dispatched,
	                const char* exception = nullptr) {
		*error = json {{"code", code}, {"message", message}};
		if (exception != nullptr) (*error)["exception"] = exception;
		if (dispatched >= 0) (*error)["dispatched"] = dispatched != 0;
		return false;
	};
	if (target.token.size() < 32)
		return fail("MISSING_PREREQUISITE", "Set the payload token file in Preferences.", 0);
	std::string data = json {{"token", target.token}, {"op", op}, {"args", args}}.dump();
	if (data.size() > 262144)
		return fail("REQUEST_TOO_LARGE", "Native request exceeds 262144 bytes.", 0);
	if (!WinsockReady())
		return fail("NATIVE_UNREACHABLE",
		            "Native payload connection failed; verify load, bind address and port.", 0,
		            "OSError");

	const uint64_t deadline = GetTickCount64() + timeout_ms;
	addrinfo       hints {};
	hints.ai_family         = AF_UNSPEC;
	hints.ai_socktype       = SOCK_STREAM;
	hints.ai_protocol       = IPPROTO_TCP;
	addrinfo*         found = nullptr;
	const std::string port  = std::to_string(target.port);
	SOCKET            s     = INVALID_SOCKET;
	Io                io    = Io::Failed;
	if (getaddrinfo(target.host.c_str(), port.c_str(), &hints, &found) == 0) {
		for (addrinfo* a = found; a != nullptr && s == INVALID_SOCKET; a = a->ai_next) {
			s = NewSocket(a->ai_family);
			if (s == INVALID_SOCKET) continue;
			bool connected = connect(s, a->ai_addr, static_cast<int>(a->ai_addrlen)) == 0;
			if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
				const int w        = Wait(s, true, deadline, cancel);
				int       so_error = 0;
				int       len      = sizeof(so_error);
				if (w == 1 && getsockopt(s, SOL_SOCKET, SO_ERROR,
				                         reinterpret_cast<char*>(&so_error), &len) == 0)
					connected = so_error == 0;
				if (w == 0) io = Io::Timeout;
			}
			if (!connected) {
				closesocket(s);
				s = INVALID_SOCKET;
				if (io == Io::Timeout) break;
			}
		}
		freeaddrinfo(found);
	}
	if (s == INVALID_SOCKET) {
		std::fill(data.begin(), data.end(), '\0');
		return fail("NATIVE_UNREACHABLE",
		            "Native payload connection failed; verify load, bind address and port.", 0,
		            io == Io::Timeout ? "TimeoutError" : "OSError");
	}

	const uint32_t       length = static_cast<uint32_t>(data.size());
	std::vector<uint8_t> frame(4 + data.size());
	frame[0] = static_cast<uint8_t>(length >> 24);
	frame[1] = static_cast<uint8_t>(length >> 16);
	frame[2] = static_cast<uint8_t>(length >> 8);
	frame[3] = static_cast<uint8_t>(length);
	std::memcpy(frame.data() + 4, data.data(), data.size());
	std::fill(data.begin(), data.end(), '\0');

	std::vector<uint8_t> reply;
	uint8_t              size_bytes[4] {};
	bool                 too_large = false;
	io                             = SendAll(s, frame.data(), frame.size(), deadline, cancel);
	std::fill(frame.begin(), frame.end(), uint8_t {0});
	if (io == Io::Ok) io = RecvExact(s, size_bytes, 4, deadline, cancel);
	if (io == Io::Ok) {
		const uint32_t size = uint32_t {size_bytes[0]} << 24 | uint32_t {size_bytes[1]} << 16 |
		                      uint32_t {size_bytes[2]} << 8 | size_bytes[3];
		too_large           = size > 2 * 1024 * 1024;
		if (!too_large) {
			reply.resize(size);
			io = RecvExact(s, reply.data(), reply.size(), deadline, cancel);
		}
	}
	closesocket(s);
	if (too_large) return fail("INVALID_RESPONSE", "Native response exceeds 2 MiB.", 1);
	if (io != Io::Ok)
		return fail("NATIVE_OUTCOME_UNKNOWN",
		            "The request was sent but no complete response arrived; inspect console state "
		            "before retrying with the same operation_id.",
		            1,
		            io == Io::Closed    ? "IncompleteReadError"
		            : io == Io::Timeout ? "TimeoutError"
		                                : "OSError");

	const json  response = json::parse(reply.begin(), reply.end(), nullptr, false);
	const char* invalid  = "Native or relay response was invalid; inspect state before retrying.";
	if (!response.is_object()) return fail("INVALID_RESPONSE", invalid, 1);
	const auto ok = response.find("ok");
	if (ok == response.end() || !ok->is_boolean() || !ok->get<bool>()) {
		const auto it      = response.find("error");
		json       details = it != response.end() ? *it : json::object();
		if (!details.is_object() || (details.contains("code") && !details["code"].is_string()) ||
		    (details.contains("message") && !details["message"].is_string()))
			return fail("INVALID_RESPONSE", invalid, 1);
		*error =
		    json {{"code", details.value("code", std::string("NATIVE_ERROR"))},
			      {"message", details.value("message", std::string("Native operation failed."))},
			      {"native", details}};
		if (response.contains("partial_result"))
			(*error)["partial_result"] = response["partial_result"];
		return false;
	}
	const auto it = response.find("result");
	if (it == response.end()) return fail("INVALID_RESPONSE", invalid, 1);
	*result = *it;
	return true;
}

struct ProviderState {
	NativeTarget             target;
	std::string              expected_build_id;
	uint32_t                 native_timeout_ms = 120000;
	std::array<uint8_t, 32>  key {};
	SOCKET                   listener = INVALID_SOCKET;
	uint16_t                 port     = 0;
	std::atomic<bool>        stopping {false};
	std::thread              acceptor;
	std::mutex               threads_mutex;
	std::vector<std::thread> threads;

	std::mutex                                            request_mutex;
	std::unordered_map<uint64_t, std::array<uint8_t, 32>> request_ids;
	std::mutex                                            rnps_mutex;
	std::mutex                                            identity_mutex;
	std::string                                           bound_instance_id;
	std::atomic<uint32_t>                                 completed {0};
	std::atomic<uint32_t>                                 rejected {0};
	std::atomic<uint32_t>                                 unknown {0};

	bool Native(const char* op, const json& args, json* result, json* error) {
		return NativeCall(target, op, args, native_timeout_ms, &stopping, result, error);
	}

	bool Identity(const json& value) {
		const auto build    = value.find("build_id");
		const auto instance = value.find("instance_id");
		if (build == value.end() || !build->is_string() || *build != expected_build_id ||
		    instance == value.end() || !LowerHexOfLength(*instance, 32))
			return false;
		std::lock_guard lock(identity_mutex);
		if (bound_instance_id.empty()) bound_instance_id = instance->get<std::string>();
		return bound_instance_id == instance->get<std::string>();
	}

	Outcome Envelope(uint32_t content_id, uint32_t master_key_version, const uint8_t* public_key,
	                 const uint8_t* salt, const uint8_t* envelope, size_t envelope_size);
	Outcome Rnps(uint64_t request_id, const std::vector<uint8_t>& data);
	int     Remove(std::initializer_list<const std::string*> paths);
	void    Serve(SOCKET client);
};

Outcome ProviderState::Envelope(uint32_t content_id, uint32_t master_key_version,
                                const uint8_t* public_key, const uint8_t* salt,
                                const uint8_t* envelope, size_t envelope_size) {
	const json    args = {{"content_id", content_id},
	                      {"master_key_version", master_key_version},
	                      {"public_key_hex", Hex(public_key, public_size)},
	                      {"salt_hex", Hex(salt, salt_size)},
	                      {"input_hex", Hex(envelope, envelope_size)},
	                      {"want_output", true}};
	json          result;
	json          error;
	const Outcome invalid = Plain(transport_invalid_native, Protocol::dispatch_complete);
	if (!Native("envelope.process", args, &result, &error)) {
		const auto native_it = error.find("native");
		if (native_it != error.end() && native_it->is_object()) {
			const json&              native = *native_it;
			static const char* const keys[] = {
			    "code",        "message",          "errno",        "stage",        "build_id",
			    "instance_id", "credential_errno", "open_errno",   "ioctl_return", "ioctl_errno",
			    "close_errno", "cleanup_errno",    "native_result"};
			if (!ExactKeys(native, keys) || !native["code"].is_string() ||
			    !native["message"].is_string())
				return invalid;
			if (!Identity(native)) return invalid;
			uint32_t operation = 0;
			if (!U32Hex(native["native_result"], &operation)) return invalid;
			const std::string stage =
			    native["stage"].is_string() ? native["stage"].get<std::string>() : "";
			static const char* const stages[] = {"open",
			                                     "ioctl",
			                                     "close",
			                                     "credential_enter",
			                                     "credential_restore",
			                                     "allocation",
			                                     "encoding",
			                                     "sticky_safe_mode"};
			if (std::none_of(std::begin(stages), std::end(stages),
			                 [&](const char* s) { return stage == s; }))
				return invalid;
			int64_t     v[5] {};
			int64_t     ioctl_return = 0;
			int64_t     errno_value  = 0;
			const char* names[5] = {"credential_errno", "open_errno", "ioctl_errno", "close_errno",
			                        "cleanup_errno"};
			bool        typed    = true;
			for (int i = 0; i < 5; i++)
				typed = typed && Int(native[names[i]], &v[i]) && v[i] >= 0 && v[i] <= 0x7FFFFFFF;
			typed = typed && Int(native["errno"], &errno_value) && errno_value >= 0 &&
			        errno_value <= 0x7FFFFFFF;
			typed = typed && Int(native["ioctl_return"], &ioctl_return) &&
			        (ioctl_return == -1 || ioctl_return == 0);
			if (!typed) return invalid;
			const int64_t credential = v[0], open = v[1], ioctl = v[2], close = v[3],
			              cleanup    = v[4];
			const bool    none       = !credential && !open && !ioctl && !close && !cleanup;
			bool          consistent = false;
			if (stage == "credential_enter")
				consistent = errno_value == credential && credential > 0 && !open && !ioctl &&
				             !close && ioctl_return == -1;
			else if (stage == "open")
				consistent = errno_value == open && open > 0 && !credential && !ioctl && !close &&
				             !cleanup && ioctl_return == -1;
			else if (stage == "ioctl")
				consistent = errno_value == ioctl && ioctl > 0 && !credential && !open &&
				             !cleanup && ioctl_return == -1;
			else if (stage == "close")
				consistent = errno_value == close && close > 0 && !credential && !open && !ioctl &&
				             !cleanup && ioctl_return == 0;
			else if (stage == "credential_restore")
				consistent = errno_value == cleanup && cleanup > 0 && !credential &&
				             ((ioctl_return == -1 &&
				               ((open > 0 && !ioctl && !close) || (!open && ioctl > 0))) ||
				              (ioctl_return == 0 && !open && !ioctl));
			else if (stage == "allocation" || stage == "sticky_safe_mode")
				consistent =
				    errno_value > 0 && none && ioctl_return == -1 && operation == 0xFFFFFFFFu;
			else if (stage == "encoding")
				consistent = errno_value > 0 && none && ioctl_return == 0 && operation == 0;
			if (!consistent) return invalid;
			if (stage == "allocation" || stage == "encoding" || stage == "sticky_safe_mode")
				return Plain(transport_internal, Protocol::dispatch_complete);
			if (ioctl_return != 0)
				operation = unavailable_result;
			else if (operation == 0xFFFFFFFFu)
				return invalid;
			Outcome o;
			o.open      = static_cast<int32_t>(open);
			o.ioctl     = static_cast<int32_t>(ioctl);
			o.close     = static_cast<int32_t>(close);
			o.operation = operation;
			o.cleanup   = static_cast<int32_t>(cleanup);
			o.dispatch  = Protocol::dispatch_complete;
			return o;
		}
		const json code = error.value("code", json());
		if (IsOutcomeUnknown(code) || DispatchedTrue(error))
			return Plain(IsOutcomeUnknown(code) ? transport_unknown : transport_invalid_native,
			             Protocol::dispatch_unknown);
		return Plain(transport_unavailable, Protocol::dispatch_pre);
	}

	static const char* const keys[] = {
	    "device",           "ioctl",        "credential_policy", "build_id",
	    "instance_id",      "input_length", "output_length",     "output_requested",
	    "ioctl_return",     "ioctl_errno",  "native_result",     "operation_succeeded",
	    "cleanup_complete", "output_hex"};
	if (!ExactKeys(result, keys) || !Identity(result)) return invalid;
	uint32_t operation = 0;
	if (!U32Hex(result["native_result"], &operation) || operation == 0xFFFFFFFFu) return invalid;
	int64_t input_length = 0, output_length = 0, ioctl_return = 0, ioctl_errno = 0;
	if (!Int(result["input_length"], &input_length) ||
	    !Int(result["output_length"], &output_length) ||
	    !Int(result["ioctl_return"], &ioctl_return) || !Int(result["ioctl_errno"], &ioctl_errno) ||
	    !result["output_requested"].is_boolean() || !result["operation_succeeded"].is_boolean() ||
	    !result["cleanup_complete"].is_boolean())
		return invalid;
	if (result["device"] != "/dev/envelope" || result["ioctl"] != "0xc3483101" ||
	    result["credential_policy"] != "preserve_authid_add_capability_62" ||
	    input_length != static_cast<int64_t>(envelope_size) ||
	    !result["output_requested"].get<bool>() || ioctl_return != 0 || ioctl_errno != 0 ||
	    !result["cleanup_complete"].get<bool>())
		return invalid;
	if (operation != 0) {
		if (result["operation_succeeded"].get<bool>() || output_length != 0 ||
		    result["output_hex"] != "")
			return invalid;
		Outcome o;
		o.operation = operation;
		o.dispatch  = Protocol::dispatch_complete;
		return o;
	}
	const size_t size = envelope_size - overhead;
	if (!result["operation_succeeded"].get<bool>() || output_length != static_cast<int64_t>(size) ||
	    !LowerHexOfLength(result["output_hex"], size * 2))
		return invalid;
	Outcome o;
	o.operation = 0;
	o.dispatch  = Protocol::dispatch_complete;
	Unhex(result["output_hex"].get_ref<const std::string&>(), &o.output);
	return o;
}

int ProviderState::Remove(std::initializer_list<const std::string*> paths) {
	int failed = 0;
	for (const std::string* path: paths) {
		json result;
		json error;
		if (!Native("fs.remove", {{"path", *path}}, &result, &error) || !result.is_object())
			failed = 1;
	}
	return failed;
}

Outcome ProviderState::Rnps(uint64_t request_id, const std::vector<uint8_t>& data) {
	std::lock_guard lock(rnps_mutex);
	char            base[64];
	snprintf(base, sizeof(base), "/data/ps5-mcp/rnps-%016llx",
	         static_cast<unsigned long long>(request_id));
	const std::string input_path  = std::string(base) + ".in";
	const std::string output_path = std::string(base) + ".out";

	// the bridge maps a failed stage read or write the same way: unknown when it may have reached the console
	auto staging_failure = [](const json& error, int cleanup) {
		const json code             = error.value("code", json());
		const bool dispatch_unknown = IsOutcomeUnknown(code) || DispatchedTrue(error);
		return Plain(dispatch_unknown ? transport_unknown : transport_unavailable,
		             dispatch_unknown ? Protocol::dispatch_unknown : Protocol::dispatch_pre,
		             cleanup);
	};

	for (size_t offset = 0; offset < data.size(); offset += rnps_stage_limit) {
		const size_t chunk = std::min(rnps_stage_limit, data.size() - offset);
		const json   args  = {{"path", input_path},
		                      {"offset", std::to_string(offset)},
		                      {"data_hex", Hex(data.data() + offset, chunk)},
		                      {"truncate", offset == 0}};
		json         result;
		json         error;
		bool         ok = Native("fs.write", args, &result, &error);
		if (ok) {
			int64_t written = 0;
			ok = result.is_object() && result.contains("bytes_written") &&
			     Int(result["bytes_written"], &written) && written == static_cast<int64_t>(chunk);
			if (!ok)
				error = {{"code", "INVALID_RESPONSE"},
				         {"message", "rnps staging write acknowledged fewer bytes than sent"},
				         {"dispatched", true}};
		}
		if (!ok) {
			Remove({&input_path});
			return staging_failure(error, 0);
		}
	}

	json          result;
	json          error;
	const Outcome invalid_cleanup_zero =
	    Plain(transport_invalid_native, Protocol::dispatch_complete);
	if (!Native("rnps.decrypt", {{"input_path", input_path}, {"output_path", output_path}}, &result,
	            &error)) {
		const int     cleanup   = Remove({&input_path, &output_path});
		const auto    native_it = error.find("native");
		const Outcome invalid =
		    Plain(transport_invalid_native, Protocol::dispatch_complete, cleanup);
		if (native_it != error.end() && native_it->is_object()) {
			const json&              native = *native_it;
			static const char* const keys[] = {
			    "code",        "message",     "errno",        "stage",       "build_id",
			    "instance_id", "open_errno",  "ioctl_return", "ioctl_errno", "close_errno",
			    "read_errno",  "write_errno", "native_result"};
			if (!ExactKeys(native, keys) || !native["code"].is_string() ||
			    !native["message"].is_string() || !Identity(native))
				return invalid;
			uint32_t operation = 0;
			if (!U32Hex(native["native_result"], &operation)) return invalid;
			const std::string stage =
			    native["stage"].is_string() ? native["stage"].get<std::string>() : "";
			static const char* const stages[] = {"open",  "ioctl",      "close",     "read",
			                                     "write", "allocation", "validation"};
			if (std::none_of(std::begin(stages), std::end(stages),
			                 [&](const char* s) { return stage == s; }))
				return invalid;
			int64_t     v[5] {};
			int64_t     ioctl_return = 0;
			int64_t     errno_value  = 0;
			const char* names[5]     = {"open_errno", "ioctl_errno", "close_errno", "read_errno",
			                            "write_errno"};
			bool        typed        = true;
			for (int i = 0; i < 5; i++)
				typed = typed && Int(native[names[i]], &v[i]) && v[i] >= 0 && v[i] <= 0x7FFFFFFF;
			typed = typed && Int(native["errno"], &errno_value) && errno_value >= 0 &&
			        errno_value <= 0x7FFFFFFF;
			typed = typed && Int(native["ioctl_return"], &ioctl_return) &&
			        (ioctl_return == -1 || ioctl_return == 0);
			if (!typed) return invalid;
			const int64_t open = v[0], ioctl = v[1], close = v[2], read = v[3], write = v[4];
			bool          consistent = false;
			if (stage == "open")
				consistent = errno_value == open && open > 0 && !ioctl && !close && !read &&
				             !write && ioctl_return == -1;
			else if (stage == "ioctl")
				consistent = errno_value == ioctl && ioctl > 0 && !open && !close && !read &&
				             !write && ioctl_return == -1;
			else if (stage == "close")
				consistent = errno_value == close && close > 0 && !open && !ioctl && !read &&
				             !write && ioctl_return == 0;
			else if (stage == "read")
				consistent = errno_value == read && read > 0 && !open && !ioctl && !close &&
				             !write && ioctl_return == -1;
			else if (stage == "write")
				consistent = errno_value == write && write > 0 && !open && !ioctl && !close &&
				             !read && ioctl_return == 0;
			else
				consistent = errno_value > 0 && !open && !ioctl && !close && !read && !write &&
				             ioctl_return == -1;
			if (!consistent) return invalid;
			if (stage == "allocation" || stage == "validation" || stage == "read")
				return Plain(transport_internal, Protocol::dispatch_complete, cleanup);
			if (ioctl_return != 0)
				operation = unavailable_result;
			else if (operation == 0xFFFFFFFFu)
				return invalid;
			Outcome o;
			o.open      = static_cast<int32_t>(open);
			o.ioctl     = static_cast<int32_t>(ioctl);
			o.close     = static_cast<int32_t>(close);
			o.operation = operation;
			o.cleanup   = cleanup;
			o.dispatch  = Protocol::dispatch_complete;
			return o;
		}
		const json code = error.value("code", json());
		if (IsOutcomeUnknown(code) || DispatchedTrue(error))
			return Plain(IsOutcomeUnknown(code) ? transport_unknown : transport_invalid_native,
			             Protocol::dispatch_unknown, cleanup);
		return Plain(transport_unavailable, Protocol::dispatch_pre, cleanup);
	}

	static const char* const keys[] = {
	    "device",      "ioctl",         "credential_policy",   "build_id",
	    "instance_id", "input_length",  "output_length",       "ioctl_return",
	    "ioctl_errno", "native_result", "operation_succeeded", "cleanup_complete"};
	uint32_t    operation = 0;
	int64_t     numbers[4] {};
	bool        valid    = ExactKeys(result, keys) && Identity(result) &&
	                       U32Hex(result["native_result"], &operation) && operation != 0xFFFFFFFFu;
	const char* names[4] = {"input_length", "output_length", "ioctl_return", "ioctl_errno"};
	for (int i = 0; valid && i < 4; i++) {
		json& field = result[names[i]];
		// the payload reports these as decimal strings on some builds
		if (field.is_string() && !field.get_ref<const std::string&>().empty() &&
		    std::all_of(field.get_ref<const std::string&>().begin(),
		                field.get_ref<const std::string&>().end(),
		                [](char c) { return c >= '0' && c <= '9'; })) {
			const std::string text = field.get<std::string>();
			valid                  = text.size() <= 18;
			if (valid) field = std::stoll(text);
		}
		valid = valid && Int(field, &numbers[i]);
	}
	valid = valid && result["operation_succeeded"].is_boolean() &&
	        result["cleanup_complete"].is_boolean();
	valid = valid && result["device"] == "/dev/rnps" && result["ioctl"] == "0xc0105203" &&
	        numbers[0] == static_cast<int64_t>(data.size()) && numbers[2] == 0 && numbers[3] == 0 &&
	        result["cleanup_complete"].get<bool>();
	if (valid && operation != 0) {
		if (result["operation_succeeded"].get<bool>() || numbers[1] != 0) {
			Remove({&input_path, &output_path});
			return invalid_cleanup_zero;
		}
		Outcome o;
		o.operation = operation;
		o.cleanup   = Remove({&input_path, &output_path});
		o.dispatch  = Protocol::dispatch_complete;
		return o;
	}
	valid = valid && result["operation_succeeded"].get<bool>() &&
	        numbers[1] == static_cast<int64_t>(data.size());
	if (!valid) {
		Remove({&input_path, &output_path});
		return invalid_cleanup_zero;
	}

	Outcome o;
	o.output.reserve(data.size());
	json read_error;
	bool read_ok = true;
	for (size_t offset = 0; read_ok && offset < data.size();) {
		const size_t want = std::min(rnps_stage_limit, data.size() - offset);
		json         chunk;
		read_ok =
		    Native("fs.read",
			       {{"path", output_path}, {"offset", std::to_string(offset)}, {"length", want}},
			       &chunk, &read_error);
		if (read_ok) {
			read_ok = chunk.is_object() && chunk.contains("data_hex") &&
			          LowerHexOfLength(chunk["data_hex"], want * 2);
			if (read_ok) Unhex(chunk["data_hex"].get_ref<const std::string&>(), &o.output);
			if (!read_ok)
				read_error = {
				    {"code", "INVALID_RESPONSE"},
				    {"message", "rnps staged output read returned a short or malformed range"},
				    {"dispatched", true}};
		}
		offset += want;
	}
	const int cleanup = Remove({&input_path, &output_path});
	if (!read_ok) return staging_failure(read_error, cleanup);
	o.operation = 0;
	o.cleanup   = cleanup;
	o.dispatch  = Protocol::dispatch_complete;
	return o;
}

void ProviderState::Serve(SOCKET client) {
	const uint64_t started        = GetTickCount64();
	auto           stream_timeout = [&](uint32_t op) {
		return std::min<uint64_t>(native_timeout_ms, op == Protocol::rnps_opcode ? 30000 : 5000);
	};
	auto respond = [&](uint64_t request_id, uint32_t op, Outcome o) {
		if (o.transport || o.open || o.ioctl || o.close || o.operation || o.cleanup ||
		    o.dispatch != Protocol::dispatch_complete)
			o.output.clear();
		Protocol::ResponseHeader header {};
		header.magic              = Protocol::response_magic;
		header.version            = Protocol::version;
		header.header_size        = Protocol::header_size;
		header.total_size         = Protocol::header_size + static_cast<uint32_t>(o.output.size());
		header.opcode             = op;
		header.request_id         = request_id;
		header.transport_status   = o.transport;
		header.native_open_errno  = o.open;
		header.native_ioctl_errno = o.ioctl;
		header.native_close_errno = o.close;
		header.operation_result   = o.operation;
		header.output_size        = static_cast<uint32_t>(o.output.size());
		header.cleanup_status     = o.cleanup;
		header.dispatch_state     = o.dispatch;
		std::array<uint8_t, 32> tag {};
		Digest(&key, reinterpret_cast<const uint8_t*>(&header), sizeof(header), o.output.data(),
		       o.output.size(), &tag);
		header.hmac = tag;
		std::vector<uint8_t> wire(sizeof(header) + o.output.size());
		std::memcpy(wire.data(), &header, sizeof(header));
		if (!o.output.empty())
			std::memcpy(wire.data() + sizeof(header), o.output.data(), o.output.size());
		if (SendAll(client, wire.data(), wire.size(), GetTickCount64() + stream_timeout(op),
		            &stopping) != Io::Ok)
			rejected++;
	};

	std::array<uint8_t, Protocol::header_size> raw {};
	if (RecvExact(client, raw.data(), raw.size(), started + stream_timeout(Protocol::opcode),
	              &stopping) != Io::Ok) {
		rejected++;
		return;
	}
	Protocol::RequestHeader header {};
	std::memcpy(&header, raw.data(), sizeof(header));
	const uint64_t deadline = started + stream_timeout(header.opcode);
	if (header.total_size < Protocol::header_size ||
	    header.total_size > Protocol::header_size + Protocol::rnps_max_input_size) {
		rejected++;
		return;
	}
	std::vector<uint8_t> body(header.total_size - Protocol::header_size);
	uint8_t              extra = 0;
	if (RecvExact(client, body.data(), body.size(), deadline, &stopping) != Io::Ok ||
	    RecvExact(client, &extra, 1, deadline, &stopping) != Io::Closed) {
		rejected++;
		return;
	}
	auto unsigned_header = raw;
	std::fill(unsigned_header.begin() + 0x40, unsigned_header.end(), uint8_t {0});
	std::array<uint8_t, 32> tag {};
	uint8_t                 different = 0;
	if (!Digest(&key, unsigned_header.data(), unsigned_header.size(), body.data(), body.size(),
	            &tag)) {
		rejected++;
		return;
	}
	for (size_t i = 0; i < 32; i++)
		different |= tag[i] ^ header.hmac[i];
	if (different != 0) {
		rejected++;
		return;
	}

	bool valid = header.magic == Protocol::request_magic && header.version == Protocol::version &&
	             header.header_size == Protocol::header_size && !header.reserved0 &&
	             !header.reserved1;
	if (header.opcode == Protocol::opcode)
		valid = valid && header.key_size == public_size && header.salt_size == salt_size &&
		        header.input_size >= min_input && header.input_size <= Protocol::max_input_size &&
		        header.output_capacity == header.input_size - overhead &&
		        header.total_size ==
		            Protocol::header_size + header.key_size + header.salt_size + header.input_size;
	else if (header.opcode == Protocol::rnps_opcode)
		valid = valid && !header.cid && !header.mkv && !header.key_size && !header.salt_size &&
		        header.input_size >= 1 && header.input_size <= Protocol::rnps_max_input_size &&
		        header.output_capacity == header.input_size &&
		        header.total_size == Protocol::header_size + header.input_size;
	else
		valid = false;
	if (!valid) {
		rejected++;
		const uint32_t op =
		    header.opcode == Protocol::rnps_opcode ? Protocol::rnps_opcode : Protocol::opcode;
		respond(header.request_id, op, Plain(transport_malformed, Protocol::dispatch_pre));
		return;
	}

	std::array<uint8_t, 32> digest {};
	Digest(nullptr, raw.data(), raw.size(), body.data(), body.size(), &digest);
	const char* admission = "admitted";
	{
		std::lock_guard lock(request_mutex);
		const auto      it = request_ids.find(header.request_id);
		if (header.request_id == 0)
			admission = "invalid";
		else if (it != request_ids.end())
			admission = it->second == digest ? "duplicate" : "conflict";
		else if (request_ids.size() >= max_request_ids)
			admission = "full";
		else
			request_ids.emplace(header.request_id, digest);
	}
	if (std::strcmp(admission, "admitted") != 0) {
		rejected++;
		const bool duplicate = std::strcmp(admission, "duplicate") == 0;
		if (duplicate) unknown++;
		const int32_t transport = duplicate                             ? transport_unknown
		                          : std::strcmp(admission, "full") == 0 ? transport_unavailable
		                                                                : transport_malformed;
		respond(header.request_id, header.opcode,
		        Plain(transport, duplicate ? Protocol::dispatch_unknown : Protocol::dispatch_pre));
		return;
	}

	Outcome outcome = header.opcode == Protocol::rnps_opcode
	                      ? Rnps(header.request_id, body)
	                      : Envelope(header.cid, header.mkv, body.data(), body.data() + public_size,
	                                 body.data() + public_size + salt_size,
	                                 body.size() - public_size - salt_size);
	if (outcome.dispatch == Protocol::dispatch_unknown)
		unknown++;
	else if (outcome.dispatch == Protocol::dispatch_complete)
		completed++;
	respond(header.request_id, header.opcode, std::move(outcome));
}

EnvelopeProvider::EnvelopeProvider(): m_state(std::make_unique<ProviderState>()) {}

EnvelopeProvider::~EnvelopeProvider() {
	Stop();
}

bool EnvelopeProvider::Start(const NativeTarget& target, const std::string& expected_build_id,
                             uint32_t native_timeout_ms, const std::array<uint8_t, 32>& key,
                             std::wstring* error) {
	auto& s             = *m_state;
	s.target            = target;
	s.expected_build_id = expected_build_id;
	s.native_timeout_ms = native_timeout_ms;
	s.key               = key;
	s.stopping          = false;
	if (!WinsockReady()) {
		*error = L"WSAStartup failed.";
		return false;
	}
	s.listener = NewSocket(AF_INET);
	if (s.listener == INVALID_SOCKET) {
		*error = L"Could not create the loopback provider socket (" +
		         std::to_wstring(WSAGetLastError()) + L").";
		return false;
	}
	BOOL exclusive = TRUE;
	setsockopt(s.listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
	           reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
	sockaddr_in address {};
	address.sin_family      = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int length              = sizeof(address);
	if (bind(s.listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
	    listen(s.listener, SOMAXCONN) != 0 ||
	    getsockname(s.listener, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
		*error = L"Could not listen on 127.0.0.1 for the emulator (" +
		         std::to_wstring(WSAGetLastError()) + L").";
		closesocket(s.listener);
		s.listener = INVALID_SOCKET;
		return false;
	}
	s.port     = ntohs(address.sin_port);
	s.acceptor = std::thread([&s] {
		while (!s.stopping) {
			if (Wait(s.listener, false, GetTickCount64() + 1000, &s.stopping) != 1) continue;
			SOCKET client = accept(s.listener, nullptr, nullptr);
			if (client == INVALID_SOCKET) continue;
			SetHandleInformation(reinterpret_cast<HANDLE>(client), HANDLE_FLAG_INHERIT, 0);
			u_long nonblocking = 1;
			ioctlsocket(client, FIONBIO, &nonblocking);
			std::lock_guard lock(s.threads_mutex);
			s.threads.emplace_back([&s, client] {
				s.Serve(client);
				closesocket(client);
			});
		}
	});
	return true;
}

void EnvelopeProvider::Stop() {
	auto& s = *m_state;
	if (s.listener == INVALID_SOCKET) return;
	s.stopping = true;
	if (s.acceptor.joinable()) s.acceptor.join();
	closesocket(s.listener);
	s.listener = INVALID_SOCKET;
	std::vector<std::thread> threads;
	{
		std::lock_guard lock(s.threads_mutex);
		threads.swap(s.threads);
	}
	for (auto& t: threads)
		t.join();
	SecureZeroMemory(s.key.data(), s.key.size());
}

uint16_t EnvelopeProvider::Port() const {
	return m_state->port;
}

uint32_t EnvelopeProvider::Completed() const {
	return m_state->completed;
}

uint32_t EnvelopeProvider::Rejected() const {
	return m_state->rejected;
}

} // namespace Sysboot
