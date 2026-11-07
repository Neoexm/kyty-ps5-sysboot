#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#endif

#include "kernel/envelopeConsoleProvider.h"
#include "kernel/envelopeConsoleProviderProtocol.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

namespace {

constexpr uint32_t minimum_timeout_ms = 100;
constexpr uint32_t maximum_timeout_ms = 300000;
constexpr uint32_t default_timeout_ms = 10000;

using EnvelopeConsoleProtocol::RequestHeader;
using EnvelopeConsoleProtocol::ResponseHeader;

struct Configuration {
	uint16_t                port       = 0;
	uint32_t                timeout_ms = default_timeout_ms;
	std::array<uint8_t, 32> token {};
	Configuration()                                = default;
	Configuration(const Configuration&)            = delete;
	Configuration& operator=(const Configuration&) = delete;
	Configuration(Configuration&& other) noexcept
	    : port(other.port), timeout_ms(other.timeout_ms), token(other.token) {
		Wipe(other.token);
	}
	Configuration& operator=(Configuration&& other) noexcept {
		if (this != &other) {
			Wipe(token);
			port       = other.port;
			timeout_ms = other.timeout_ms;
			token      = other.token;
			Wipe(other.token);
		}
		return *this;
	}
	~Configuration() { Wipe(token); }
};

bool ParseUnsigned(const char* text, uint32_t minimum, uint32_t maximum, uint32_t* value) {
	if (text == nullptr || text[0] == '\0') return false;
	uint32_t    parsed = 0;
	const auto* end    = text + std::strlen(text);
	const auto  result = std::from_chars(text, end, parsed, 10);
	if (result.ec != std::errc {} || result.ptr != end || parsed < minimum || parsed > maximum)
		return false;
	*value = parsed;
	return true;
}

int Hex(char value) {
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

bool LoadToken(const char* path, std::array<uint8_t, 32>* token) {
	if (path == nullptr || path[0] == '\0') return false;
	std::ifstream input(path, std::ios::binary);
	if (!input.is_open()) return false;
	input.seekg(0, std::ios::end);
	const auto length = input.tellg();
	if (length < static_cast<std::streamoff>(token->size() * 2) ||
	    length > static_cast<std::streamoff>(token->size() * 2 + 2))
		return false;
	input.seekg(0, std::ios::beg);
	std::string text(static_cast<size_t>(length), '\0');
	input.read(text.data(), length);
	if (!input || input.gcount() != length) {
		Wipe(std::span<uint8_t>(reinterpret_cast<uint8_t*>(text.data()), text.size()));
		return false;
	}
	if (text.size() >= 2 && text[text.size() - 2] == '\r' && text.back() == '\n')
		text.resize(text.size() - 2);
	else if (!text.empty() && text.back() == '\n')
		text.pop_back();
	bool    ok  = text.size() == token->size() * 2;
	uint8_t any = 0;
	for (size_t i = 0; ok && i < token->size(); i++) {
		const int high = Hex(text[i * 2]);
		const int low  = Hex(text[i * 2 + 1]);
		ok             = high >= 0 && low >= 0;
		if (ok) {
			(*token)[i] = static_cast<uint8_t>(high << 4 | low);
			any |= (*token)[i];
		}
	}
	ok = ok && any != 0;
	if (!text.empty())
		Wipe(std::span<uint8_t>(reinterpret_cast<uint8_t*>(text.data()), text.size()));
	return ok;
}

#if defined(_WIN32)

bool HmacSha256(const std::array<uint8_t, 32>& token, const void* header, size_t header_size,
                std::span<const uint8_t> body, std::array<uint8_t, 32>* digest) {
	BCRYPT_ALG_HANDLE    algorithm   = nullptr;
	BCRYPT_HASH_HANDLE   hash        = nullptr;
	DWORD                object_size = 0;
	DWORD                copied      = 0;
	std::vector<uint8_t> object;
	bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
	                                      BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0;
	if (ok) {
		ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
		                       reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied,
		                       0) >= 0 &&
		     copied == sizeof(object_size);
	}
	if (ok) {
		object.resize(object_size);
		ok = BCryptCreateHash(algorithm, &hash, object.data(), static_cast<ULONG>(object.size()),
		                      const_cast<PUCHAR>(token.data()), static_cast<ULONG>(token.size()),
		                      0) >= 0;
	}
	if (ok)
		ok = BCryptHashData(hash, static_cast<PUCHAR>(const_cast<void*>(header)),
		                    static_cast<ULONG>(header_size), 0) >= 0;
	if (ok && !body.empty()) {
		ok = BCryptHashData(hash, const_cast<PUCHAR>(body.data()), static_cast<ULONG>(body.size()),
		                    0) >= 0;
	}
	if (ok) ok = BCryptFinishHash(hash, digest->data(), static_cast<ULONG>(digest->size()), 0) >= 0;
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	if (!object.empty()) SecureZeroMemory(object.data(), object.size());
	return ok;
}

bool ConstantTimeEqual(const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right) {
	uint8_t different = 0;
	for (size_t i = 0; i < left.size(); i++)
		different |= left[i] ^ right[i];
	return different == 0;
}

class Socket {
public:
	Socket() = default;
	explicit Socket(SOCKET value): value(value) {}
	~Socket() {
		if (value != INVALID_SOCKET) closesocket(value);
	}
	Socket(const Socket&)            = delete;
	Socket& operator=(const Socket&) = delete;
	Socket(Socket&& other) noexcept: value(other.value) { other.value = INVALID_SOCKET; }
	Socket& operator=(Socket&& other) noexcept {
		if (this != &other) {
			if (value != INVALID_SOCKET) closesocket(value);
			value       = other.value;
			other.value = INVALID_SOCKET;
		}
		return *this;
	}
	SOCKET Get() const { return value; }

private:
	SOCKET value = INVALID_SOCKET;
};

bool SocketRuntime() {
	static const bool initialized = [] {
		WSADATA data {};
		return WSAStartup(MAKEWORD(2, 2), &data) == 0;
	}();
	return initialized;
}

DWORD RemainingTimeout(uint64_t deadline, int32_t* error) {
	const uint64_t now = GetTickCount64();
	if (now >= deadline) {
		*error = WSAETIMEDOUT;
		return 0;
	}
	return static_cast<DWORD>(
	    std::min<uint64_t>(deadline - now, std::numeric_limits<DWORD>::max()));
}

bool SetSocketTimeout(SOCKET socket, int option, uint64_t deadline, int32_t* error) {
	const DWORD timeout = RemainingTimeout(deadline, error);
	if (timeout == 0) return false;
	if (setsockopt(socket, SOL_SOCKET, option, reinterpret_cast<const char*>(&timeout),
	               sizeof(timeout)) != 0) {
		*error = WSAGetLastError();
		return false;
	}
	return true;
}

Socket Connect(uint16_t port, uint64_t deadline, int32_t* error) {
	if (!SocketRuntime()) {
		*error = WSANOTINITIALISED;
		return {};
	}
	Socket socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
	if (socket.Get() == INVALID_SOCKET) {
		*error = WSAGetLastError();
		return {};
	}
	u_long nonblocking = 1;
	if (ioctlsocket(socket.Get(), FIONBIO, &nonblocking) != 0) {
		*error = WSAGetLastError();
		return {};
	}
	sockaddr_in address {};
	address.sin_family      = AF_INET;
	address.sin_port        = htons(port);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	const int connected =
	    connect(socket.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
	if (connected != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
		*error = WSAGetLastError();
		return {};
	}
	if (connected != 0) {
		const DWORD remaining = RemainingTimeout(deadline, error);
		if (remaining == 0) return {};
		fd_set write_set;
		fd_set error_set;
		FD_ZERO(&write_set);
		FD_ZERO(&error_set);
		FD_SET(socket.Get(), &write_set);
		FD_SET(socket.Get(), &error_set);
		timeval   timeout {static_cast<long>(remaining / 1000),
		                   static_cast<long>((remaining % 1000) * 1000)};
		const int selected = select(0, nullptr, &write_set, &error_set, &timeout);
		if (selected <= 0) {
			*error = selected == 0 ? WSAETIMEDOUT : WSAGetLastError();
			return {};
		}
		int socket_error = 0;
		int size         = sizeof(socket_error);
		if (getsockopt(socket.Get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error),
		               &size) != 0 ||
		    socket_error != 0) {
			*error = socket_error != 0 ? socket_error : WSAGetLastError();
			return {};
		}
	}
	nonblocking = 0;
	if (ioctlsocket(socket.Get(), FIONBIO, &nonblocking) != 0) {
		*error = WSAGetLastError();
		return {};
	}
	return socket;
}

bool SendAll(SOCKET socket, const uint8_t* bytes, size_t size, uint64_t deadline, int32_t* error) {
	while (size != 0) {
		if (!SetSocketTimeout(socket, SO_SNDTIMEO, deadline, error)) return false;
		const int count = send(socket, reinterpret_cast<const char*>(bytes),
		                       static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))), 0);
		if (count <= 0) {
			*error = count == 0 ? WSAECONNRESET : WSAGetLastError();
			return false;
		}
		bytes += count;
		size -= count;
	}
	return true;
}

bool ReceiveAll(SOCKET socket, uint8_t* bytes, size_t size, uint64_t deadline, int32_t* error) {
	while (size != 0) {
		if (!SetSocketTimeout(socket, SO_RCVTIMEO, deadline, error)) return false;
		const int count = recv(socket, reinterpret_cast<char*>(bytes),
		                       static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))), 0);
		if (count <= 0) {
			*error = count == 0 ? WSAECONNRESET : WSAGetLastError();
			return false;
		}
		bytes += count;
		size -= count;
	}
	return true;
}

class ConsoleBackend final: public EnvelopeBackend, public RnpsBackend {
public:
	explicit ConsoleBackend(Configuration configuration): configuration(std::move(configuration)) {}

	bool Probe() noexcept override {
		int32_t        error    = 0;
		const uint64_t deadline = GetTickCount64() + configuration.timeout_ms;
		auto           socket   = Connect(configuration.port, deadline, &error);
		return socket.Get() != INVALID_SOCKET;
	}

	Result Decrypt(std::span<uint8_t> data) noexcept override {
		Result result {Status::ProtocolError, unavailable_result, 0, Provider::Console};
		if (data.empty() || data.size() > EnvelopeConsoleProtocol::rnps_max_input_size ||
		    data.size() > UINT32_MAX - EnvelopeConsoleProtocol::header_size) {
			Wipe(data);
			return result;
		}

		RequestHeader header {};
		header.magic       = EnvelopeConsoleProtocol::request_magic;
		header.version     = EnvelopeConsoleProtocol::version;
		header.header_size = EnvelopeConsoleProtocol::header_size;
		header.total_size =
		    EnvelopeConsoleProtocol::header_size + static_cast<uint32_t>(data.size());
		header.opcode = EnvelopeConsoleProtocol::rnps_opcode;
		if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&header.request_id),
		                    sizeof(header.request_id), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
		    header.request_id == 0) {
			Wipe(data);
			return result;
		}
		result.request_id      = header.request_id;
		header.input_size      = static_cast<uint32_t>(data.size());
		header.output_capacity = static_cast<uint32_t>(data.size());
		if (!HmacSha256(configuration.token, &header, sizeof(header), data, &header.hmac)) {
			Wipe(data);
			return result;
		}

		int32_t        error    = 0;
		const uint64_t deadline = GetTickCount64() + configuration.timeout_ms;
		auto           socket   = Connect(configuration.port, deadline, &error);
		if (socket.Get() == INVALID_SOCKET ||
		    !SendAll(socket.Get(), reinterpret_cast<const uint8_t*>(&header), sizeof(header),
		             deadline, &error) ||
		    !SendAll(socket.Get(), data.data(), data.size(), deadline, &error)) {
			if (error == 0) error = WSAGetLastError();
			Wipe(data);
			result.status           = Status::TransportError;
			result.transport_result = error;
			return result;
		}
		if (shutdown(socket.Get(), SD_SEND) != 0) {
			error = WSAGetLastError();
			Wipe(data);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}

		ResponseHeader response {};
		if (!ReceiveAll(socket.Get(), reinterpret_cast<uint8_t*>(&response), sizeof(response),
		                deadline, &error)) {
			Wipe(data);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		if (response.magic != EnvelopeConsoleProtocol::response_magic ||
		    response.version != EnvelopeConsoleProtocol::version ||
		    response.header_size != EnvelopeConsoleProtocol::header_size ||
		    response.opcode != EnvelopeConsoleProtocol::rnps_opcode ||
		    response.request_id != header.request_id || response.dispatch_state > 2 ||
		    response.transport_status < 0 ||
		    response.transport_status > EnvelopeConsoleProtocol::maximum_transport_status ||
		    response.native_open_errno < 0 || response.native_ioctl_errno < 0 ||
		    response.native_close_errno < 0 || response.cleanup_status < 0 ||
		    response.operation_result == UINT32_MAX || response.output_size > data.size() ||
		    response.total_size != EnvelopeConsoleProtocol::header_size + response.output_size) {
			Wipe(data);
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		std::vector<uint8_t> response_body(response.output_size);
		if (!ReceiveAll(socket.Get(), response_body.data(), response_body.size(), deadline,
		                &error)) {
			Wipe(response_body);
			Wipe(data);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		char trailing = 0;
		if (!SetSocketTimeout(socket.Get(), SO_RCVTIMEO, deadline, &error)) {
			Wipe(response_body);
			Wipe(data);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		const int trailing_count = recv(socket.Get(), &trailing, 1, 0);
		if (trailing_count != 0) {
			Wipe(response_body);
			Wipe(data);
			if (trailing_count < 0) {
				result.status           = Status::TransportError;
				result.transport_result = WSAGetLastError();
			}
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		const auto received_hmac = response.hmac;
		response.hmac.fill(0);
		std::array<uint8_t, 32> expected_hmac {};
		const bool authenticated = HmacSha256(configuration.token, &response, sizeof(response),
		                                      response_body, &expected_hmac) &&
		                           ConstantTimeEqual(received_hmac, expected_hmac);
		Wipe(expected_hmac);
		if (!authenticated) {
			Wipe(response_body);
			Wipe(data);
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}

		result.transport_result   = response.transport_status;
		result.native_open_errno  = response.native_open_errno;
		result.native_ioctl_errno = response.native_ioctl_errno;
		result.native_close_errno = response.native_close_errno;
		result.cleanup_result     = response.cleanup_status;
		result.dispatch_state     = response.dispatch_state;
		result.operation_result   = response.operation_result;
		const bool failed = response.transport_status != 0 || response.dispatch_state != 1 ||
		                    response.native_open_errno != 0 || response.native_ioctl_errno != 0 ||
		                    response.native_close_errno != 0 || response.cleanup_status != 0 ||
		                    response.operation_result != 0;
		if (failed && response.output_size != 0)
			result.status = Status::ProtocolError;
		else if (response.transport_status != 0 || response.dispatch_state != 1)
			result.status = Status::TransportError;
		else if (response.native_open_errno != 0 || response.native_ioctl_errno != 0 ||
		         response.native_close_errno != 0 || response.cleanup_status != 0)
			result.status = Status::OperationError;
		else if (response.operation_result != 0)
			result.status = Status::OperationError;
		else if (response.output_size != data.size())
			result.status = Status::ProtocolError;
		else
			result.status = Status::Success;

		if (result.status == Status::Success) {
			std::copy(response_body.begin(), response_body.end(), data.begin());
			result.written = response_body.size();
		} else {
			Wipe(data);
			if (result.operation_result == 0) result.operation_result = unavailable_result;
		}
		Wipe(response_body);
		return result;
	}

	Result Process(const EnvelopeRequest& request, std::span<uint8_t> output) noexcept override {
		Result result {Status::ProtocolError, unavailable_result, 0, Provider::Console};
		if (request.verification_key.size() != 0x300 || request.context.salt.size() != 0x20 ||
		    request.envelope.size() < 0x1d1 ||
		    request.envelope.size() > EnvelopeConsoleProtocol::max_input_size ||
		    request.output_capacity != output.size() ||
		    output.size() > EnvelopeConsoleProtocol::max_input_size ||
		    output.size() != request.envelope.size() - 0x1d0 ||
		    request.envelope.size() > UINT32_MAX - EnvelopeConsoleProtocol::header_size - 0x320) {
			Wipe(output);
			return result;
		}

		RequestHeader header {};
		header.magic       = EnvelopeConsoleProtocol::request_magic;
		header.version     = EnvelopeConsoleProtocol::version;
		header.header_size = EnvelopeConsoleProtocol::header_size;
		header.total_size  = EnvelopeConsoleProtocol::header_size + 0x320 +
		                     static_cast<uint32_t>(request.envelope.size());
		header.opcode      = EnvelopeConsoleProtocol::opcode;
		if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&header.request_id),
		                    sizeof(header.request_id), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
		    header.request_id == 0) {
			Wipe(output);
			return result;
		}
		header.cid             = request.context.cid;
		header.mkv             = request.context.mkv;
		header.key_size        = 0x300;
		header.salt_size       = 0x20;
		header.input_size      = static_cast<uint32_t>(request.envelope.size());
		header.output_capacity = static_cast<uint32_t>(output.size());

		std::vector<uint8_t> body;
		body.reserve(0x320 + request.envelope.size());
		body.insert(body.end(), request.verification_key.begin(), request.verification_key.end());
		body.insert(body.end(), request.context.salt.begin(), request.context.salt.end());
		body.insert(body.end(), request.envelope.begin(), request.envelope.end());
		if (!HmacSha256(configuration.token, &header, sizeof(header), body, &header.hmac)) {
			Wipe(body);
			Wipe(output);
			return result;
		}

		int32_t        error    = 0;
		const uint64_t deadline = GetTickCount64() + configuration.timeout_ms;
		auto           socket   = Connect(configuration.port, deadline, &error);
		if (socket.Get() == INVALID_SOCKET ||
		    !SendAll(socket.Get(), reinterpret_cast<const uint8_t*>(&header), sizeof(header),
		             deadline, &error) ||
		    !SendAll(socket.Get(), body.data(), body.size(), deadline, &error)) {
			if (error == 0) error = WSAGetLastError();
			Wipe(body);
			Wipe(output);
			result.status           = Status::TransportError;
			result.transport_result = error;
			return result;
		}
		if (shutdown(socket.Get(), SD_SEND) != 0) {
			error = WSAGetLastError();
			Wipe(body);
			Wipe(output);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		Wipe(body);

		ResponseHeader response {};
		if (!ReceiveAll(socket.Get(), reinterpret_cast<uint8_t*>(&response), sizeof(response),
		                deadline, &error)) {
			Wipe(output);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		if (response.magic != EnvelopeConsoleProtocol::response_magic ||
		    response.version != EnvelopeConsoleProtocol::version ||
		    response.header_size != EnvelopeConsoleProtocol::header_size ||
		    response.opcode != EnvelopeConsoleProtocol::opcode ||
		    response.request_id != header.request_id || response.dispatch_state > 2 ||
		    response.transport_status < 0 ||
		    response.transport_status > EnvelopeConsoleProtocol::maximum_transport_status ||
		    response.native_open_errno < 0 || response.native_ioctl_errno < 0 ||
		    response.native_close_errno < 0 || response.cleanup_status < 0 ||
		    response.operation_result == UINT32_MAX || response.output_size > output.size() ||
		    response.total_size != EnvelopeConsoleProtocol::header_size + response.output_size) {
			Wipe(output);
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		std::vector<uint8_t> response_body(response.output_size);
		if (!ReceiveAll(socket.Get(), response_body.data(), response_body.size(), deadline,
		                &error)) {
			Wipe(response_body);
			Wipe(output);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		char trailing = 0;
		if (!SetSocketTimeout(socket.Get(), SO_RCVTIMEO, deadline, &error)) {
			Wipe(response_body);
			Wipe(output);
			result.status           = Status::TransportError;
			result.transport_result = error;
			result.dispatch_state   = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		const int trailing_count = recv(socket.Get(), &trailing, 1, 0);
		if (trailing_count != 0) {
			Wipe(response_body);
			Wipe(output);
			if (trailing_count < 0) {
				result.status           = Status::TransportError;
				result.transport_result = WSAGetLastError();
			}
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}
		const auto received_hmac = response.hmac;
		response.hmac.fill(0);
		std::array<uint8_t, 32> expected_hmac {};
		const bool authenticated = HmacSha256(configuration.token, &response, sizeof(response),
		                                      response_body, &expected_hmac) &&
		                           ConstantTimeEqual(received_hmac, expected_hmac);
		Wipe(expected_hmac);
		if (!authenticated) {
			Wipe(response_body);
			Wipe(output);
			result.dispatch_state = EnvelopeConsoleProtocol::dispatch_unknown;
			return result;
		}

		result.transport_result   = response.transport_status;
		result.native_open_errno  = response.native_open_errno;
		result.native_ioctl_errno = response.native_ioctl_errno;
		result.native_close_errno = response.native_close_errno;
		result.cleanup_result     = response.cleanup_status;
		result.dispatch_state     = response.dispatch_state;
		result.operation_result   = response.operation_result;
		const bool failed = response.transport_status != 0 || response.dispatch_state != 1 ||
		                    response.native_open_errno != 0 || response.native_ioctl_errno != 0 ||
		                    response.native_close_errno != 0 || response.cleanup_status != 0 ||
		                    response.operation_result != 0;
		if (failed && response.output_size != 0)
			result.status = Status::ProtocolError;
		else if (response.transport_status != 0 || response.dispatch_state != 1)
			result.status = Status::TransportError;
		else if (response.native_open_errno != 0 || response.native_ioctl_errno != 0 ||
		         response.native_close_errno != 0 || response.cleanup_status != 0)
			result.status = Status::OperationError;
		else if (response.operation_result != 0)
			result.status = Status::OperationError;
		else if (response.output_size != output.size())
			result.status = Status::ProtocolError;
		else
			result.status = Status::Success;

		if (result.status == Status::Success) {
			std::copy(response_body.begin(), response_body.end(), output.begin());
			result.written = response_body.size();
		} else {
			Wipe(output);
			if (result.operation_result == 0) result.operation_result = unavailable_result;
		}
		Wipe(response_body);
		return result;
	}

private:
	Configuration configuration;
};

#endif

} // namespace

ConfigurationStatus CreateConsoleProviderFromEnvironment(std::shared_ptr<EnvelopeBackend>* provider,
                                                         std::string*                      error) {
	if (provider == nullptr) return ConfigurationStatus::Invalid;
	const char* port_text    = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_PORT");
	const char* token_path   = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE");
	const char* timeout_text = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS");
	if (port_text == nullptr && token_path == nullptr && timeout_text == nullptr)
		return ConfigurationStatus::NotRequested;
#if defined(_WIN32)
	Configuration configuration;
	uint32_t      port = 0;
	if (!ParseUnsigned(port_text, 1, 65535, &port)) {
		if (error != nullptr) *error = "invalid loopback provider port";
		return ConfigurationStatus::Invalid;
	}
	configuration.port = static_cast<uint16_t>(port);
	if (timeout_text != nullptr && !ParseUnsigned(timeout_text, minimum_timeout_ms,
	                                              maximum_timeout_ms, &configuration.timeout_ms)) {
		if (error != nullptr) *error = "invalid loopback provider timeout";
		return ConfigurationStatus::Invalid;
	}
	if (!LoadToken(token_path, &configuration.token)) {
		if (error != nullptr) *error = "invalid loopback provider token file";
		return ConfigurationStatus::Invalid;
	}
	*provider = std::make_shared<ConsoleBackend>(std::move(configuration));
	return ConfigurationStatus::Configured;
#else
	if (error != nullptr) *error = "console provider is only implemented on Windows";
	return ConfigurationStatus::Invalid;
#endif
}

ConfigurationStatus CreateConsoleRnpsProviderFromEnvironment(std::shared_ptr<RnpsBackend>* provider,
                                                             std::string*                  error) {
	if (provider == nullptr) return ConfigurationStatus::Invalid;
	const char* port_text    = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_PORT");
	const char* token_path   = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE");
	const char* timeout_text = std::getenv("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS");
	if (port_text == nullptr && token_path == nullptr && timeout_text == nullptr)
		return ConfigurationStatus::NotRequested;
#if defined(_WIN32)
	Configuration configuration;
	uint32_t      port = 0;
	if (!ParseUnsigned(port_text, 1, 65535, &port)) {
		if (error != nullptr) *error = "invalid loopback provider port";
		return ConfigurationStatus::Invalid;
	}
	configuration.port = static_cast<uint16_t>(port);
	if (timeout_text != nullptr && !ParseUnsigned(timeout_text, minimum_timeout_ms,
	                                              maximum_timeout_ms, &configuration.timeout_ms)) {
		if (error != nullptr) *error = "invalid loopback provider timeout";
		return ConfigurationStatus::Invalid;
	}
	if (!LoadToken(token_path, &configuration.token)) {
		if (error != nullptr) *error = "invalid loopback provider token file";
		return ConfigurationStatus::Invalid;
	}
	*provider = std::make_shared<ConsoleBackend>(std::move(configuration));
	return ConfigurationStatus::Configured;
#else
	if (error != nullptr) *error = "console provider is only implemented on Windows";
	return ConfigurationStatus::Invalid;
#endif
}

} // namespace Libs::LibKernel::EnvelopeSecureProcessor
