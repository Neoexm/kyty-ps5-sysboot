void CheckCompositorSockets() {
#if defined(_WIN32)
  namespace Net = Libs::Network::Net;
  const std::array<const char*, 3> keys {{
      "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
      "KYTY_DIAGNOSTIC_GNM_COMMAND3000_SEMANTICS"}};
  std::array<std::string, 3> saved;
  for (size_t i = 0; i < keys.size(); ++i) {
    const auto* value = std::getenv(keys[i]);
    saved[i] = value ? value : "";
  }
  const auto scope = "cs" + std::to_string(GetCurrentProcessId()) + "_" +
      std::to_string(GetTickCount64() % 10000000);
  Check(scope.size() < 20 && _putenv_s(keys[0], "1") == 0 &&
            _putenv_s(keys[1], scope.c_str()) == 0 && _putenv_s(keys[2], "1") == 0,
        "select isolated local socket fixture scope");
  const auto address = [](const char* path) {
    std::array<uint8_t, 106> bytes {};
    bytes[1] = 1;
    Check(std::strlen(path) < bytes.size() - 2, "local socket fixture name fits guest sockaddr");
    std::memcpy(bytes.data() + 2, path, std::strlen(path) + 1);
    return bytes;
  };
  const std::array<std::array<uint8_t, 106>, 3> addresses {{
      address("/system_tmp/GnmCompositor"), address("/system_tmp/AgcCompositorSppSocket"),
      address("/system_tmp/GnmCompositorRestricted")}};
  void* policy_input = nullptr;
  uint64_t policy_token = 0;
  Check(Libs::LibKernel::Memory::MapOwnedFlexibleMemory(&policy_input, 0x4000,
            "compositor_socket_policy", &policy_token) == OK,
        "map four-byte ioctl input in guest memory");
  *static_cast<int32_t*>(policy_input) = 1;
  const auto ready = [](int descriptor, int64_t microseconds) {
    std::array<uint64_t, 1024> readable {};
    readable[descriptor / 64] = uint64_t {1} << (descriptor % 64);
    const std::array<int64_t, 2> timeout {{microseconds / 1000000, microseconds % 1000000}};
    return Net::Select(descriptor + 1, readable.data(), nullptr, nullptr, timeout.data());
  };
  const auto listen = [&](const auto& bytes) {
    const int listener = Net::Socket(1, 1, 0);
    Check(listener >= 0 && Net::Ioctl(listener, 0x80049301u, policy_input) == 0 &&
              Net::Bind(listener, bytes.data(), bytes.size()) == 0 &&
              Net::Listen(listener, 4) == 0, "bind and listen on a scoped local endpoint");
    return listener;
  };
  std::array<int, 3> listeners {{listen(addresses[0]), listen(addresses[1]), listen(addresses[2])}};
  for (size_t i = 0; i < addresses.size(); ++i) {
    const int duplicate = Net::Socket(1, 1, 0);
    Check(duplicate >= 0 && Net::Bind(duplicate, addresses[i].data(), addresses[i].size()) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EADDRINUSE &&
              Net::SocketClose(duplicate) == 0,
          "duplicate local binds fail while preserving the owning listener");
  }
  enum class ExchangeMode { FullCommand3000, FilteredCommand3000, WrongCommand3000 };
  const auto exchange = [&](int listener, const auto& bytes, int other, ExchangeMode mode) {
    namespace EventQueue = Libs::LibKernel::EventQueue;
    EventQueue::KernelEqueue queue = EventQueue::KERNEL_EQUEUE_INVALID;
    Check(EventQueue::KernelCreateEqueue(&queue, "compositor-socket-read") == OK &&
              EventQueue::KernelAddReadEvent(queue, listener, 0, &queue) == OK,
          "register local listener in the guest event queue");
    EventQueue::KernelEvent event {};
    int event_count = -1;
    uint32_t timeout = 0;
    Check(EventQueue::KernelWaitEqueue(queue, &event, 1, &event_count, &timeout) ==
              Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT && event_count == 0,
          "empty listener reports no read event");
    const int writer = Net::Socket(1, 1, 0);
    Check(writer >= 0 && Net::Connect(writer, bytes.data(), bytes.size()) == 0 &&
              ready(listener, 2000000) == 1 && ready(other, 0) == 0,
          "connection reaches only the selected scoped guest endpoint");
    timeout = 2000000;
    Check(EventQueue::KernelWaitEqueue(queue, &event, 1, &event_count, &timeout) == OK &&
              event_count == 1 && event.ident == listener && event.udata == &queue && event.data > 0,
          "connection wakes the listener read-event path");
    const int reader = Net::Accept(listener, nullptr, nullptr);
    Check(reader >= 0, "accept a queued local connection");
    timeout = 0;
    Check(EventQueue::KernelWaitEqueue(queue, &event, 1, &event_count, &timeout) ==
              Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT && event_count == 0 &&
              EventQueue::KernelDeleteEqueue(queue) == OK,
          "accept drains listener readiness and its event queue closes");
    const int timeout_ms = 2000;
    Check(Net::Setsockopt(reader, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0 &&
              Net::Setsockopt(writer, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0,
          "bound local peer receive operations");
    std::array<uint8_t, 64> copied {};
    const auto transfer = [&](int sender, int receiver, const void* source, size_t count,
                              std::initializer_list<size_t> send_parts,
                              std::initializer_list<size_t> receive_parts) {
      size_t send_total = 0;
      for (const auto part: send_parts) send_total += part;
      size_t receive_total = 0;
      for (const auto part: receive_parts) receive_total += part;
      Check(count <= copied.size() && send_total == count && receive_total == count,
            "bounded command fixture partitions cover the exact caller bytes");
      size_t offset = 0;
      for (const auto part: send_parts) {
        Check(Net::Send(sender, static_cast<const uint8_t*>(source) + offset, part, 0) == part,
              "fragmented command fixture send preserves caller bytes");
        offset += part;
      }
      copied.fill(0);
      offset = 0;
      for (const auto part: receive_parts) {
        Check(ready(receiver, 2000000) == 1 &&
                  Net::Recv(receiver, copied.data() + offset, part, 0) == part,
              "fragmented command fixture receive preserves caller bytes");
        offset += part;
      }
      Check(std::memcmp(copied.data(), source, count) == 0,
            "command fixture bytes remain unchanged across the socket");
    };
    const std::array<uint32_t, 4> request {{1, 0x3000, 0, 0}};
    const std::array<uint32_t, 4> response_a {{0, 0, 16, 0x81234567}};
    const std::array<uint64_t, 2> descriptor_a {{0, 0x55aa}};
    if (mode == ExchangeMode::FullCommand3000) {
      transfer(writer, reader, request.data(), sizeof(request), {5, 11}, {3, 13});
      std::array<uint8_t, 32> combined {};
      std::memcpy(combined.data(), response_a.data(), sizeof(response_a));
      std::memcpy(combined.data() + sizeof(response_a), descriptor_a.data(), sizeof(descriptor_a));
      transfer(reader, writer, combined.data(), combined.size(), {32}, {7, 25});

      const std::array<uint32_t, 4> response_b {{0, 0, 16, 0x81234568}};
      const std::array<uint64_t, 2> descriptor_b {{0, 0}};
      transfer(writer, reader, request.data(), sizeof(request), {16}, {4, 12});
      transfer(reader, writer, response_b.data(), sizeof(response_b), {6, 10}, {5, 11});
      transfer(reader, writer, descriptor_b.data(), sizeof(descriptor_b), {1, 15}, {8, 8});

      const std::array<uint32_t, 4> response_zero {{0, 0, 0, 0x81234569}};
      transfer(writer, reader, request.data(), sizeof(request), {16}, {16});
      transfer(reader, writer, response_zero.data(), sizeof(response_zero), {8, 8}, {16});

      const std::array<uint32_t, 4> response_c {{0, 0, 16, 0x8123456a}};
      const std::array<uint64_t, 2> descriptor_c {{0x55aa, 0}};
      transfer(writer, reader, request.data(), sizeof(request), {2, 14}, {16});
      transfer(reader, writer, response_c.data(), sizeof(response_c), {16}, {2, 14});
      transfer(reader, writer, descriptor_c.data(), sizeof(descriptor_c), {16}, {16});

      const std::array<uint32_t, 4> response_unsupported {{0, 0, 8, 0x8123456b}};
      const std::array<uint64_t, 1> unsupported_body {{0x1122}};
      transfer(writer, reader, request.data(), sizeof(request), {16}, {16});
      transfer(reader, writer, response_unsupported.data(), sizeof(response_unsupported), {16}, {16});
      transfer(reader, writer, unsupported_body.data(), sizeof(unsupported_body), {8}, {8});
    } else if (mode == ExchangeMode::FilteredCommand3000) {
      transfer(writer, reader, request.data(), sizeof(request), {16}, {16});
      std::array<uint8_t, 32> combined {};
      std::memcpy(combined.data(), response_a.data(), sizeof(response_a));
      std::memcpy(combined.data() + sizeof(response_a), descriptor_a.data(), sizeof(descriptor_a));
      transfer(reader, writer, combined.data(), combined.size(), {32}, {32});
    } else {
      const std::array<uint32_t, 4> wrong_request {{2, 0x3000, 1, 0}};
      transfer(writer, reader, wrong_request.data(), sizeof(wrong_request), {7, 9}, {16});
      std::array<uint8_t, 32> combined {};
      std::memcpy(combined.data(), response_a.data(), sizeof(response_a));
      std::memcpy(combined.data() + sizeof(response_a), descriptor_a.data(), sizeof(descriptor_a));
      transfer(reader, writer, combined.data(), combined.size(), {32}, {32});
      for (uint32_t i = 0; i < 12; ++i) {
        const std::array<uint32_t, 4> header {{0xaabb0000u + i, 0x11223344, 0x55667788, 0x99aabbcc}};
        transfer(writer, reader, header.data(), sizeof(header), {16}, {16});
      }
    }
    Check(Net::SocketClose(reader) == 0 && Net::SocketClose(writer) == 0,
          "close the exchanged local socket pair");
  };
  exchange(listeners[0], addresses[0], listeners[1], ExchangeMode::FullCommand3000);
  exchange(listeners[1], addresses[1], listeners[0], ExchangeMode::FilteredCommand3000);
  exchange(listeners[2], addresses[2], listeners[0], ExchangeMode::FilteredCommand3000);
  const auto redis_address = address("/system_tmp/redis.sock");
  const int redis_listener = Net::Socket(1, 1, 0);
  Check(redis_listener >= 0, "create Redis's local socket");
  const int redis_reuse = 1;
  const int redis_reuse_result = Net::Setsockopt(redis_listener, 0xffff, 4, &redis_reuse,
                                                sizeof(redis_reuse));
  int redis_reuse_readback = 0;
  uint32_t redis_reuse_size = sizeof(redis_reuse_readback);
  Check(redis_reuse_result == 0 &&
            Net::Getsockopt(redis_listener, 0xffff, 4, &redis_reuse_readback,
                            &redis_reuse_size) == 0 &&
            redis_reuse_size == sizeof(redis_reuse_readback) && redis_reuse_readback == 1 &&
            Net::Ioctl(redis_listener, 0x80049301u, policy_input) == 0 &&
            Net::Bind(redis_listener, redis_address.data(), redis_address.size()) == 0 &&
            Net::Listen(redis_listener, 4) == 0,
        "Redis's original local socket creation, reuse option, bind and listen sequence");
  const int redis_duplicate = Net::Socket(1, 1, 0);
  Check(redis_duplicate >= 0 &&
            Net::Bind(redis_duplicate, redis_address.data(), redis_address.size()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EADDRINUSE &&
            Net::SocketClose(redis_duplicate) == 0,
        "Redis's original local socket name has one owner within the boot scope");
  const int redis_writer = Net::Socket(1, 1, 0);
  Check(redis_writer >= 0 && Net::Connect(redis_writer, redis_address.data(), redis_address.size()) == 0 &&
            ready(redis_listener, 2000000) == 1 && ready(listeners[0], 0) == 0,
        "Redis's local socket does not alias a compositor endpoint");
  const int redis_reader = Net::Accept(redis_listener, nullptr, nullptr);
  constexpr char redis_request[] = "PING\r\n";
  std::array<char, sizeof(redis_request) - 1> redis_copied {};
  Check(redis_reader >= 0 &&
            Net::Send(redis_writer, redis_request, redis_copied.size(), 0) == redis_copied.size() &&
            ready(redis_reader, 2000000) == 1 &&
            Net::Recv(redis_reader, redis_copied.data(), redis_copied.size(), 0) == redis_copied.size() &&
            std::memcmp(redis_copied.data(), redis_request, redis_copied.size()) == 0 &&
            Net::SocketClose(redis_reader) == 0 && Net::SocketClose(redis_writer) == 0,
        "Redis's original local socket accepts and transfers bytes");
  const auto other_scope = scope + "b";
  Check(_putenv_s(keys[1], other_scope.c_str()) == 0, "select independent local socket namespace");
  const int absent = Net::Socket(1, 1, 0);
  Check(absent >= 0 && Net::Connect(absent, addresses[0].data(), addresses[0].size()) == -1 &&
            ready(listeners[0], 0) == 0 && Net::SocketClose(absent) == 0,
        "same guest name cannot connect across isolated socket scopes");
  const int absent_redis = Net::Socket(1, 1, 0);
  Check(absent_redis >= 0 &&
            Net::Connect(absent_redis, redis_address.data(), redis_address.size()) == -1 &&
            ready(redis_listener, 0) == 0 && Net::SocketClose(absent_redis) == 0,
        "Redis's guest name cannot cross boot scopes");
  const int scoped = listen(addresses[0]);
  exchange(scoped, addresses[0], listeners[0], ExchangeMode::WrongCommand3000);
  Check(Net::SocketClose(scoped) == 0 && _putenv_s(keys[1], scope.c_str()) == 0,
        "close independent namespace endpoint and restore the original scope");
  Check(Net::SocketClose(redis_listener) == 0, "close Redis's local socket owner");
  const int redis_rebound = listen(redis_address);
  Check(Net::SocketClose(redis_rebound) == 0,
        "Redis's scoped local socket can bind after its original owner closes");
  const int invalid = Net::Socket(1, 1, 0);
  Check(invalid >= 0, "create socket for unsupported address checks");
  for (const char* path: {"/system_tmp/UnknownSocket", "/system_tmp/GnmCompositorRestricted/extra",
                          "/system_tmp/GnmCompositor/..", "/system_tmp/../AgcCompositorSppSocket"}) {
    const auto bytes = address(path);
    Check(Net::Bind(invalid, bytes.data(), bytes.size()) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP,
          "unimplemented policy and unknown local names remain unsupported");
  }
  Check(Net::Ioctl(invalid, 0x80049302, policy_input) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP,
        "unimplemented local policy selectors retain the kernel unsupported error");
  auto unterminated = addresses[1];
  std::fill(unterminated.begin() + 2, unterminated.end(), uint8_t {'x'});
  Check(Net::Bind(invalid, unterminated.data(), unterminated.size()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP &&
            Net::Bind(invalid, addresses[1].data(), 1) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            Net::Bind(invalid, nullptr, 106) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "malformed local sockaddr input never publishes an endpoint");
  Check(_putenv_s(keys[1], "invalid/socket/scope") == 0 &&
            Net::Bind(invalid, addresses[1].data(), addresses[1].size()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG &&
            _putenv_s(keys[1], scope.c_str()) == 0 && Net::SocketClose(invalid) == 0,
        "invalid namespace cannot redirect a guest socket to an arbitrary host path");
  for (size_t i = 0; i < listeners.size(); ++i) {
    Check(Net::SocketClose(listeners[i]) == 0, "close the endpoint owner");
    listeners[i] = listen(addresses[i]);
    Check(Net::SocketClose(listeners[i]) == 0, "closed endpoint cleanup permits the same name to bind again");
  }
  Check(Libs::LibKernel::Memory::UnmapOwnedFlexibleMemory(
            reinterpret_cast<uint64_t>(policy_input), 0x4000, policy_token) == OK,
        "release the guest ioctl input mapping");
  char temp_path[MAX_PATH] {};
  Check(GetTempPathA(MAX_PATH, temp_path) != 0, "locate scoped host fixture cleanup");
  for (const auto& fixture_scope: {scope, other_scope}) {
    for (const char* endpoint: {"gnm", "spp", "gnmr", "redis"}) {
      const auto path = std::filesystem::path(temp_path) /
          ("kyty_ps5_" + fixture_scope + "_" + endpoint + ".sock.policy");
      std::error_code ec;
      std::filesystem::remove(path, ec);
      Check(!ec, "remove the closed fixture policy sidecar");
    }
  }
  for (size_t i = 0; i < keys.size(); ++i) {
    Check(_putenv_s(keys[i], saved[i].c_str()) == 0, "restore local socket fixture environment");
  }
  std::printf("CompositorSocketTests: gnm_spp_restricted=pass redis=pass separate_names=pass separate_scopes=pass bidirectional_bytes=pass command3000_semantics=pass duplicate_bind=pass cleanup_rebind=pass listener_read_events=pass host_fixture_only=1\n");
#endif
}
