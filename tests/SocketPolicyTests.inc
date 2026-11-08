void CheckSocketPolicy() {
  namespace Policy = Libs::LibKernel::SocketPolicy;
  using Policy::Admission;
  using Policy::Fact;
  constexpr std::array<Fact, 3> facts {Fact::Unknown, Fact::Clear, Fact::Set};
  size_t cases = 0;
  for (uint32_t flags: {0u, 0x10u, 0x20u, 0x30u}) {
    for (Fact target: facts) {
      for (Fact caller: facts) {
        for (Fact alternate: facts) {
          unsigned admitted = 0, denied = 0;
          for (unsigned bits = 0; bits < 8; ++bits) {
            const auto matches = [](Fact fact, bool value) {
              return fact == Fact::Unknown || (fact == Fact::Set) == value;
            };
            const bool target_set = (bits & 1u) != 0;
            const bool caller_set = (bits & 2u) != 0;
            const bool alternate_set = (bits & 4u) != 0;
            if (!matches(target, target_set) || !matches(caller, caller_set) || !matches(alternate, alternate_set)) continue;
            const bool allow = !target_set || caller_set || (flags & 0x10u) != 0 ||
                ((flags & 0x20u) != 0 && alternate_set);
            if (allow) ++admitted; else ++denied;
          }
          const auto expected = denied == 0 ? Admission::Allow : admitted == 0 ? Admission::Deny : Admission::Unknown;
          const Policy::Credentials listener {target, Fact::Unknown};
          const Policy::Credentials client {caller, alternate};
          Check(Policy::Check(flags, listener, client) == expected &&
                    Policy::Check(flags | 0xffff00cfu, listener, client) == expected,
                "socket policy agrees with every compatible original binary credential completion and ignores unrelated flags");
          ++cases;
        }
      }
    }
  }
  const Policy::Credentials unknown;
  const Policy::Credentials privileged {Fact::Set, Fact::Unknown};
  const Policy::Credentials ordinary {Fact::Clear, Fact::Clear};
  const Policy::Credentials alternate {Fact::Clear, Fact::Set};
  Check(cases == 108 && Policy::Check(0x10, unknown, unknown) == Admission::Allow &&
            Policy::Check(0, unknown, privileged) == Admission::Allow &&
            Policy::Check(0, ordinary, unknown) == Admission::Allow,
        "a decisive allow branch does not require unknown credential bits");
  Check(Policy::Check(0, privileged, unknown) == Admission::Unknown &&
            Policy::Check(0, unknown, ordinary) == Admission::Unknown &&
            Policy::Check(0, privileged, ordinary) == Admission::Deny &&
            Policy::Check(0x20, privileged, alternate) == Admission::Allow &&
            Policy::Check(0, privileged, alternate) == Admission::Deny,
        "alternate permission is independent of capability62 and only matters when listener bit0x20 is set");
  std::printf("SocketPolicyTests: completions=108 unknown_preserved=pass decisive_allow=pass alternate_word68_bit57=pass\n");
}
