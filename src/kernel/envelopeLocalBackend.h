#ifndef KYTY_KERNEL_ENVELOPE_LOCAL_BACKEND_H_
#define KYTY_KERNEL_ENVELOPE_LOCAL_BACKEND_H_

#include "kernel/envelopeSecureProcessor.h"

#include <memory>
#include <string>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

// Host-side secure backend, selected with KYTY_PS5_ENVELOPE_BACKEND=local.
// Looks up the (cid, mkv) master-key entry and runs its derivation; crypt is host AES-128 with the
// console's slot/state contract.
//
// Master-key table file (binary, path from KYTY_PS5_ENVELOPE_LOCAL_KEYTABLE):
//   u8  magic[8] = "KYTYMKV1"
//   u32 count
//   per record:
//     u32 cid        (0xffffffff matches any cid)
//     u32 mkv
//     u32 derivation (id registered below; unknown ids make the entry unusable)
//     u32 material_size (16..32 bytes)
//     u8  material[32] (only material_size bytes are read; secret, pass by path)
//
// Ids < 0x80000000: algorithms checked against service 80021001. Ids >= 0x80000000 are stand-ins,
// need KYTY_DIAGNOSTIC_ENVELOPE_LOCAL=1 and log NON_AUTHENTIC.
constexpr uint32_t derivation_diagnostic_ecb_salt =
    0x80000001; // key = AES-128-ECB-ENC(material[0:16], salt[0:16])

class LocalSecureBackend final: public Backend {
public:
	LocalSecureBackend();
	~LocalSecureBackend() override;
	LocalSecureBackend(const LocalSecureBackend&)            = delete;
	LocalSecureBackend& operator=(const LocalSecureBackend&) = delete;

	Provider Kind() const noexcept override { return Provider::Local; }

	CommandResult DeriveKey(const Context& context, uint16_t* slot) noexcept override;
	CommandResult DecryptBlocks(uint16_t slot, std::span<uint8_t, 16> state,
	                            std::span<const uint8_t> input,
	                            std::span<uint8_t>       output) noexcept override;
	CommandResult EncryptBlock(uint16_t slot, std::span<uint8_t, 16> state) noexcept override;
	void          ReleaseKey(uint16_t slot) noexcept override;

	bool LoadKeyTable(const char* path, std::string* error) noexcept;
	void TableCounts(size_t* total, uint32_t* authentic, uint32_t* diagnostic) const noexcept;

private:
	struct Impl;
	std::unique_ptr<Impl> impl;
};

ConfigurationStatus CreateLocalBackendFromEnvironment(std::shared_ptr<Backend>* backend,
                                                      std::string*              error);

} // namespace Libs::LibKernel::EnvelopeSecureProcessor

#endif
