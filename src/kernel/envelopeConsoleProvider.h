#ifndef KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_H_
#define KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_H_

#include "kernel/envelopeSecureProcessor.h"

#include <memory>
#include <string>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

ConfigurationStatus CreateConsoleProviderFromEnvironment(std::shared_ptr<EnvelopeBackend>* provider,
                                                         std::string*                      error);
ConfigurationStatus CreateConsoleRnpsProviderFromEnvironment(std::shared_ptr<RnpsBackend>* provider,
                                                             std::string*                  error);

} // namespace Libs::LibKernel::EnvelopeSecureProcessor

#endif
