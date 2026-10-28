// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Statement integrity only: does not trust the supplied AIK or confer hardware
// qualification. Separate certificate-chain verification is mandatory.
bool VerifyWindowsHelloStatement(std::string_view ownerPublicKey,std::string_view aikPublicKey,std::string_view statement);
// The roots must come from protected deployment, never the requesting peer.
// Chain is the PKCS#7 CertificateChainBuffer supplied by Windows Hello.
bool VerifyWindowsHelloAttestation(std::string_view ownerPublicKey,std::string_view statement,
    std::string_view chain,const std::vector<std::string>& roots);
// Fixed read-only LocalMachine ROOT trust, excluding CurrentUser roots.
bool VerifyWindowsHelloAttestationMachine(std::string_view ownerPublicKey,std::string_view statement,std::string_view chain);
std::string WindowsMachineCABundle(); // Public certificates only; no key APIs.
}
