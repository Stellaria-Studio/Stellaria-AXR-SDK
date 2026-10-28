// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Fixed protected interactive owner host only; no signing or provisioning.
bool ReviewWindowsOwner(std::string review,double expires);
// The constructor only opens an enrolled, pinned credential. Provision is a
// separate, locally reviewed first-enrollment path with FailIfExists. Neither
// path replaces/deletes keys or supplies software fallback/private-key export.
// A successful Hello signature is not hardware attestation.
class WindowsHelloOwnerKey {
public:
    explicit WindowsHelloOwnerKey(std::string expectedPublicKey);
    static std::unique_ptr<WindowsHelloOwnerKey> Provision(std::string review,double expires);
    // Explicit orphaned-first-setup recovery: open only, show the actual key
    // fingerprint for local review, then require attestation and a signature.
    static std::unique_ptr<WindowsHelloOwnerKey> Recover(std::string review,double expires);
    ~WindowsHelloOwnerKey();
    WindowsHelloOwnerKey(const WindowsHelloOwnerKey&)=delete;
    WindowsHelloOwnerKey& operator=(const WindowsHelloOwnerKey&)=delete;
    std::string PublicKey() const;
    std::string Sign(std::string_view message) const;
    Json Attestation() const; // Untrusted evidence; verifier must check roots.
private:
    WindowsHelloOwnerKey();
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
