// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Native OS storage for the independently installed authority process. macOS
// requires its provisioned access group; Windows requires the service identity.
// Never substitutes the user's generic keyring when unavailable.
class ProtectedStore {
public:
    explicit ProtectedStore(std::string nameSpace);
    std::string Get(const std::string& name) const;
    void Put(const std::string& name,std::string_view bytes) const;
private:
    std::string namespace_;
    void Identity() const;
};
}
