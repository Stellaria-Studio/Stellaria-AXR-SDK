// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include <axr/Core.hpp>
#include <iostream>
int main() {
    // Link/install smoke test; no authority is created and no action is executed.
    const auto seal=Stellaria::AXR::Digest("AXR consumer fixture");
    if(seal.size()!=64)return 1;
    std::cout<<"Stellaria::AXR consumer linked successfully\n";
}
