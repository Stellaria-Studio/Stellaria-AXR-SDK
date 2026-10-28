// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// One setup exchange only. Caller must be the fixed protected LocalSystem host.
// No executable/session/script selection, token export or authority restoration.
Json ExchangeWindowsOwnerSetup(std::string ownerSid,const Json& challenge);
class WindowsOwnerSetupClient {
public:
    WindowsOwnerSetupClient();
    ~WindowsOwnerSetupClient();
    WindowsOwnerSetupClient(const WindowsOwnerSetupClient&)=delete;
    WindowsOwnerSetupClient& operator=(const WindowsOwnerSetupClient&)=delete;
    Json Challenge() const;
    void Respond(const Json& response);
    void Close();
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
