// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Protected LocalSystem host only. Launches one fixed installed wechat-uia.exe
// in the unique active owner session. No token, arbitrary command or handle export.
class WindowsNavigation {
public:
    WindowsNavigation(std::string ownerSid,std::string helper,std::string sha256,const std::function<void()>& check);
    ~WindowsNavigation();
    Json Identity() const;
    Json Ready(const std::function<void()>& check);
    void Submit(const Json& request,const std::function<void()>& check);
    Json Result(const std::function<void()>& check);
    void Close();
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
// Fixed interactive UIA helper only. Authenticates its protected System peer
// before receiving an action; action preflight/claim/observe remain separate.
class WindowsNavigationPeer {
public:
    explicit WindowsNavigationPeer(std::string endpoint);
    ~WindowsNavigationPeer();
    Json Request();
    void Respond(const Json& response);
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
