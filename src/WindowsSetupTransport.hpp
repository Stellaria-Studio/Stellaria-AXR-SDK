// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include "axr/Core.hpp"
namespace Stellaria::AXR::WindowsSetupTransport {
// Internal message I/O only. These primitives cannot assign a role or launch a
// process. Setup entry points separately require protected native host identity.
struct Deadline {
    double wall;ULONGLONG tick;std::function<void()> check;
    explicit Deadline(double expires,std::function<void()> active={});
    DWORD Remaining() const;
};
void Connect(HANDLE pipe,const Deadline& deadline);
DWORD Transfer(HANDLE pipe,void* buffer,DWORD size,bool write,const Deadline& deadline);
void Stable(HANDLE pipe,bool serverPeer,const Json& expected);
void Send(HANDLE pipe,const Json& value,const Deadline& deadline,bool serverPeer,const Json& expected,size_t maximum=300000);
Json Receive(HANDLE pipe,size_t maximum,const Deadline& deadline,bool serverPeer,const Json& expected);
}
#endif
