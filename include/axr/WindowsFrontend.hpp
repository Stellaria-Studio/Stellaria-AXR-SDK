// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Read-only OS witness: requires an AAP-opted-out AppContainer with no
// capabilities. No caller-supplied role, SID, environment or trust flag.
Json WindowsFrontendIdentity(unsigned long pid);
// Fixed self executable and one fixed child argument; forwards only stdio.
int RunWindowsFrontend();
// Only public OS identity queries, never token duplication/impersonation. The
// formal entry requires the fixed protected System authority.
void ExposeWindowsAuthorityIdentity(const std::string& ownerSid);
}
