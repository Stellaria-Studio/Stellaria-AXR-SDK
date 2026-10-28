// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
Json ProcessIdentity(unsigned long pid);
Json PeerIdentity(unsigned long long handle,bool serverPeer=false);
void RequireProtectedHost(const Json& actual,bool owner=false);
// Deterministic decisions over observations supplied by the trusted host, never
// values taken from an agent's request. Authorization is additionally required.
void ValidateTaskContract(const Json& contract);
Json SecurityDecision(const Json& contract, const Json& action,
                      const Json& hostObservation, double now);
Json ContainmentDecision(std::string_view event, std::string_view domain,
                         unsigned recentViolations);
}
namespace Stellaria::AXR {
// Verify the already claimed, short-lived permit against a root pinned by the
// trusted installer. The helper must claim on its own authenticated channel;
// this function never treats an unclaimed execution proof as permission.
bool VerifyCommitPermit(const Json& envelope,std::string_view pinnedPublicKey,
                        std::string_view expectedRoot,std::string_view expectedEpoch,
                        std::string_view expectedNonce,std::string_view expectedSeal,
                        const Json& actualHelper,double now);
}
