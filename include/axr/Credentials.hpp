// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Application implementations derive in a separately qualified native module.
// There is no Python trampoline or secret-export virtual function. Applications
// keep database/token formats outside AXR and own their fixed native consumer.
class CredentialConsumer {
public:
    CredentialConsumer(std::string identity,std::vector<std::string> resources,
                       std::vector<std::string> operations);
    virtual ~CredentialConsumer()=default;
    const std::string& Identity() const{return identity_;}
    const std::vector<std::string>& Resources() const{return resources_;}
    const std::vector<std::string>& Operations() const{return operations_;}
    Json Use(const Json& resource,const std::string& operation,const Json& request,
             const std::function<void()>& verifyCommit);
protected:
    // Only operation results may cross this boundary. Implementations hold OS
    // handles/worker channels; never return a raw key or application login token.
    virtual Json Perform(const Json& resource,const std::string& operation,const Json& request)=0;
private:
    std::string identity_;std::vector<std::string> resources_,operations_;
};
}
