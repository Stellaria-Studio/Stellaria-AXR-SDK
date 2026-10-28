// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Credentials.hpp"
#include <algorithm>
namespace Stellaria::AXR {
CredentialConsumer::CredentialConsumer(std::string identity,std::vector<std::string> resources,std::vector<std::string> operations)
    :identity_(std::move(identity)),resources_(std::move(resources)),operations_(std::move(operations)){
    if(identity_.empty()||identity_.size()>2048||resources_.empty()||resources_.size()>4096||operations_.empty())throw std::runtime_error("native_credential_registration_invalid");
    for(const auto& op:operations_)if(op!="database.query"&&op!="document.decrypt")throw std::runtime_error("native_credential_operation_forbidden");
}
Json CredentialConsumer::Use(const Json& resource,const std::string& op,const Json& request,const std::function<void()>& check){
    if(!check||resource.size()!=3||!resource.contains("platform")||!resource.contains("account_id")||!resource.contains("conversation_id")||
       std::find(resources_.begin(),resources_.end(),Digest(resource.dump()))==resources_.end()||
       std::find(operations_.begin(),operations_.end(),op)==operations_.end()||request.dump().size()>MaximumFrameBytes/2)throw std::runtime_error("native_credential_use_outside_scope");
    check();auto result=Perform(resource,op,request);check();
    if(result.dump().size()>MaximumFrameBytes/2)throw std::runtime_error("native_credential_result_budget");
    return result;
}
}
