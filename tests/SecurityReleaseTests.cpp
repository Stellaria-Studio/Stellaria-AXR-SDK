// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Security.hpp"
#include "axr/Commit.h"
#include "axr/Credentials.hpp"
#include "axr/WindowsHello.hpp"
#include <cassert>
#include <iostream>
using namespace Stellaria::AXR;
class FixedConsumer final:public CredentialConsumer{
public:
    explicit FixedConsumer(std::string resource):CredentialConsumer("handler",{resource},{"database.query"}){}
    int calls=0;
protected:
    Json Perform(const Json&,const std::string&,const Json&) override{++calls;return {{"rows",Json::array()}};}
};
int main(){
#if defined(_WIN32)
    // This test executable is not a protected owner host. All checks must fail
    // before WinRT discovery/UI, in reference as well as security builds.
    bool helloDenied=false;
    try{WindowsHelloOwnerKey key("");}catch(const std::exception& e){helloDenied=std::string(e.what())=="hello_enrolled_public_key_required";}
    assert(helloDenied);helloDenied=false;
    try{WindowsHelloOwnerKey key(std::string(294,'x'));}catch(const std::exception& e){helloDenied=std::string(e.what())=="hello_protected_owner_host_required";}
    assert(helloDenied);
    helloDenied=false;
    try{auto key=WindowsHelloOwnerKey::Provision("synthetic first-enrollment review",Now()+60);}
    catch(const std::exception& e){helloDenied=std::string(e.what())=="hello_protected_owner_host_required";}
    assert(helloDenied);
#endif
    auto now=Now();Json resource={{"platform","fixture"},{"account_id","a"},{"conversation_id","b"}};
    Json contract={{"version",2},{"id","task"},{"owner","owner"},{"agent","agent"},{"application","app"},{"goal_digest",Digest("goal")},
        {"mode","incoming"},{"trigger","external-message"},{"operations",Json{"messages.read"}},{"resources",Json{Digest(resource.dump())}},
        {"sources",Json{Digest(resource.dump())}},{"destinations",Json{"local"}},{"classes",Json{"personal"}},
        {"outputs",Json{"Summary"}},{"sandbox","isolated"},{"presence_required",false},{"created",now},{"expires",now+60},{"max_uses",3},{"policy_version",1}};
    ValidateTaskContract(contract);
    assert(axr_authority_claim(nullptr,nullptr,nullptr)==0);
    assert(axr_authority_preflight("/not-a-server","{}","{}")==0);
    assert(axr_authority_observe(nullptr,nullptr,1,nullptr)==0);
    FixedConsumer consumer(Digest(resource.dump()));
    assert(consumer.Use(resource,"database.query",Json::object(),[]{}).contains("rows"));assert(consumer.calls==1);
    bool credentialDenied=false;try{consumer.Use(resource,"credentials.export",Json::object(),[]{});}catch(...){credentialDenied=true;}assert(credentialDenied&&consumer.calls==1);
    credentialDenied=false;try{consumer.Use(resource,"database.query",Json::object(),[]{throw std::runtime_error("revoked");});}catch(...){credentialDenied=true;}assert(credentialDenied&&consumer.calls==1);
    Json action={{"principal","agent"},{"resource",resource},{"operation","messages.read"},{"purpose","test"},{"payload",Json::object()},
        {"sources",Json::array()},{"destination","local"},{"workflow","manual"},{"execution_id","execution"}};
    Json host={{"agent","agent"},{"application","app"},{"identity_verified",true},{"sandbox","isolated"},{"environment_valid",true},
        {"user_present",false},{"trust_state","Normal"},{"used",0},{"revoked",false},{"policy_version",1}};
    assert(SecurityDecision(contract,action,host,now).at("allow")==true);
    host["agent"]="forged";assert(SecurityDecision(contract,action,host,now).at("allow")==false);
    host["agent"]="agent";
    auto work=contract;work["mode"]="workspace";work["trigger"]="owner-command";work["operations"]=Json{"shell.execute"};
    auto command=action;command["operation"]="shell.execute";command["payload"]={{"command","fixed-owner-test"}};
    assert(SecurityDecision(work,command,host,now).at("code")=="exact_owner_execution_review_required");
    host["owner_execution_seal"]=IntentSeal(command);assert(SecurityDecision(work,command,host,now).at("allow")==true);
    command["payload"]={{"command","changed"}};assert(SecurityDecision(work,command,host,now).at("allow")==false);
    contract["operations"]=Json{"shell.execute"};bool denied=false;try{ValidateTaskContract(contract);}catch(...){denied=true;}assert(denied);
    assert(ContainmentDecision("suspicious_content","kernel",1).at("scope")=="connection");
    assert(ContainmentDecision("attachment_invalid","file",1).at("scope")=="file");
    assert(ContainmentDecision("audit_integrity","file",1).at("state")=="Sealed");
#ifdef AXR_SECURITY_RELEASE
    assert(axr_check_commit("untrusted-path","{\"version\":1}")==0);
    const auto dir=std::filesystem::temp_directory_path()/RandomId();std::filesystem::create_directory(dir);
    {Guard g(dir/"guard.db",std::string(32,'g'));denied=false;
     try{g.ExecutionProof(action,"fake",g.Version(),now);}catch(const std::exception& e){denied=std::string(e.what())=="legacy_commit_disabled_in_security_release";}assert(denied);}
    std::filesystem::remove_all(dir);
#endif
    std::cout<<"native task/containment and formal no-downgrade gates passed\n";
}
