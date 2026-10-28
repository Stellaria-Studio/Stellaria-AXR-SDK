// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Security.hpp"
#include "axr/WindowsInstallation.hpp"
#include <algorithm>
#include <cmath>
#include <set>
#include <stdexcept>
#if defined(__APPLE__)
#include <sys/stat.h>
#endif
namespace Stellaria::AXR {
void RequireProtectedHost(const Json& actual,bool owner){
#if defined(__APPLE__)
    std::filesystem::path expected=owner?"/Library/Application Support/Stellaria AXR/AXR Owner.app/Contents/MacOS/axr-owner":"/Library/Application Support/Stellaria AXR/AXR Authority.app/Contents/MacOS/axr-authority";
    if(actual.at("image")!=expected.string())throw std::runtime_error("protected_host_installation_required");
    for(auto path=expected;!path.empty();path=path.parent_path()){
        struct stat info{};
        if(lstat(path.c_str(),&info)||S_ISLNK(info.st_mode)||info.st_uid!=0||(info.st_mode&0022))throw std::runtime_error("protected_host_installation_required");
        if(path==path.root_path())break;
    }
#elif defined(_WIN32)
    auto root=WindowsInstallationRoot();auto expected=root/(owner?L"axr-owner.exe":L"axr-authority.exe");
    if(Utf8Path(actual.at("image").get<std::string>())!=expected||actual.at("app_container")!=false||
        (owner?(actual.at("user")=="S-1-5-18"):(actual.at("user")!="S-1-5-18")))
        throw std::runtime_error("protected_host_installation_required");
    VerifyWindowsInstallation(root);
#else
    (void)actual;(void)owner;throw std::runtime_error("protected_host_platform_unavailable");
#endif
}
namespace {
[[noreturn]] void Invalid(){throw std::runtime_error("task_contract_invalid");}
bool In(const Json& a,const Json& b){return a.is_array()&&std::find(a.begin(),a.end(),b)!=a.end();}
void Text(const Json& v,unsigned max=2048){
    if(!v.is_string())Invalid();auto s=v.get<std::string>();
    if(s.empty()||s.size()>max||std::any_of(s.begin(),s.end(),[](unsigned char c){return c<32;}))Invalid();
}
void List(const Json& v,unsigned max=4096){
    if(!v.is_array()||v.empty()||v.size()>max)Invalid();
    std::set<std::string> seen;for(const auto& x:v){Text(x);if(!seen.insert(x.get<std::string>()).second)Invalid();}
}
bool Number(const Json& v){return v.is_number()&&!v.is_boolean()&&std::isfinite(v.get<double>());}
bool GeneralExecution(std::string_view op){
    return op.starts_with("process.")||op.starts_with("shell.")||op.starts_with("code.")||
        op.starts_with("script.")||op.starts_with("runtime.")||op=="application.launch";
}
Json Deny(const char* predicate,const char* code){return {{"allow",false},{"predicate",predicate},{"code",code}};}
}
void ValidateTaskContract(const Json& c){
    static const std::set<std::string> fields={"version","id","owner","agent","application","goal_digest","mode","trigger",
        "operations","resources","sources","destinations","classes","outputs","sandbox","presence_required",
        "created","expires","max_uses","policy_version"};
    if(!c.is_object()||c.size()!=fields.size()||c.dump().size()>MaximumFrameBytes/2)Invalid();
    for(auto i=c.begin();i!=c.end();++i)if(!fields.contains(i.key()))Invalid();
    if(c.at("version")!=2)Invalid();
    for(auto k:{"id","owner","agent","application","goal_digest","sandbox"})Text(c.at(k));
    auto goal=c.at("goal_digest").get<std::string>();
    if(goal.size()!=64||goal.find_first_not_of("0123456789abcdef")!=std::string::npos)Invalid();
    if(!In(Json{"incoming","workspace","full"},c.at("mode"))||
       !In(Json{"owner-ui","owner-command","external-message","document"},c.at("trigger")))Invalid();
    if(c.at("mode")!="incoming"&&In(Json{"external-message","document"},c.at("trigger")))Invalid();
    for(auto k:{"operations","resources","sources","destinations","classes","outputs"})List(c.at(k));
    for(const auto& x:c.at("classes"))if(!In(Json{"workspace-normal","personal","sensitive","credentials","financial"},x))Invalid();
    for(const auto& x:c.at("outputs"))if(!In(Json{"Summary","ReplyDraft","ActionProposal","DataRequest","SafeContent"},x))Invalid();
    if(!c.at("presence_required").is_boolean()||!Number(c.at("created"))||!Number(c.at("expires"))||
       c.at("expires").get<double>()<=c.at("created").get<double>()||
       c.at("expires").get<double>()-c.at("created").get<double>()>86400||
       !c.at("max_uses").is_number_integer()||c.at("max_uses").get<long long>()<1||c.at("max_uses").get<unsigned long long>()>100000||c.at("max_uses")==0||
       !c.at("policy_version").is_number_integer()||c.at("policy_version").get<long long>()<1||c.at("policy_version")==0)Invalid();
    // This is a native invariant, not a prompt instruction or configurable denylist.
    if(c.at("mode")=="incoming")for(const auto& op:c.at("operations")){
        if(!In(Json{"status.read","messages.read","messages.search","files.read","reply.prepare","messages.send",
                    "disclosure.send","application.navigate","application.draft"},op))Invalid();
    }
    if(c.at("mode")=="full"&&(!c.at("presence_required").get<bool>()||
       c.at("expires").get<double>()-c.at("created").get<double>()>3600))Invalid();
}
Json SecurityDecision(const Json& c,const Json& a,const Json& h,double now){
    try{
        ValidateTaskContract(c);ValidateAction(a);
        if(!std::isfinite(now))return Deny("P","invalid_clock");
        if(h.at("agent")!=c.at("agent")||a.at("principal")!=c.at("agent")||
           h.at("application")!=c.at("application")||h.at("identity_verified")!=true)
            return Deny("I","identity_not_bound");
        if(!In(c.at("resources"),Digest(a.at("resource").dump()))||!In(c.at("operations"),a.at("operation")))
            return Deny("C","action_outside_task_contract");
        const auto op=a.at("operation").get<std::string>();
        if(In(Json{"external-message","document"},c.at("trigger"))&&GeneralExecution(op))
            return Deny("C","incoming_execution_forbidden");
        // General execution always needs a separate exact-action owner review.
        // It cannot inherit code-execution consent from a broad workspace task.
        if(GeneralExecution(op)&&(!h.contains("owner_execution_seal")||h.at("owner_execution_seal")!=IntentSeal(a)))
            return Deny("C","exact_owner_execution_review_required");
        if(!In(c.at("destinations"),a.at("destination")))return Deny("D","destination_outside_task_contract");
        for(const auto& p:a.at("sources")){
            if(!In(c.at("sources"),Digest(p.at("resource").dump()))||!In(c.at("classes"),p.at("data_class")))
                return Deny("D","source_outside_task_contract");
            if(In(Json{"credentials","financial"},p.at("data_class"))&&c.at("mode")!="full")
                return Deny("D","sensitive_class_requires_owner_task");
        }
        if(h.at("sandbox")!=c.at("sandbox")||h.at("environment_valid")!=true||
           (c.at("presence_required")==true&&h.at("user_present")!=true))
            return Deny("E","execution_environment_not_verified");
        auto state=h.at("trust_state");
        if(state=="Sealed"||state=="Quarantined"||
           (state=="Restricted"&&(a.at("destination")!="local"||Risk(a)>=3)))return Deny("E","trust_domain_contained");
        if(!In(Json{"Normal","Restricted","Quarantined","Sealed"},state))return Deny("E","unknown_trust_state");
        if(now<c.at("created").get<double>()-1||now>=c.at("expires").get<double>()||
           h.at("policy_version")!=c.at("policy_version")||!h.at("used").is_number_integer()||h.at("used").get<long long>()<0||
           h.at("used").get<unsigned long long>()>=c.at("max_uses").get<unsigned long long>()||h.at("revoked")!=false)
            return Deny("P","contract_expired_revoked_or_exhausted");
        return {{"allow",true},{"predicate","I&C&D&E&P"},{"code","allowed"}};
    }catch(...){return Deny("C","security_context_invalid");}
}
Json ContainmentDecision(std::string_view event,std::string_view domain,unsigned n){
    // Untrusted text alone cannot seal the installation or revoke other domains.
    if(domain.empty()||domain.size()>2048)return {{"state","Restricted"},{"scope","connection"},{"revoke",false}};
    if(event=="policy_integrity"||event=="root_integrity"||event=="audit_integrity"||event=="kernel_integrity")
        return {{"state","Sealed"},{"scope","kernel"},{"revoke",true}};
    if(domain=="kernel"||domain=="connection")return {{"state","Restricted"},{"scope","connection"},{"revoke",false}};
    if(event=="owner_stop")return {{"state","Quarantined"},{"scope",domain},{"revoke",true}};
    if(event=="application_identity"||event=="worker_escape"||event=="attachment_invalid"||event=="inspection_unavailable")
        return {{"state","Quarantined"},{"scope",domain},{"revoke",true}};
    if(event=="ipc_authentication"||event=="ipc_replay")return {{"state","Quarantined"},{"scope","connection"},{"revoke",false}};
    if(event=="authority_denied")return {{"state",n>=10?"Quarantined":n>=5?"Restricted":"Normal"},{"scope",domain},{"revoke",n>=10}};
    if(event=="suspicious_content")return {{"state","Restricted"},{"scope",domain},{"revoke",false}};
    return {{"state","Restricted"},{"scope",domain},{"revoke",false}};
}
}

#include "axr/TrustRoot.hpp"
namespace Stellaria::AXR {
bool VerifyCommitPermit(const Json& envelope,std::string_view key,std::string_view root,
                        std::string_view epoch,std::string_view nonce,std::string_view seal,
                        const Json& helper,double now){
    try{
        if(!std::isfinite(now)||envelope.size()!=2||!envelope.contains("body")||!envelope.contains("signature"))return false;
        const auto& b=envelope.at("body");auto hex=envelope.at("signature").get<std::string>();
        if(hex.empty()||hex.size()>160||hex.size()%2||hex.find_first_not_of("0123456789abcdef")!=std::string::npos)return false;
        std::string signature;for(std::size_t i=0;i<hex.size();i+=2)signature.push_back(char(std::stoi(hex.substr(i,2),nullptr,16)));
        if(!VerifyRootSignature(key,b.dump(),signature))return false;
        return b.size()==10&&b.at("version")==2&&b.at("kind")=="commit-permit"&&
            b.at("root_id").get<std::string>()==root&&b.at("epoch").get<std::string>()==epoch&&b.at("nonce").get<std::string>()==nonce&&b.at("seal").get<std::string>()==seal&&
            b.at("helper")==Digest(helper.dump())&&b.at("helper_pid")==helper.at("pid")&&
            b.at("helper_birth")==helper.at("birth")&&Number(b.at("expires"))&&
            b.at("expires").get<double>()>now&&b.at("expires").get<double>()-now<=5;
    }catch(...){return false;}
}
}
