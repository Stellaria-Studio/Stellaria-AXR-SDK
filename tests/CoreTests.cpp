// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Core.hpp"
#include "axr/Commit.h"
#include <cassert>
#include <thread>
#include <iostream>
using namespace Stellaria::AXR;
void CheckLegacyProof(Guard& guard,const Json& action,const Json& reservation,const std::filesystem::path& database){
#ifdef AXR_SECURITY_RELEASE
    bool denied=false;
    try{guard.ExecutionProof(action,reservation[0],reservation[1],Now());}
    catch(const std::exception& e){denied=std::string(e.what())=="legacy_commit_disabled_in_security_release";}
    assert(denied);
#else
    auto checked=guard.ExecutionProof(action,reservation[0],reservation[1],Now());assert(checked["grants"].size()==1);
    auto proof=checked.dump();auto path=database.u8string();
    assert(axr_check_commit(reinterpret_cast<const char*>(path.c_str()),proof.c_str())==1);
    guard.RevokeOwner(reservation[0]);
    assert(axr_check_commit(reinterpret_cast<const char*>(path.c_str()),proof.c_str())==0);
#endif
}
int main() {
    assert(axr_authority_preflight(nullptr,nullptr,nullptr)==0);
    assert(std::string(axr_authority_last_failure())=="scope");
    assert(axr_authority_local_permit("unconnected","{}","{}")==0);
    assert(std::string(axr_authority_last_failure())=="local_permit");
    std::thread isolated([]{assert(std::string(axr_authority_last_failure())=="none");});isolated.join();
    const std::string key(32,'k');
    assert(Digest("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    auto encrypted=Encrypt(key,"private","job-1");assert(encrypted.find("private")==std::string::npos);
    assert(Decrypt(key,encrypted,"job-1")=="private");bool denied=false;
    try{Decrypt(key,encrypted,"job-2");}catch(...){denied=true;}assert(denied);
    assert(ValidTransition("Executing","Unknown"));assert(!ValidTransition("Unknown","Ready"));
    Json record=CommitRecord(Json::object(),{{"state","Prepared"}},"intent",Now());
    assert(VerifyRecord(record,Json::object()));record["job"]["state"]="Completed";assert(!VerifyRecord(record,Json::object()));
    const auto dir=std::filesystem::temp_directory_path()/Utf8Path("AXR-验证-"+RandomId());std::filesystem::create_directory(dir);
    Json a{{"principal","agent:test"},{"resource",{{"platform","test"},{"account_id","a"},{"conversation_id","c"}}},
        {"operation","messages.read"},{"purpose","test"},{"payload",Json::object()},
        {"sources",Json::array()},{"destination","local"},{"workflow","manual"},{"execution_id",RandomId()}};
    {
        auto fileRead=a;fileRead["operation"]="files.read";
        assert(Risk(fileRead)==1);
        fileRead["sources"]=Json::array({Json{{"resource",a["resource"]},{"reference","fixture-file"},{"data_class","sensitive"},{"trust","untrusted-external"}}});
        assert(Risk(fileRead)==4);
        Guard guard(dir/"guard.db",key);
        Json b{{"principal","agent:test"},{"resource",a["resource"]},{"operations",Json::array({"messages.read"})},
            {"purpose","test"},{"expires_at",Now()+60},{"max_uses",1},{"destinations",Json::array()},
            {"classes",Json::array({"workspace-normal"})},{"intent",nullptr},{"workflow","manual"}};
        guard.IssueOwner(b,Now());guard.Check(a,Now());auto reservation=guard.Consume(a,Now());denied=false;
        try{guard.Check(a,Now());}catch(...){denied=true;}assert(denied);
        CheckLegacyProof(guard,a,reservation,dir/"guard.db");
        guard.RevokeOwner(reservation[0]);
        denied=false;try{guard.Revalidate(a,reservation[0],reservation[1],Now());}catch(...){denied=true;}assert(denied);
        auto classified=a;
        classified["sources"]=Json::array({Json{{"resource",a["resource"]},{"reference","query:fixture"},
            {"data_class","personal"},{"trust","untrusted-external"}}});
        guard.IssueOwner(b,Now());denied=false;
        try{guard.Check(classified,Now());}catch(...){denied=true;}assert(denied);
        b["classes"]=Json::array({"personal"});guard.IssueOwner(b,Now());
        reservation=guard.Consume(classified,Now());
        CheckLegacyProof(guard,classified,reservation,dir/"guard.db");
        denied=false;try{guard.Check(classified,Now());}catch(...){denied=true;}assert(denied);
        classified["sources"][0]["data_class"]="sensitive";b["classes"]=Json::array({"sensitive"});
        b["intent"]=IntentSeal(classified);guard.IssueOwner(b,Now());
        reservation=guard.Consume(classified,Now());
        CheckLegacyProof(guard,classified,reservation,dir/"guard.db");
    }
    assert(DurableWrite(dir/"record.json",record.dump()));
#if !defined(_WIN32)
    WorkerSupervisor worker;assert(worker.Start("/bin/sleep",{"2"},30));
    std::this_thread::sleep_for(std::chrono::milliseconds(60));assert(worker.Poll()==WorkerProcessState::TimedOut);
    assert(worker.Start("/usr/bin/true",{},1000));std::this_thread::sleep_for(std::chrono::milliseconds(30));
    assert(worker.Poll()==WorkerProcessState::Exited);
#else
    const char* systemRoot=std::getenv("SystemRoot");assert(systemRoot);
    auto command=Utf8Path(systemRoot)/"System32"/"cmd.exe";
    WorkerSupervisor worker;assert(worker.Start(command,{"/d","/c","exit 0"},5000));
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while(worker.Poll()==WorkerProcessState::Running&&std::chrono::steady_clock::now()<deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(worker.Poll()==WorkerProcessState::Exited);
    assert(worker.Start(command,{"/d","/c","ping -n 5 127.0.0.1 > nul"},30));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));assert(worker.Poll()==WorkerProcessState::TimedOut);
#endif
    std::filesystem::remove_all(dir);std::cout<<"native crypto, Guard, durability, state and worker gates passed\n";
}
