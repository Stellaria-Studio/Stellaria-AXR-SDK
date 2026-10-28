// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Core.hpp"
#include <cassert>
#include <sqlite3.h>
#include <iostream>
#include <atomic>
#include <barrier>
#include <thread>
using namespace Stellaria::AXR;
template<class F> void denied(F f,const std::string& expected="") {
    bool rejected=false;
    try{f();}catch(const std::exception& e){rejected=expected.empty()||e.what()==expected;}
    assert(rejected);
}
int main() {
    const auto root=std::filesystem::temp_directory_path()/("axr-lookup-test-"+RandomId());
    std::filesystem::create_directory(root);
    try {
        {
            const auto db=root/"guard.db";Guard guard(db,std::string(32,'t'));
            const double now=1000;
            Json a{{"principal","agent:test"},{"resource",{{"platform","fixture"},{"account_id","a"},{"conversation_id","c"}}},
                {"operation","messages.read"},{"purpose","test"},{"payload",Json::object()},{"sources",Json::array()},
                {"destination","local"},{"workflow","fixture"},{"execution_id",RandomId()}};
            Json g{{"principal",a["principal"]},{"resource",a["resource"]},{"operations",Json::array({"messages.read"})},
                {"purpose","test"},{"expires_at",now+2},{"max_uses",100},{"destinations",Json::array()},
                {"classes",Json::array({"workspace-normal"})},{"intent",nullptr},{"workflow","fixture"}};
            guard.IssueOwner(g,now);
            auto exact=g;exact["intent"]=IntentSeal(a);exact["max_uses"]=1;exact["expires_at"]=now+120;
            const auto id=guard.IssueOwner(exact,now);
            auto claim=guard.Consume(a,now);assert(claim[0]==id);
            guard.Revalidate(a,claim[0],claim[1],now+3);
            denied([&]{guard.Check(a,now+3);}); // exact quota exhausted, broad expired
            g["expires_at"]=now+180;const auto fresh=guard.IssueOwner(g,now+3);
            assert(guard.Check(a,now+3)==fresh);
            guard.RevokeOwner(fresh);
            denied([&]{guard.Check(a,now+3);}); // no cross-call policy cache
            denied([&]{guard.Revalidate(a,claim[0],claim[1],now+3);});
            g["expires_at"]=now+240;guard.IssueOwner(g,now+3);guard.Check(a,now+3);
            sqlite3* connection=nullptr;auto path=db.u8string();
            assert(sqlite3_open(reinterpret_cast<const char*>(path.c_str()),&connection)==SQLITE_OK);
            assert(sqlite3_exec(connection,"UPDATE security_meta SET mac='tampered' WHERE name='policy-version'",nullptr,nullptr,nullptr)==SQLITE_OK);
            denied([&]{guard.Check(a,now+3);},"policy_version_integrity_failed");
            sqlite3_close(connection);
        }
        {
            Guard guard(root/"concurrent.db",std::string(32,'c'));
            Json a{{"principal","agent:parallel"},{"resource",{{"platform","fixture"},{"account_id","a"},{"conversation_id","c"}}},
                {"operation","messages.read"},{"purpose","parallel"},{"payload",Json::object()},{"sources",Json::array()},
                {"destination","local"},{"workflow","fixture"},{"execution_id",RandomId()}};
            guard.IssueOwner({{"principal",a["principal"]},{"resource",a["resource"]},{"operations",Json::array({"messages.read"})},
                {"purpose","parallel"},{"expires_at",1120},{"max_uses",32},{"destinations",Json::array()},
                {"classes",Json::array({"workspace-normal"})},{"intent",nullptr},{"workflow","fixture"}},1000);
            std::barrier start(8);std::atomic<int> accepted=0,unexpected=0;std::vector<std::thread> workers;
            for(int t=0;t<8;++t)workers.emplace_back([&]{start.arrive_and_wait();for(int i=0;i<8;++i){
                try{guard.Consume(a,1000);++accepted;}
                catch(const std::exception& e){if(std::string(e.what())!="authority_missing_expired_revoked_or_exhausted")++unexpected;}
            }});
            for(auto& worker:workers)worker.join();
            if(accepted!=32||unexpected!=0){
                std::cerr<<"concurrent quota failure: accepted="<<accepted<<" unexpected="<<unexpected<<'\n';
                return 1;
            }
        }
        std::filesystem::remove_all(root);
        std::cout<<"exact selection, expiry, quota, revocation and policy integrity passed\n";
    }catch(...){std::filesystem::remove_all(root);throw;}
}
