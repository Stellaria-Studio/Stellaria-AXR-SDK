// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Synthetic owner-controlled state only. No OS authentication or application IO.
#include "axr/Core.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
using namespace Stellaria::AXR;
int main() {
    const auto root=std::filesystem::temp_directory_path()/("axr-lookup-"+RandomId());
    std::filesystem::create_directory(root);
    try {
        std::vector<double> samples;
        {
            Guard guard(root/"guard.db",std::string(32,'b'));
            const double now=1000;
            Json action{{"principal","agent:benchmark"},{"resource",{{"platform","fixture"},{"account_id","synthetic"},{"conversation_id","lookup"}}},
                {"operation","messages.read"},{"purpose","benchmark"},{"payload",Json::object()},{"sources",Json::array()},
                {"destination","local"},{"workflow","fixture"},{"execution_id",RandomId()}};
            Json grant{{"principal",action["principal"]},{"resource",action["resource"]},{"operations",Json::array({"messages.read"})},
                {"purpose","benchmark"},{"expires_at",now+120},{"max_uses",1000},{"destinations",Json::array()},
                {"classes",Json::array({"workspace-normal"})},{"intent",nullptr},{"workflow","fixture"}};
            for(int i=0;i<1000;++i)guard.IssueOwner(grant,now);
            for(int sample=0;sample<5;++sample) {
                const auto start=std::chrono::steady_clock::now();
                for(int i=0;i<20;++i)guard.Check(action,now);
                samples.push_back(std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count()/20);
            }
        }
        std::filesystem::remove_all(root);
        std::sort(samples.begin(),samples.end());
        std::cout<<Json{{"scenario","1000-active-broad-grants"},{"lookups_per_sample",20},{"samples",samples},
            {"median_ms_per_lookup",samples[2]},{"application_io",false}}.dump()<<'\n';
    }catch(...){std::filesystem::remove_all(root);throw;}
}
