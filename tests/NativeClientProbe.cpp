// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Commit.h"
#include "axr/Core.hpp"
#include <iostream>
int main(int argc,char** argv){
    if(argc!=2)return 2;
    auto resource=Stellaria::AXR::Json{{"platform","fixture"},{"account_id","account"},{"conversation_id","peer"}};
    Stellaria::AXR::Json action={{"principal","agent"},{"resource",resource},{"operation","messages.read"},{"purpose","test"},{"payload",Stellaria::AXR::Json::object()},
        {"sources",Stellaria::AXR::Json::array()},{"destination","local"},{"workflow","manual"},{"execution_id","probe"}};
    auto proof=Stellaria::AXR::Json{{"body",{{"action",action}}},{"signature","00"}}.dump();
    auto scope=Stellaria::AXR::Json{{"resource",resource},{"operations",Stellaria::AXR::Json{"messages.read"}}}.dump();
    std::cout<<axr_authority_preflight(argv[1],proof.c_str(),scope.c_str())<<'\n';
}
