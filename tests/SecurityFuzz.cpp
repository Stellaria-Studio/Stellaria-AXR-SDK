// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Security.hpp"
#include "axr/TrustRoot.hpp"
using namespace Stellaria::AXR;
extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data,std::size_t size){
    if(size>MaximumFrameBytes/2)return 0;
    try{
        auto value=ParseBounded(std::string_view(reinterpret_cast<const char*>(data),size));
        if(value.is_object()){
            try{ValidateTaskContract(value);}catch(...){}
            try{ValidateAction(value);}catch(...){}
            if(value.contains("contract")&&value.contains("action")&&value.contains("host"))SecurityDecision(value["contract"],value["action"],value["host"],1000);
        }
        auto encoded=value.dump();auto encrypted=Encrypt(std::string(32,'f'),encoded,"fuzz");
        if(Decrypt(std::string(32,'f'),encrypted,"fuzz")!=encoded)__builtin_trap();
        auto record=CommitRecord(Json::object(),value,"fuzz",1);
        if(!VerifyRecord(record,Json::object()))__builtin_trap();
    }catch(...){}
    return 0;
}
