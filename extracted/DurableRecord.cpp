// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// AXR authenticated commit, load, write and sync;
// no compute jobs, scheduler, Provider, project format or runtime dependencies.
#include "axr/Core.hpp"
#include <fstream>
#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
namespace Stellaria::AXR {
Json CommitRecord(const Json& previous,const Json& snapshot,std::string_view kind,double now) {
    Json record{{"version",1},{"sequence",previous.empty()?1:previous.at("sequence").get<unsigned>()+1},
        {"previous",previous.value("sha256",std::string{})},{"kind",kind},{"at",now},{"job",snapshot}};
    record["sha256"]=Digest(record.dump());return record;
}
bool VerifyRecord(const Json& record,const Json& previous) {
    try {
        auto body=record;auto checksum=body.at("sha256").get<std::string>();body.erase("sha256");
        return body.at("sequence")== (previous.empty()?1:previous.at("sequence").get<unsigned>()+1)&&
            body.at("previous")==previous.value("sha256",std::string{})&&ConstantEqual(Digest(body.dump()),checksum);
    }catch(...){return false;}
}
bool DurableWrite(const std::filesystem::path& path,std::string_view bytes) {
    auto temporary=path;temporary+= "."+RandomId()+".tmp";
#if defined(_WIN32)
    HANDLE file=CreateFileW(temporary.wstring().c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return false;
    DWORD count=0;bool ok=WriteFile(file,bytes.data(),DWORD(bytes.size()),&count,nullptr)&&count==bytes.size()&&FlushFileBuffers(file);
    CloseHandle(file);
    ok=ok&&MoveFileExW(temporary.wstring().c_str(),path.wstring().c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
#else
    int file=open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(file<0)return false;
    std::size_t written=0;bool ok=true;
    while(written<bytes.size()){auto n=write(file,bytes.data()+written,bytes.size()-written);if(n<0&&errno==EINTR)continue;if(n<=0){ok=false;break;}written+=std::size_t(n);}
    ok=ok&&fsync(file)==0;close(file);ok=ok&&rename(temporary.c_str(),path.c_str())==0;
    if(ok){int directory=open(path.parent_path().c_str(),O_RDONLY);if(directory<0)ok=false;else{ok=fsync(directory)==0;close(directory);}}
#endif
    if(!ok){std::error_code error;std::filesystem::remove(temporary,error);}return ok;
}
}
