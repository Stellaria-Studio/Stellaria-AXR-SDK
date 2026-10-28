// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// No file-based proof fallback. Root identity comes from the OS connection and
// a protected fixed installation, never an endpoint's JSON description.
#include "axr/Commit.h"
#include "axr/Security.hpp"
#include "axr/WindowsInstallation.hpp"
#include "axr/TrustRoot.hpp"
#include <chrono>
#include <mutex>
#include <set>
#include <map>
#include <openssl/evp.h>
#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#endif
namespace Stellaria::AXR { namespace {
[[noreturn]] void Denied(){throw std::runtime_error("native_authority_channel_denied");}
double Now(){return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();}
std::string Unhex(const std::string& s){
    if(s.empty()||s.size()%2||s.size()>4096||s.find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
    std::string result;for(std::size_t i=0;i<s.size();i+=2)result+=char(std::stoi(s.substr(i,2),nullptr,16));return result;
}
#if defined(__APPLE__)
void Protected(const std::filesystem::path& path){
    for(auto p=path;!p.empty();p=p.parent_path()){
        struct stat st{};if(lstat(p.c_str(),&st)||S_ISLNK(st.st_mode)||st.st_uid!=0||(st.st_mode&0022))Denied();
        if(p==p.root_path())break;
    }
}
std::filesystem::path InstalledAuthority(){return "/Library/Application Support/Stellaria AXR/AXR Authority.app/Contents/MacOS/axr-authority";}
unsigned long Self(){return unsigned(getpid());}
#elif defined(_WIN32)
void Protected(const std::filesystem::path& path){
    try{VerifyWindowsInstallation(path.parent_path());}catch(...){Denied();}
}
std::filesystem::path InstalledAuthority(){PWSTR p=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,KF_FLAG_DEFAULT,nullptr,&p)))Denied();auto result=std::filesystem::path(p)/L"Stellaria AXR"/L"axr-authority.exe";CoTaskMemFree(p);return result;}
unsigned long Self(){return GetCurrentProcessId();}
#else
void Protected(const std::filesystem::path&){Denied();}
std::filesystem::path InstalledAuthority(){Denied();}
unsigned long Self(){Denied();}
#endif
void ValidateServer(const Json& actual){
    auto image=Utf8Path(actual.at("image").get<std::string>());
    if(image!=InstalledAuthority())Denied();Protected(image);
#if defined(__APPLE__)
    if(actual.at("signature_valid")!=true||actual.at("hardened_runtime")!=true||actual.at("signing_id")!="org.stellaria.axr.authority")Denied();
#elif defined(_WIN32)
    if(actual.at("user")!="S-1-5-18")Denied();
#else
    Denied();
#endif
}
class Channel {
#if defined(__APPLE__)
    int handle_=-1;
#elif defined(_WIN32)
    HANDLE handle_=INVALID_HANDLE_VALUE;
#endif
    Json identity_;std::string tx_,rx_,frameEpoch_;unsigned long long sent_=0,received_=0;
    unsigned long long Handle()const{
#if defined(__APPLE__)
        return static_cast<unsigned long long>(handle_);
#elif defined(_WIN32)
        return reinterpret_cast<uintptr_t>(handle_);
#else
        Denied();
#endif
    }
    void Stable(){if(PeerIdentity(Handle(),true)!=identity_)Denied();}
#if defined(_WIN32)
    DWORD Transfer(void* buffer,DWORD size,bool write){
        OVERLAPPED pending{};pending.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!pending.hEvent)Denied();
        DWORD n=0;BOOL ok=write?WriteFile(handle_,buffer,size,&n,&pending):ReadFile(handle_,buffer,size,&n,&pending);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){
            auto ready=WaitForSingleObject(pending.hEvent,5000);
            if(ready!=WAIT_OBJECT_0){CancelIoEx(handle_,&pending);GetOverlappedResult(handle_,&pending,&n,TRUE);CloseHandle(pending.hEvent);Denied();}
            ok=GetOverlappedResult(handle_,&pending,&n,FALSE);
        }
        CloseHandle(pending.hEvent);if(!ok)Denied();return n;
    }
#endif
    void Write(const std::string& raw){
        if(raw.size()>MaximumFrameBytes)Denied();Stable();
#if defined(__APPLE__)
        std::size_t n=0;while(n<raw.size()){auto wrote=send(handle_,raw.data()+n,raw.size()-n,0);if(wrote<=0)Denied();n+=std::size_t(wrote);}
#elif defined(_WIN32)
        if(Transfer(const_cast<char*>(raw.data()),DWORD(raw.size()),true)!=raw.size())Denied();
#else
        Denied();
#endif
    }
    std::string Read(){
        Stable();std::string raw;
#if defined(__APPLE__)
        char buffer[4096];
        while(true){auto n=recv(handle_,buffer,sizeof(buffer),0);if(n<=0)Denied();raw.append(buffer,std::size_t(n));if(raw.size()>MaximumFrameBytes)Denied();
            auto pos=raw.find('\n');if(pos!=std::string::npos){if(pos!=raw.size()-1)Denied();return raw;}}
#elif defined(_WIN32)
        raw.resize(MaximumFrameBytes+1);auto n=Transfer(raw.data(),DWORD(raw.size()),false);if(n>MaximumFrameBytes)Denied();raw.resize(n);return raw;
#else
        Denied();
#endif
    }
    void Send(const Json& payload){Json body={{"version",1},{"epoch",frameEpoch_},{"sequence",++sent_},{"payload",payload}};Write(Json{{"body",body},{"mac",Hmac(tx_,body.dump())}}.dump()+"\n");}
    Json Receive(){auto value=ParseBounded(Read());const auto& b=value.at("body");
        if(value.size()!=2||b.size()!=4||b.at("version")!=1||b.at("epoch")!=frameEpoch_||!b.at("sequence").is_number_unsigned()||b.at("sequence")!=received_+1||
           !ConstantEqual(value.at("mac").get<std::string>(),Hmac(rx_,b.dump())))Denied();++received_;return b.at("payload");}
public:
    std::string publicKey,rootId,epoch;Json self;
    explicit Channel(const std::string& endpoint){
        try{
#if defined(__APPLE__)
            if(endpoint.empty()||endpoint.size()>=sizeof(sockaddr_un::sun_path)||endpoint.find('\0')!=std::string::npos)Denied();
            handle_=socket(AF_UNIX,SOCK_STREAM,0);if(handle_<0)Denied();
            timeval timeout{5,0};setsockopt(handle_,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(handle_,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
            int yes=1;setsockopt(handle_,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes));
            sockaddr_un address{};address.sun_family=AF_UNIX;std::copy(endpoint.begin(),endpoint.end(),address.sun_path);
            if(connect(handle_,reinterpret_cast<sockaddr*>(&address),sizeof(address)))Denied();
#elif defined(_WIN32)
            if(!endpoint.starts_with("\\\\.\\pipe\\Stellaria.AXR.")||endpoint.size()>256)Denied();
            auto path=Utf8Path(endpoint);if(!WaitNamedPipeW(path.c_str(),5000))Denied();
            handle_=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);if(handle_==INVALID_HANDLE_VALUE)Denied();
            DWORD mode=PIPE_READMODE_MESSAGE;if(!SetNamedPipeHandleState(handle_,&mode,nullptr,nullptr))Denied();
#else
            (void)endpoint;Denied();
#endif
            identity_=PeerIdentity(Handle(),true);ValidateServer(identity_);self=ProcessIdentity(Self());
            auto hello=ParseBounded(Read());if(hello.size()!=5||hello.at("version")!=2)Denied();
            epoch=hello.at("epoch").get<std::string>();auto nonce=hello.at("nonce").get<std::string>();
            if(epoch.empty()||epoch.size()>128||nonce.size()!=64||nonce.find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
            auto encoded=hello.at("key").get<std::string>();if(encoded.size()!=44||encoded.back()!='=')Denied();
            std::string key(33,'\0');int n=EVP_DecodeBlock(reinterpret_cast<unsigned char*>(key.data()),reinterpret_cast<const unsigned char*>(encoded.data()),int(encoded.size()));if(n!=33)Denied();key.resize(32);
            auto& authority=hello.at("authority");if(authority.size()!=2)Denied();
            auto hex=authority.at("public_key").get<std::string>();publicKey=Unhex(hex);rootId=authority.at("root_id").get<std::string>();
            if(publicKey.size()!=65||publicKey[0]!=4||rootId!=Digest(Json(hex).dump()))Denied();
            frameEpoch_=epoch+":"+nonce;tx_=Unhex(Hmac(key,"AXR-IPC-v2/request"));rx_=Unhex(Hmac(key,"AXR-IPC-v2/response"));
            Send({{"op","session.open"}});if(Receive()!=Json{{"op","session.ready"}})Denied();
        }catch(...){Close();throw;}
    }
    ~Channel(){Close();}
    void Close(){
#if defined(__APPLE__)
        if(handle_>=0){close(handle_);handle_=-1;}
#elif defined(_WIN32)
        if(handle_!=INVALID_HANDLE_VALUE){CloseHandle(handle_);handle_=INVALID_HANDLE_VALUE;}
#endif
    }
    Json Request(const char* op,const Json& payload){Send({{"operation",op},{"payload",payload}});auto result=Receive();if(result.size()!=2||result.at("ok")!=true)Denied();return result.at("result");}
    void CheckProof(const Json& p){
        if(p.size()!=2||!VerifyRootSignature(publicKey,p.at("body").dump(),Unhex(p.at("signature").get<std::string>())))Denied();
        const auto& b=p.at("body");if(b.at("root_id")!=rootId||b.at("epoch")!=epoch||b.at("kind")!="execution"||
            b.at("helper")!=Digest(self.dump())||b.at("helper_pid")!=self.at("pid")||b.at("helper_birth")!=self.at("birth")||
            !b.at("expires").is_number()||b.at("expires").get<double>()<=Now())Denied();
        if(b.at("seal")!=IntentSeal(b.at("action")))Denied();
    }
};
std::mutex claimsMutex;std::map<std::string,Json> claimed;std::set<std::string> attempted;
thread_local const char* lastFailure="none";
thread_local std::unique_ptr<Channel> connection;
thread_local std::string connectionEndpoint;
thread_local bool connectionFailed=false;
Channel& Connection(const char* endpoint){
    if(connectionFailed||!endpoint)Denied();
    if(!connection){connectionEndpoint=endpoint;connection=std::make_unique<Channel>(connectionEndpoint);}
    if(connectionEndpoint!=endpoint)Denied();
    return *connection;
}
void FailConnection(){connectionFailed=true;connection.reset();}
void Scope(const Json& proof,const Json& scope){
    const auto& action=proof.at("body").at("action");ValidateAction(action);
    if(!scope.is_object()||scope.size()<2||scope.size()>5)Denied();
    for(auto i=scope.begin();i!=scope.end();++i)if(i.key()!="operations"&&i.key()!="resource"&&i.key()!="text"&&i.key()!="visual_binding"&&i.key()!="navigation_binding")Denied();
    if(scope.at("resource")!=action.at("resource")||scope.at("operations")!=Json::array({action.at("operation")}))Denied();
    for(auto field:{"text","visual_binding","navigation_binding"}){
        if(action.at("payload").contains(field)!=scope.contains(field))Denied();
        if(scope.contains(field)&&scope.at(field)!=action.at("payload").at(field))Denied();
    }
}
int Invoke(const char* endpoint,const char* encoded,const char* scope,bool claim){
    const char* stage="scope";lastFailure="none";
    try{
        if(!endpoint||!encoded||!scope)Denied();auto proof=ParseBounded(encoded);Scope(proof,ParseBounded(scope));
        // Reuse the authenticated directional-MAC session within this helper
        // birth. Every frame still revalidates the OS peer; any error closes
        // the channel permanently. There is no reconnect or request replay.
        stage="channel";auto& channel=Connection(endpoint);stage="proof";channel.CheckProof(proof);
        const auto& body=proof.at("body");auto nonce=body.at("nonce").get<std::string>();std::lock_guard lock(claimsMutex);
        if(claim){
            if(attempted.size()>=10000||!attempted.insert(nonce).second)Denied();
            stage="claim";auto permit=channel.Request("Commit",{{"phase","claim"},{"proof",proof}});
            stage="permit";
            if(!VerifyCommitPermit(permit,channel.publicKey,channel.rootId,channel.epoch,nonce,body.at("seal").get<std::string>(),channel.self,Now()))Denied();
            claimed[nonce]=permit;return 1;
        }
        stage="preflight";auto check=channel.Request("Access",{{"phase","preflight"},{"proof",proof}});
        if(check.at("ready")!=true||check.at("nonce")!=nonce||check.at("seal")!=body.at("seal"))Denied();
        if(check.at("claimed")==true){auto found=claimed.find(nonce);if(found==claimed.end()||!VerifyCommitPermit(found->second,channel.publicKey,channel.rootId,channel.epoch,nonce,body.at("seal").get<std::string>(),channel.self,Now()))Denied();}
        return 1;
    }catch(...){lastFailure=stage;FailConnection();return 0;}
}
} }
extern "C" int axr_authority_preflight(const char* e,const char* p,const char* s){return Stellaria::AXR::Invoke(e,p,s,false);}
extern "C" int axr_authority_claim(const char* e,const char* p,const char* s){return Stellaria::AXR::Invoke(e,p,s,true);}
extern "C" const char* axr_authority_last_failure(){return Stellaria::AXR::lastFailure;}
extern "C" int axr_authority_local_permit(const char* e,const char* p,const char* s){
    using namespace Stellaria::AXR;
    try{
        if(!e||!p||!s||connectionFailed||!connection||connectionEndpoint!=e)Denied();
        auto proof=ParseBounded(p);Scope(proof,ParseBounded(s));connection->CheckProof(proof);
        if(connection->self.at("pid")!=Self())Denied();
        const auto& body=proof.at("body");auto nonce=body.at("nonce").get<std::string>();
        std::lock_guard lock(claimsMutex);auto found=claimed.find(nonce);
        const double permitNow=std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
        if(found==claimed.end()||!VerifyCommitPermit(found->second,connection->publicKey,connection->rootId,
            connection->epoch,nonce,body.at("seal").get<std::string>(),connection->self,permitNow))Denied();
        return 1;
    }catch(...){lastFailure="local_permit";FailConnection();return 0;}
}
extern "C" int axr_authority_observe(const char* e,const char* p,int verified,const char* evidence){
    using namespace Stellaria::AXR;
    try{
        if(!e||!p||!evidence||(verified!=0&&verified!=1))Denied();std::string digest(evidence);
        if(digest.size()!=64||digest.find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
        auto proof=ParseBounded(p);auto& channel=Connection(e);channel.CheckProof(proof);std::lock_guard lock(claimsMutex);
        auto found=claimed.find(proof.at("body").at("nonce").get<std::string>());if(found==claimed.end())Denied();
        auto result=channel.Request("Commit",{{"phase","receipt"},{"proof",proof},{"verified",verified==1},{"evidence_digest",digest}});
        claimed.erase(found);return result.at("retry")==false&&result.at("delivery_confirmed")==false?1:0;
    }catch(...){lastFailure="observe";FailConnection();return 0;}
}
