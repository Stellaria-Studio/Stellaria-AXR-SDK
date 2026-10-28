// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/Security.hpp"
#include <array>
#include <fstream>
#include <stdexcept>
#include <openssl/evp.h>
#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#endif
namespace Stellaria::AXR {
namespace {
std::string FileHash(const std::filesystem::path& path){
    std::ifstream stream(path,std::ios::binary);if(!stream)throw std::runtime_error("identity_image_unreadable");
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!context||EVP_DigestInit_ex(context.get(),EVP_sha256(),nullptr)!=1)throw std::runtime_error("identity_hash_unavailable");
    std::array<char,65536> buffer{};std::size_t total=0;
    while(stream){stream.read(buffer.data(),buffer.size());auto n=std::size_t(stream.gcount());total+=n;
        if(total>512*1024*1024||EVP_DigestUpdate(context.get(),buffer.data(),n)!=1)throw std::runtime_error("identity_image_budget");}
    if(!stream.eof())throw std::runtime_error("identity_image_unreadable");
    std::array<unsigned char,32> bytes{};unsigned size=0;
    if(EVP_DigestFinal_ex(context.get(),bytes.data(),&size)!=1||size!=32)throw std::runtime_error("identity_hash_unavailable");
    constexpr char hex[]="0123456789abcdef";std::string result;for(auto v:bytes){result+=hex[v>>4];result+=hex[v&15];}return result;
}
#if defined(__APPLE__)
std::string String(CFTypeRef v){
    if(!v||CFGetTypeID(v)!=CFStringGetTypeID())return "";
    std::array<char,8192> b{};if(!CFStringGetCString((CFStringRef)v,b.data(),b.size(),kCFStringEncodingUTF8))return "";return b.data();
}
std::string Data(CFTypeRef v){
    if(!v||CFGetTypeID(v)!=CFDataGetTypeID())return "";
    auto d=(CFDataRef)v;constexpr char hex[]="0123456789abcdef";std::string out;
    for(CFIndex i=0;i<CFDataGetLength(d);++i){auto c=CFDataGetBytePtr(d)[i];out+=hex[c>>4];out+=hex[c&15];}return out;
}
#elif defined(_WIN32)
std::string Utf8(const std::wstring& v){int n=WideCharToMultiByte(CP_UTF8,0,v.data(),int(v.size()),nullptr,0,nullptr,nullptr);std::string out(n,'\0');WideCharToMultiByte(CP_UTF8,0,v.data(),int(v.size()),out.data(),n,nullptr,nullptr);return out;}
#endif
}
Json ProcessIdentity(unsigned long pid){
#if defined(__APPLE__)
    proc_bsdinfo before{},after{};
    if(!pid||proc_pidinfo(int(pid),PROC_PIDTBSDINFO,0,&before,sizeof(before))!=sizeof(before))throw std::runtime_error("identity_process_unavailable");
    std::array<char,PROC_PIDPATHINFO_MAXSIZE> path{};
    if(proc_pidpath(int(pid),path.data(),path.size())<=0)throw std::runtime_error("identity_image_unavailable");
    auto number=CFNumberCreate(nullptr,kCFNumberLongType,&pid);const void* keys[]={kSecGuestAttributePid};const void* values[]={number};
    auto attrs=CFDictionaryCreate(nullptr,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFRelease(number);
    SecCodeRef code=nullptr;auto copied=SecCodeCopyGuestWithAttributes(nullptr,attrs,kSecCSDefaultFlags,&code);CFRelease(attrs);
    bool valid=false;std::string team,identifier,hash;unsigned flags=0;
    if(copied==errSecSuccess&&code){
        valid=SecCodeCheckValidity(code,kSecCSStrictValidate,nullptr)==errSecSuccess;CFDictionaryRef info=nullptr;
        if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info)==errSecSuccess&&info){
            team=String(CFDictionaryGetValue(info,kSecCodeInfoTeamIdentifier));identifier=String(CFDictionaryGetValue(info,kSecCodeInfoIdentifier));
            hash=Data(CFDictionaryGetValue(info,kSecCodeInfoUnique));
            auto f=CFDictionaryGetValue(info,kSecCodeInfoFlags);if(f&&CFGetTypeID(f)==CFNumberGetTypeID())CFNumberGetValue((CFNumberRef)f,kCFNumberIntType,&flags);
            CFRelease(info);
        }CFRelease(code);
    }
    auto imageHash=FileHash(std::filesystem::path(path.data()));
    if(proc_pidinfo(int(pid),PROC_PIDTBSDINFO,0,&after,sizeof(after))!=sizeof(after)||before.pbi_start_tvsec!=after.pbi_start_tvsec||before.pbi_start_tvusec!=after.pbi_start_tvusec)
        throw std::runtime_error("identity_process_replaced");
    return {{"pid",pid},{"user",std::to_string(before.pbi_uid)},{"birth",std::to_string(before.pbi_start_tvsec)+":"+std::to_string(before.pbi_start_tvusec)},
        {"image",path.data()},{"image_sha256",imageHash},{"signature_valid",valid},{"team",team},{"signing_id",identifier},{"cdhash",hash},
        {"hardened_runtime",bool(flags&0x10000)},{"app_container",false},{"platform","macos"}};
#elif defined(_WIN32)
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,DWORD(pid));if(!process)throw std::runtime_error("identity_process_unavailable");
    try{
        FILETIME created{},exited{},kernel{},user{};std::array<wchar_t,32768> image{};DWORD length=DWORD(image.size());
        if(!GetProcessTimes(process,&created,&exited,&kernel,&user)||!QueryFullProcessImageNameW(process,0,image.data(),&length))throw std::runtime_error("identity_image_unavailable");
        HANDLE token=nullptr;if(!OpenProcessToken(process,TOKEN_QUERY,&token))throw std::runtime_error("identity_token_unavailable");
        DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);std::vector<unsigned char> buffer(size);std::string sid;
        if(!size||!GetTokenInformation(token,TokenUser,buffer.data(),size,&size)){CloseHandle(token);throw std::runtime_error("identity_user_unavailable");}
        LPWSTR raw=nullptr;if(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&raw)){sid=Utf8(raw);LocalFree(raw);}
        DWORD container=0;size=sizeof(container);GetTokenInformation(token,TokenIsAppContainer,&container,size,&size);CloseHandle(token);
        WINTRUST_FILE_INFO file{};file.cbStruct=sizeof(file);file.pcwszFilePath=image.data();
        WINTRUST_DATA trust{};trust.cbStruct=sizeof(trust);trust.dwUIChoice=WTD_UI_NONE;trust.fdwRevocationChecks=WTD_REVOKE_NONE;
        trust.dwUnionChoice=WTD_CHOICE_FILE;trust.pFile=&file;trust.dwStateAction=WTD_STATEACTION_VERIFY;trust.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;
        GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;bool signedImage=WinVerifyTrust(nullptr,&action,&trust)==ERROR_SUCCESS;std::string signer;
        if(signedImage){
            auto data=WTHelperProvDataFromStateData(trust.hWVTStateData);auto chain=data?WTHelperGetProvSignerFromChain(data,0,FALSE,0):nullptr;
            if(chain&&chain->csCertChain){std::array<unsigned char,32> hash{};DWORD n=DWORD(hash.size());
                if(CertGetCertificateContextProperty(chain->pasCertChain[0].pCert,CERT_SHA256_HASH_PROP_ID,hash.data(),&n)){
                    constexpr char hex[]="0123456789abcdef";for(DWORD i=0;i<n;++i){signer+=hex[hash[i]>>4];signer+=hex[hash[i]&15];}
                }}
        }
        trust.dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(nullptr,&action,&trust);
        auto path=std::filesystem::path(image.data());auto imageHash=FileHash(path);CloseHandle(process);
        return {{"pid",pid},{"user",sid},{"birth",std::to_string((static_cast<unsigned long long>(created.dwHighDateTime)<<32)|created.dwLowDateTime)},
            {"image",Utf8(std::wstring(image.data(),length))},{"image_sha256",imageHash},{"signature_valid",signedImage},{"signer_sha256",signer},
            {"app_container",bool(container)},{"hardened_runtime",false},{"platform","windows"}};
    }catch(...){CloseHandle(process);throw;}
#else
    (void)pid;throw std::runtime_error("native_identity_platform_unavailable");
#endif
}
Json PeerIdentity(unsigned long long handle,bool serverPeer){
#if defined(__APPLE__)
    int pid=0;socklen_t size=sizeof(pid);uid_t uid=0;gid_t gid=0;
    if(getpeereid(int(handle),&uid,&gid)||getsockopt(int(handle),SOL_LOCAL,LOCAL_PEERPID,&pid,&size)||pid<=0)throw std::runtime_error("ipc_peer_identity_unavailable");
    auto identity=ProcessIdentity(unsigned(pid));if(identity.at("user")!=std::to_string(uid))throw std::runtime_error("ipc_peer_user_changed");return identity;
#elif defined(_WIN32)
    ULONG pid=0;auto pipe=reinterpret_cast<HANDLE>(static_cast<uintptr_t>(handle));
    if(!(serverPeer?GetNamedPipeServerProcessId(pipe,&pid):GetNamedPipeClientProcessId(pipe,&pid)))throw std::runtime_error("ipc_peer_identity_unavailable");
    return ProcessIdentity(pid);
#else
    (void)handle;(void)serverPeer;throw std::runtime_error("native_identity_platform_unavailable");
#endif
}
}
