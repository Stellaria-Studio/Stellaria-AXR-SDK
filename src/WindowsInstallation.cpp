// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/WindowsInstallation.hpp"
#include "axr/Security.hpp"
#include <map>
#include <mutex>
#include <set>
#include <array>
#include <fstream>
#include <openssl/evp.h>
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <wincred.h>
#include "WindowsInteractiveHost.hpp"
#endif
namespace Stellaria::AXR {
std::filesystem::path WindowsInstallationRoot(){
#if defined(_WIN32)
    PWSTR value=nullptr;
    if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,KF_FLAG_DEFAULT,nullptr,&value)))
        throw std::runtime_error("authority_installation_unavailable");
    auto path=std::filesystem::path(value)/L"Stellaria AXR";CoTaskMemFree(value);return path;
#else
    throw std::runtime_error("windows_installation_required");
#endif
}
#if defined(_WIN32)
namespace {
std::string FileDigest(const std::filesystem::path& path){
    using WindowsInteractiveHost::Handle;
    Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    BY_HANDLE_FILE_INFORMATION info{};FILE_BASIC_INFO basic{};
    if(file.value==INVALID_HANDLE_VALUE||!GetFileInformationByHandle(file.value,&info)||!GetFileInformationByHandleEx(file.value,FileBasicInfo,&basic,sizeof(basic))||
        info.nNumberOfLinks!=1||(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||info.nFileSizeHigh||info.nFileSizeLow>512u*1024*1024)
        throw std::runtime_error("authority_installation_file_invalid");
    std::vector<uint64_t> stamp={info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow,info.nFileSizeLow,
        uint64_t(basic.CreationTime.QuadPart),uint64_t(basic.ChangeTime.QuadPart),uint64_t(basic.LastWriteTime.QuadPart)};
    static std::mutex mutex;static std::map<std::filesystem::path,std::pair<std::vector<uint64_t>,std::string>> cache;
    std::lock_guard lock(mutex);auto previous=cache.find(path);
    if(previous!=cache.end()&&previous->second.first==stamp)return previous->second.second;
    auto context=EVP_MD_CTX_new();if(!context)throw std::runtime_error("authority_installation_hash_failed");
    struct Release{EVP_MD_CTX* value;~Release(){EVP_MD_CTX_free(value);}} release{context};
    if(EVP_DigestInit_ex(context,EVP_sha256(),nullptr)!=1)throw std::runtime_error("authority_installation_hash_failed");
    std::array<char,65536> block{};DWORD size=0;uint64_t total=0;
    do{if(!ReadFile(file.value,block.data(),DWORD(block.size()),&size,nullptr))throw std::runtime_error("authority_installation_hash_failed");
        total+=size;if(total>info.nFileSizeLow||EVP_DigestUpdate(context,block.data(),size)!=1)throw std::runtime_error("authority_installation_hash_failed");}while(size);
    unsigned char hash[32];unsigned length=0;
    if(total!=info.nFileSizeLow||EVP_DigestFinal_ex(context,hash,&length)!=1||length!=32)throw std::runtime_error("authority_installation_hash_failed");
    const char* digits="0123456789abcdef";std::string value;for(auto byte:hash){value+=digits[byte>>4];value+=digits[byte&15];}
    if(cache.size()>20000)cache.clear();cache[path]={std::move(stamp),value};return value;
}
void Protected(const std::filesystem::path& path,bool ancestor){
    auto attributes=GetFileAttributesW(path.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES)throw std::runtime_error("authority_installation_unavailable");
    if(attributes&FILE_ATTRIBUTE_REPARSE_POINT)throw std::runtime_error("authority_installation_reparse_denied");
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    auto status=GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&descriptor);
    struct Release {PSECURITY_DESCRIPTOR value;~Release(){if(value)LocalFree(value);}} release{descriptor};
    struct InstallerSid {PSID value=nullptr;
        InstallerSid(){if(!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&value))
            throw std::runtime_error("authority_installation_acl_unavailable");}
        ~InstallerSid(){if(value)LocalFree(value);}};
    static const InstallerSid installer;
    auto trusted=[&](PSID sid){return sid&&(IsWellKnownSid(sid,WinLocalSystemSid)||IsWellKnownSid(sid,WinBuiltinAdministratorsSid)||EqualSid(sid,installer.value));};
    if(status!=ERROR_SUCCESS||!acl)throw std::runtime_error("authority_installation_acl_unavailable");
    if(!trusted(owner))throw std::runtime_error("authority_installation_not_protected");
    for(DWORD i=0;i<acl->AceCount;++i){void* raw=nullptr;
        if(!GetAce(acl,i,&raw))throw std::runtime_error("authority_installation_not_protected");
        auto header=static_cast<ACE_HEADER*>(raw);
        if((header->AceFlags&INHERIT_ONLY_ACE)||header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)throw std::runtime_error("authority_installation_not_protected");
        auto ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
        DWORD writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD|
            DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
        if(ancestor)writes&=~(FILE_WRITE_DATA|FILE_APPEND_DATA); // Creating a sibling does not replace this protected directory.
        if((ace->Mask&writes)&&!trusted(&ace->SidStart))throw std::runtime_error("authority_installation_not_protected");
    }
}
}
#endif
void VerifyWindowsInstallation(const std::filesystem::path& directory){
#if defined(_WIN32)
    for(auto parent=directory;!parent.empty();parent=parent.parent_path()){
        Protected(parent,parent!=directory);if(parent==parent.root_path())break;
    }
    size_t count=0;
    for(const auto& entry:std::filesystem::recursive_directory_iterator(directory)){
        if(++count>20000)throw std::runtime_error("authority_installation_budget");
        Protected(entry.path(),false);
    }
#ifdef AXR_SECURITY_RELEASE
    VerifyWindowsRuntimeFiles(directory);
#endif
#else
    (void)directory;throw std::runtime_error("windows_installation_required");
#endif
}
void VerifyWindowsRuntimeFiles(const std::filesystem::path& directory){
#if defined(_WIN32)
    if(!directory.is_absolute()||directory.lexically_normal()!=directory)throw std::runtime_error("authority_installation_file_invalid");
    auto noReparse=[](const std::filesystem::path& path){auto attrs=GetFileAttributesW(path.c_str());
        if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("authority_installation_reparse_denied");};
    for(auto node=directory;!node.empty();node=node.parent_path()){noReparse(node);if(node==node.root_path())break;}
    size_t count=0;
    for(const auto& entry:std::filesystem::recursive_directory_iterator(directory)){
        if(++count>20000)throw std::runtime_error("authority_installation_budget");noReparse(entry.path());
    }
    auto manifest=directory/L"installation-review.json";
    if(!std::filesystem::is_regular_file(manifest)||std::filesystem::file_size(manifest)>2*1024*1024)
        throw std::runtime_error("authority_installation_manifest_required");
    Json review;
    try{review=Json::parse(std::ifstream(manifest));}catch(...){throw std::runtime_error("authority_installation_manifest_invalid");}
    if(!review.is_object()||review.size()!=2||review.value("version",Json{})!=2||!review.contains("files")||!review.at("files").is_object()||
        review.at("files").empty()||review.at("files").size()>20000)throw std::runtime_error("authority_installation_manifest_invalid");
    std::set<std::filesystem::path> paths;
    for(auto entry=review.at("files").begin();entry!=review.at("files").end();++entry){
        auto name=entry.key();auto relative=Utf8Path(name);
        if(relative.is_absolute()||relative.has_root_name()||relative.lexically_normal()!=relative||name.find_first_of("\\:\r\n")!=std::string::npos||
            name.empty()||name.back()=='/'||name=="installation-review.json"||!entry.value().is_string()||entry.value().get_ref<const std::string&>().size()!=64||
            entry.value().get_ref<const std::string&>().find_first_not_of("0123456789abcdef")!=std::string::npos)
            throw std::runtime_error("authority_installation_manifest_invalid");
        for(const auto& part:relative)if(part==L".."||part==L"."||part.empty()||part.wstring().back()==L'.'||part.wstring().back()==L' ')
            throw std::runtime_error("authority_installation_manifest_invalid");
        auto path=directory/relative;if(!paths.insert(path).second||FileDigest(path)!=entry.value().get_ref<const std::string&>())throw std::runtime_error("authority_installation_build_changed");
    }
    const std::set<std::filesystem::path> dynamic={L"installation-review.json",L"runtime/owner-key.json",L"runtime/owner-connection.json",L"runtime/owner-bootstrap.json",L"runtime/owner-bootstrap.lock"};
    for(const auto& entry:std::filesystem::recursive_directory_iterator(directory))if(entry.is_regular_file()&&!paths.contains(entry.path())&&!dynamic.contains(entry.path().lexically_relative(directory)))
        throw std::runtime_error("authority_installation_unreviewed_file");
#else
    (void)directory;throw std::runtime_error("windows_installation_required");
#endif
}
std::filesystem::path WindowsDataRoot(){
#if defined(_WIN32)
    PWSTR value=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData,KF_FLAG_DEFAULT,nullptr,&value)))
        throw std::runtime_error("authority_installation_unavailable");
    auto path=std::filesystem::path(value)/L"Stellaria AXR";CoTaskMemFree(value);return path;
#else
    throw std::runtime_error("windows_installation_required");
#endif
}
std::filesystem::path WindowsDeploymentConfiguration(){
#if defined(_WIN32)
    auto path=WindowsDataRoot()/L"deployment.json";
    for(auto node=path;!node.empty();node=node.parent_path()){
        Protected(node,node!=path);if(node==node.root_path())break;
    }
    if(!std::filesystem::is_regular_file(path)||std::filesystem::file_size(path)>32768)
        throw std::runtime_error("authority_deployment_configuration_invalid");
    return path;
#else
    throw std::runtime_error("windows_installation_required");
#endif
}
std::string ReadWindowsOwnerCredential(const std::string& ownerSid,const std::string& space,const std::string& name){
#if defined(_WIN32)
    auto actual=ProcessIdentity(GetCurrentProcessId());
    if(actual.at("user")!="S-1-5-18"||Utf8Path(actual.at("image").get<std::string>())!=WindowsInstallationRoot()/L"axr-authority.exe")
        throw std::runtime_error("windows_owner_credential_authority_required");
    VerifyWindowsInstallation(WindowsInstallationRoot());
    if(ownerSid.rfind("S-1-5-21-",0)!=0||ownerSid.find_first_not_of("S-0123456789")!=std::string::npos||
        space.empty()||space.size()>256||name.empty()||name.size()>1024)
        throw std::runtime_error("windows_owner_credential_request_invalid");
    using namespace WindowsInteractiveHost;
    Sid sid(ownerSid);Privilege tcb(L"SeTcbPrivilege");auto token=UserToken(sid);
    Handle existing;
    if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&existing.value)||GetLastError()!=ERROR_NO_TOKEN)
        throw std::runtime_error("windows_owner_credential_nested_impersonation_denied");
    if(!ImpersonateLoggedOnUser(token.value))throw std::runtime_error("windows_owner_credential_impersonation_failed");
    // No Python callback or application code executes under this thread token.
    // Scope reverts before the raw credential is validated or stored as System.
    struct Revert {~Revert(){if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),ERROR_ACCESS_DENIED);}} revert;
    auto read=[&](const std::string& target)->PCREDENTIALW{
        PCREDENTIALW value=nullptr;
        if(!CredReadW(Utf8Path(target).c_str(),CRED_TYPE_GENERIC,0,&value)){
            if(GetLastError()==ERROR_NOT_FOUND)return nullptr;
            throw std::runtime_error("wcdb_native_legacy_access_denied");}
        return value;
    };
    struct Credential {PCREDENTIALW value=nullptr;~Credential(){if(value){SecureZeroMemory(value->CredentialBlob,value->CredentialBlobSize);CredFree(value);}}} credential;
    credential.value=read(space);
    if(credential.value&&(!credential.value->UserName||Utf8Path(name).wstring()!=credential.value->UserName)){
        SecureZeroMemory(credential.value->CredentialBlob,credential.value->CredentialBlobSize);CredFree(credential.value);credential.value=nullptr;}
    if(!credential.value)credential.value=read(name+"@"+space);
    if(!credential.value||!credential.value->UserName||Utf8Path(name).wstring()!=credential.value->UserName)
        throw std::runtime_error("wcdb_native_legacy_access_denied");
    // python-keyring stores base64 as UTF-16; support its documented legacy
    // UTF-8 representation, but no arbitrary encoding or other user's vault.
    std::string encoded;
    if(credential.value->CredentialBlobSize==88){
        auto bytes=credential.value->CredentialBlob;
        for(size_t i=0;i<44;++i){if(bytes[i*2+1])throw std::runtime_error("wcdb_native_legacy_record_invalid");encoded.push_back(char(bytes[i*2]));}
    }else if(credential.value->CredentialBlobSize==44)encoded.assign(reinterpret_cast<char*>(credential.value->CredentialBlob),44);
    else throw std::runtime_error("wcdb_native_legacy_record_invalid");
    return encoded; // Native caller immediately decodes/cleanses; no Python API.
#else
    (void)ownerSid;(void)space;(void)name;throw std::runtime_error("windows_installation_required");
#endif
}
}
