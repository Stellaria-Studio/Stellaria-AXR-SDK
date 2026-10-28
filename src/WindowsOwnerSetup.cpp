// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Fixed, one-shot LocalSystem -> interactive owner setup. The job only manages
// child lifetime; it is not an agent sandbox or authorization mechanism.
#include "axr/WindowsOwnerSetup.hpp"
#include "axr/WindowsInstallation.hpp"
#include "axr/Security.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shlobj.h>
#include "WindowsSetupTransport.hpp"
#include "WindowsInteractiveHost.hpp"
#endif
namespace Stellaria::AXR {
namespace {
bool Hex64(const Json& value){return value.is_string()&&value.get_ref<const std::string&>().size()==64&&
    value.get_ref<const std::string&>().find_first_not_of("0123456789abcdef")==std::string::npos;}
void ValidateChallenge(const Json& value){
    bool initial=value.is_object()&&value.value("kind",Json{})=="wechat-owner-enrollment";
    bool orphan=value.is_object()&&value.value("kind",Json{})=="wechat-owner-orphan-recovery";
    bool reviewed=value.is_object()&&(value.value("kind",Json{})=="wechat-owner-recovery"||value.value("kind",Json{})=="wechat-owner-build-update");
    bool build=orphan||reviewed||(initial&&value.contains("build_digest"));
    if((!initial&&!orphan&&!reviewed)||value.size()!=(reviewed?7:build?6:5)||!value.contains("version")||!value.at("version").is_number_integer()||value.at("version")!=2||
       !value.contains("nonce")||!Hex64(value.at("nonce"))||
       !value.contains("configuration_digest")||!Hex64(value.at("configuration_digest"))||!value.contains("expires")||
       !value.at("expires").is_number()||!std::isfinite(value.at("expires").get<double>())||
       value.at("expires").get<double>()<=Now()||value.at("expires").get<double>()>Now()+180)
        throw std::runtime_error("windows_owner_setup_challenge_invalid");
    if(build&&(!value.contains("build_digest")||!Hex64(value.at("build_digest"))))throw std::runtime_error("windows_owner_setup_challenge_invalid");
    if(reviewed&&(!value.contains("expected_public_key")||
        !value.at("expected_public_key").is_string()||value.at("expected_public_key").get_ref<const std::string&>().size()!=588||
        value.at("expected_public_key").get_ref<const std::string&>().find_first_not_of("0123456789abcdef")!=std::string::npos))
        throw std::runtime_error("windows_owner_setup_challenge_invalid");
}
#if defined(_WIN32)
using WindowsInteractiveHost::Handle;
using WindowsInteractiveHost::Sid;
using WindowsInteractiveHost::Child;
using WindowsInteractiveHost::Launch;
using WindowsInteractiveHost::Pipe;
[[noreturn]] void Denied(){throw std::runtime_error("windows_owner_setup_denied");}
std::filesystem::path InstalledRoot(){PWSTR path=nullptr;
    if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,KF_FLAG_DEFAULT,nullptr,&path)))Denied();
    auto root=std::filesystem::path(path)/L"Stellaria AXR";CoTaskMemFree(path);return root;
}
Json Host(bool server){
    auto actual=ProcessIdentity(GetCurrentProcessId());auto image=Utf8Path(actual.at("image").get<std::string>());
    if(image.filename()!=(server?L"axr-authority.exe":L"axr-owner.exe"))
        throw std::runtime_error(server?"windows_owner_setup_authority_host_required":"windows_owner_setup_owner_host_required");
    DWORD session=0;
    if(server){if(actual.at("user")!="S-1-5-18")throw std::runtime_error("windows_owner_setup_system_required");}
    else if(actual.at("user")=="S-1-5-18"||!ProcessIdToSessionId(GetCurrentProcessId(),&session)||!session)
        throw std::runtime_error("windows_owner_setup_interactive_owner_required");
    if(image.parent_path()!=InstalledRoot())Denied();
    VerifyWindowsInstallation(image.parent_path());return actual;
}
using namespace WindowsSetupTransport;
std::string Read(const std::filesystem::path& path,size_t maximum){
    std::ifstream stream(path,std::ios::binary);if(!stream)Denied();std::string raw(maximum+1,'\0');
    stream.read(raw.data(),std::streamsize(raw.size()));auto count=stream.gcount();
    if(count>std::streamsize(maximum)||stream.bad())Denied();raw.resize(size_t(count));return raw;
}
struct Descriptor {
    Handle lock;std::filesystem::path path;std::string raw;
    explicit Descriptor(const std::filesystem::path& root):path(root/L"runtime"/L"owner-bootstrap.json"){
        lock=Handle(CreateFileW((root/L"runtime"/L"owner-bootstrap.lock").c_str(),GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(lock.value==INVALID_HANDLE_VALUE)throw std::runtime_error("windows_owner_setup_already_running");}
    ~Descriptor(){if(!raw.empty())try{if(Read(path,8192)==raw){std::error_code error;std::filesystem::remove(path,error);}}catch(...){} }
    void Write(const Json& value){raw=value.dump();if(!DurableWrite(path,raw))throw std::runtime_error("windows_owner_setup_descriptor_write_failed");}
};
#endif
}
Json ExchangeWindowsOwnerSetup(std::string ownerSid,const Json& challenge){
    ValidateChallenge(challenge);
    if(ownerSid.empty()||ownerSid.size()>184||ownerSid.find_first_not_of("S-0123456789")!=std::string::npos||ownerSid.rfind("S-1-5-21-",0)!=0)
        throw std::runtime_error("windows_owner_setup_owner_sid_invalid");
#if defined(_WIN32)
    auto server=Host(true);auto root=InstalledRoot();Sid sid(ownerSid);Deadline deadline(challenge.at("expires"));Descriptor descriptor(root);
    auto nonce=Digest(RandomId()+RandomId()),endpoint=std::string("\\\\.\\pipe\\Stellaria.AXR.Setup.")+RandomId();
    auto pipe=Pipe(Utf8Path(endpoint).wstring(),ownerSid);
    descriptor.Write({{"version",2},{"kind","windows-owner-setup"},{"endpoint",endpoint},{"nonce",nonce},
        {"expires",challenge.at("expires")},{"server",server},{"owner_user",ownerSid},{"configuration_digest",challenge.at("configuration_digest")}});
    Child child;Launch(child,sid,root,root/L"axr-owner.exe",L"--owner-enroll",deadline);if(child.identity.at("user")!=ownerSid)Denied();
    Connect(pipe.value,deadline);Stable(pipe.value,false,child.identity);
    if(Receive(pipe.value,32768,deadline,false,child.identity)!=Json{{"version",2},{"kind","owner-setup.open"},{"nonce",nonce}})Denied();
    Send(pipe.value,{{"version",2},{"kind","owner-setup.challenge"},{"nonce",nonce},{"challenge",challenge}},deadline,false,child.identity);
    auto packet=Receive(pipe.value,300000,deadline,false,child.identity);
    if(!packet.is_object()||packet.size()!=4||packet.at("version")!=2||packet.at("kind")!="owner-setup.response"||packet.at("nonce")!=nonce)Denied();
    Send(pipe.value,{{"version",2},{"kind","owner-setup.received"},{"nonce",nonce},{"authority_restored",false}},deadline,false,child.identity);
    return {{"response",packet.at("response")},{"identity",child.identity}};
#else
    throw std::runtime_error("windows_owner_setup_required");
#endif
}
struct WindowsOwnerSetupClient::Impl {
    Json challenge;
#if defined(_WIN32)
    Handle pipe;Json server;std::string nonce;std::unique_ptr<Deadline> deadline;bool responded=false;
#endif
};
WindowsOwnerSetupClient::WindowsOwnerSetupClient():impl_(std::make_unique<Impl>()){
#if defined(_WIN32)
    auto owner=Host(false);auto value=ParseBounded(Read(InstalledRoot()/L"runtime"/L"owner-bootstrap.json",8192));
    if(!value.is_object()||value.size()!=8||value.at("version")!=2||value.at("kind")!="windows-owner-setup"||
       value.at("owner_user")!=owner.at("user")||!Hex64(value.at("nonce"))||!Hex64(value.at("configuration_digest")))Denied();
    auto endpoint=value.at("endpoint").get<std::string>();constexpr std::string_view prefix="\\\\.\\pipe\\Stellaria.AXR.Setup.";
    if(endpoint.rfind(prefix,0)!=0||endpoint.size()!=prefix.size()+32||endpoint.substr(prefix.size()).find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
    auto expires=value.at("expires").get<double>();if(!std::isfinite(expires)||expires<=Now()||expires>Now()+180)Denied();
    impl_->deadline=std::make_unique<Deadline>(expires);impl_->server=value.at("server");impl_->nonce=value.at("nonce");
    if(impl_->server.at("user")!="S-1-5-18"||Utf8Path(impl_->server.at("image").get<std::string>())!=InstalledRoot()/L"axr-authority.exe")Denied();
    impl_->pipe=Handle(CreateFileW(Utf8Path(endpoint).c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,nullptr));
    if(impl_->pipe.value==INVALID_HANDLE_VALUE)Denied();DWORD mode=PIPE_READMODE_MESSAGE;
    if(!SetNamedPipeHandleState(impl_->pipe.value,&mode,nullptr,nullptr))Denied();Stable(impl_->pipe.value,true,impl_->server);
    Send(impl_->pipe.value,{{"version",2},{"kind","owner-setup.open"},{"nonce",impl_->nonce}},*impl_->deadline,true,impl_->server);
    auto packet=Receive(impl_->pipe.value,32768,*impl_->deadline,true,impl_->server);
    if(packet.size()!=4||packet.at("version")!=2||packet.at("kind")!="owner-setup.challenge"||packet.at("nonce")!=impl_->nonce)Denied();
    impl_->challenge=packet.at("challenge");ValidateChallenge(impl_->challenge);
    if(impl_->challenge.at("expires")!=value.at("expires")||impl_->challenge.at("configuration_digest")!=value.at("configuration_digest"))Denied();
#else
    throw std::runtime_error("windows_owner_setup_required");
#endif
}
WindowsOwnerSetupClient::~WindowsOwnerSetupClient()=default;
void WindowsOwnerSetupClient::Close(){
#if defined(_WIN32)
    impl_->responded=true;impl_->pipe.Reset();
#endif
}
Json WindowsOwnerSetupClient::Challenge()const{return impl_->challenge;}
void WindowsOwnerSetupClient::Respond(const Json& response){
#if defined(_WIN32)
    if(impl_->responded)Denied();impl_->responded=true;
    Send(impl_->pipe.value,{{"version",2},{"kind","owner-setup.response"},{"nonce",impl_->nonce},{"response",response}},*impl_->deadline,true,impl_->server);
    if(Receive(impl_->pipe.value,32768,*impl_->deadline,true,impl_->server)!=Json{{"version",2},{"kind","owner-setup.received"},{"nonce",impl_->nonce},{"authority_restored",false}})Denied();
#else
    (void)response;throw std::runtime_error("windows_owner_setup_required");
#endif
}
}
