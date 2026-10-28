// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/WindowsNavigation.hpp"
#include "axr/WindowsInstallation.hpp"
#include "axr/Security.hpp"
#if defined(_WIN32)
#include "WindowsInteractiveHost.hpp"
#endif
namespace Stellaria::AXR {
namespace {
[[noreturn]] void Denied(){throw std::runtime_error("windows_navigation_denied");}
#if defined(_WIN32)
using WindowsInteractiveHost::Handle;
using WindowsInteractiveHost::Child;
using WindowsSetupTransport::Deadline;
using WindowsSetupTransport::Stable;
using WindowsSetupTransport::Send;
using WindowsSetupTransport::Receive;
constexpr std::string_view Prefix="\\\\.\\pipe\\Stellaria.AXR.Navigation.";
void Endpoint(const std::string& endpoint){
    if(endpoint.size()!=Prefix.size()+32||endpoint.rfind(Prefix,0)!=0||
       endpoint.substr(Prefix.size()).find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
}
void Helper(const std::filesystem::path& image){
    auto root=WindowsInstallationRoot();auto relative=image.lexically_relative(root);
    if(!image.is_absolute()||relative.empty()||image.filename()!=L"wechat-uia.exe")Denied();
    for(const auto& part:relative)if(part==L".."||part==L".")Denied();
}
Json Host(bool server){
    auto actual=ProcessIdentity(GetCurrentProcessId());auto image=Utf8Path(actual.at("image").get<std::string>());
    if(server){
        if(image!=WindowsInstallationRoot()/L"axr-authority.exe")throw std::runtime_error("windows_navigation_authority_host_required");
        if(actual.at("user")!="S-1-5-18")throw std::runtime_error("windows_navigation_system_required");
    }else{
        Helper(image);DWORD session=0;
        if(actual.at("user")=="S-1-5-18"||!ProcessIdToSessionId(GetCurrentProcessId(),&session)||!session)Denied();
    }
    VerifyWindowsInstallation(WindowsInstallationRoot());return actual;
}
Json ReadyFrame(){return {{"version",2},{"ready",true},{"input_received",false}};}
Json ReceivedFrame(){return {{"version",2},{"received",true},{"retry",false}};}
#endif
}
struct WindowsNavigation::Impl {
    Json identity;bool ready=false,submitted=false,finished=false;
#if defined(_WIN32)
    Handle pipe;Child child;
#endif
};
WindowsNavigation::WindowsNavigation(std::string ownerSid,std::string helper,std::string sha,const std::function<void()>& check):impl_(std::make_unique<Impl>()){
#if defined(_WIN32)
    Host(true); // Before selecting a token, creating a pipe or launching anything.
    if(ownerSid.rfind("S-1-5-21-",0)!=0||ownerSid.size()>184||ownerSid.find_first_not_of("S-0123456789")!=std::string::npos||
       sha.size()!=64||sha.find_first_not_of("0123456789abcdef")!=std::string::npos)Denied();
    auto image=Utf8Path(helper);Helper(image);Deadline deadline(Now()+5,check);
    auto endpoint=std::string(Prefix)+RandomId();Endpoint(endpoint);
    impl_->pipe=WindowsInteractiveHost::Pipe(Utf8Path(endpoint).wstring(),ownerSid);
    WindowsInteractiveHost::Sid sid(ownerSid);
    WindowsInteractiveHost::Launch(impl_->child,sid,WindowsInstallationRoot(),image,L"--authority-pipe "+Utf8Path(endpoint).wstring(),deadline,sha);
    impl_->identity=impl_->child.identity;
    if(impl_->identity.at("image_sha256")!=sha)Denied();
    WindowsSetupTransport::Connect(impl_->pipe.value,deadline);Stable(impl_->pipe.value,false,impl_->identity);
#else
    (void)ownerSid;(void)helper;(void)sha;(void)check;throw std::runtime_error("windows_navigation_required");
#endif
}
WindowsNavigation::~WindowsNavigation()=default;
Json WindowsNavigation::Identity()const{if(!impl_)Denied();return impl_->identity;}
Json WindowsNavigation::Ready(const std::function<void()>& check){
#if defined(_WIN32)
    if(!impl_||impl_->ready)Denied();impl_->ready=true;
    auto result=Receive(impl_->pipe.value,1024,Deadline(Now()+5,check),false,impl_->identity);
    if(result!=ReadyFrame())Denied();return result;
#else
    (void)check;Denied();
#endif
}
void WindowsNavigation::Submit(const Json& request,const std::function<void()>& check){
#if defined(_WIN32)
    if(!impl_||!impl_->ready||impl_->submitted)Denied();impl_->submitted=true;
    Send(impl_->pipe.value,request,Deadline(Now()+5,check),false,impl_->identity,MaximumFrameBytes);
#else
    (void)request;(void)check;Denied();
#endif
}
Json WindowsNavigation::Result(const std::function<void()>& check){
#if defined(_WIN32)
    if(!impl_||!impl_->submitted||impl_->finished)Denied();impl_->finished=true;
    auto result=Receive(impl_->pipe.value,MaximumFrameBytes,Deadline(Now()+20,check),false,impl_->identity);
    // Keep the peer alive through the final OS identity check. This only
    // acknowledges transport receipt; it grants no permission or retry.
    Send(impl_->pipe.value,ReceivedFrame(),Deadline(Now()+2,check),false,impl_->identity);
    Deadline deadline(Now()+2,check);
    while(WaitForSingleObject(impl_->child.process.value,std::min<DWORD>(50,deadline.Remaining()))==WAIT_TIMEOUT){}
    DWORD code=1;if(!GetExitCodeProcess(impl_->child.process.value,&code)||code!=0)Denied();
    return result;
#else
    (void)check;Denied();
#endif
}
void WindowsNavigation::Close(){impl_.reset();}
struct WindowsNavigationPeer::Impl {
    bool requested=false,responded=false;
#if defined(_WIN32)
    Handle pipe;Json server;
#endif
};
WindowsNavigationPeer::WindowsNavigationPeer(std::string endpoint):impl_(std::make_unique<Impl>()){
#if defined(_WIN32)
    Host(false);Endpoint(endpoint);
    impl_->pipe=Handle(CreateFileW(Utf8Path(endpoint).c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,nullptr));
    if(impl_->pipe.value==INVALID_HANDLE_VALUE)Denied();DWORD mode=PIPE_READMODE_MESSAGE;
    if(!SetNamedPipeHandleState(impl_->pipe.value,&mode,nullptr,nullptr))Denied();
    impl_->server=PeerIdentity(reinterpret_cast<uintptr_t>(impl_->pipe.value),true);
    if(impl_->server.at("user")!="S-1-5-18"||Utf8Path(impl_->server.at("image").get<std::string>())!=WindowsInstallationRoot()/L"axr-authority.exe")Denied();
    Send(impl_->pipe.value,ReadyFrame(),Deadline(Now()+5),true,impl_->server);
#else
    (void)endpoint;throw std::runtime_error("windows_navigation_required");
#endif
}
WindowsNavigationPeer::~WindowsNavigationPeer()=default;
Json WindowsNavigationPeer::Request(){
#if defined(_WIN32)
    if(impl_->requested)Denied();impl_->requested=true;
    return Receive(impl_->pipe.value,MaximumFrameBytes,Deadline(Now()+10),true,impl_->server);
#else
    Denied();
#endif
}
void WindowsNavigationPeer::Respond(const Json& response){
#if defined(_WIN32)
    if(!impl_->requested||impl_->responded)Denied();impl_->responded=true;
    Send(impl_->pipe.value,response,Deadline(Now()+5),true,impl_->server,MaximumFrameBytes);
    if(Receive(impl_->pipe.value,1024,Deadline(Now()+5),true,impl_->server)!=ReceivedFrame())Denied();
#else
    (void)response;Denied();
#endif
}
}
