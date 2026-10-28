// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#if defined(_WIN32)
// Internal trusted-host launch primitives shared by setup and UI navigation.
// Callers must first verify their protected host and installed fixed executable.
// A lifetime JobObject provides cleanup, not agent isolation or authority.
#include "WindowsSetupTransport.hpp"
#include "axr/Security.hpp"
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <algorithm>
namespace Stellaria::AXR::WindowsInteractiveHost {
using WindowsSetupTransport::Deadline;
[[noreturn]] inline void HostDenied(){throw std::runtime_error("windows_interactive_host_denied");}
struct Handle {
    HANDLE value=nullptr;
    Handle()=default;explicit Handle(HANDLE handle):value(handle){}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    Handle(Handle&& other)noexcept:value(other.value){other.value=nullptr;}
    Handle& operator=(Handle&& other)noexcept{if(this!=&other){Reset();value=other.value;other.value=nullptr;}return *this;}
    ~Handle(){Reset();}
    void Reset(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=nullptr;}
};
struct Sid {
    PSID value=nullptr;
    explicit Sid(const std::string& text){auto wide=Utf8Path(text).wstring();
        if(!ConvertStringSidToSidW(wide.c_str(),&value)||!IsValidSid(value))HostDenied();}
    ~Sid(){if(value)LocalFree(value);}
};
struct Privilege {
    Handle token;TOKEN_PRIVILEGES previous{};bool changed=false;
    explicit Privilege(const wchar_t* name){
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token.value))HostDenied();
        TOKEN_PRIVILEGES next{};next.PrivilegeCount=1;next.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        if(!LookupPrivilegeValueW(nullptr,name,&next.Privileges[0].Luid))HostDenied();DWORD size=sizeof(previous);SetLastError(ERROR_SUCCESS);
        if(!AdjustTokenPrivileges(token.value,FALSE,&next,sizeof(previous),&previous,&size)||GetLastError()!=ERROR_SUCCESS)HostDenied();changed=true;
    }
    ~Privilege(){if(changed)AdjustTokenPrivileges(token.value,FALSE,&previous,0,nullptr,nullptr);}
};
inline Handle UserToken(const Sid& expected){
    PWTS_SESSION_INFOW sessions=nullptr;DWORD count=0;
    if(!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count))HostDenied();
    struct Free {PWTS_SESSION_INFOW value;~Free(){WTSFreeMemory(value);}} free{sessions};Handle selected;
    for(DWORD i=0;i<count;++i){if(sessions[i].State!=WTSActive||!sessions[i].SessionId)continue;
        Handle token;if(!WTSQueryUserToken(sessions[i].SessionId,&token.value))continue;
        DWORD size=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&size);if(!size||size>4096)HostDenied();
        std::vector<unsigned char> data(size);if(!GetTokenInformation(token.value,TokenUser,data.data(),size,&size))HostDenied();
        if(EqualSid(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,expected.value)){
            if(selected.value)throw std::runtime_error("windows_owner_setup_multiple_active_sessions");selected=std::move(token);}
    }
    if(!selected.value)throw std::runtime_error("windows_owner_setup_owner_not_active");return selected;
}
inline std::vector<wchar_t> Environment(HANDLE token,const std::filesystem::path& root){
    std::wstring windows(32768,L'\0'),system(32768,L'\0'),profile(32768,L'\0');DWORD size=DWORD(profile.size());
    auto wn=GetWindowsDirectoryW(windows.data(),DWORD(windows.size())),sn=GetSystemDirectoryW(system.data(),DWORD(system.size()));
    if(!wn||wn>=windows.size()||!sn||sn>=system.size()||!GetUserProfileDirectoryW(token,profile.data(),&size)||!size||size>profile.size())HostDenied();
    windows.resize(wn);system.resize(sn);profile.resize(size-1);
    std::vector<std::wstring> entries={L"APPDATA="+profile+L"\\AppData\\Roaming",L"LOCALAPPDATA="+profile+L"\\AppData\\Local",
        L"PATH="+system+L";"+root.wstring(),L"SystemRoot="+windows,L"TEMP="+profile+L"\\AppData\\Local\\Temp",
        L"TMP="+profile+L"\\AppData\\Local\\Temp",L"USERPROFILE="+profile,L"WINDIR="+windows};
    std::sort(entries.begin(),entries.end());std::vector<wchar_t> block;
    for(const auto& entry:entries){block.insert(block.end(),entry.begin(),entry.end());block.push_back(0);}block.push_back(0);return block;
}
struct Child {
    Handle process,thread,job;DWORD pid=0;Json identity;
    ~Child(){if(process.value){if(WaitForSingleObject(process.value,0)!=WAIT_OBJECT_0)TerminateProcess(process.value,1);
        job.Reset();WaitForSingleObject(process.value,5000);}}
};
inline void Launch(Child& child,const Sid& owner,const std::filesystem::path& root,const std::filesystem::path& executable,std::wstring arguments,const Deadline& deadline,std::string_view expectedSha={}){
    deadline.Remaining();
    Privilege tcb(L"SeTcbPrivilege"),assign(L"SeAssignPrimaryTokenPrivilege"),quota(L"SeIncreaseQuotaPrivilege");
    auto token=UserToken(owner);auto environment=Environment(token.value,root);
    child.job=Handle(CreateJobObjectW(nullptr,nullptr));if(!child.job.value)HostDenied();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(child.job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))HostDenied();
    auto command=L"\""+executable.wstring()+L"\" "+arguments;
    std::wstring desktop=L"winsta0\\default";STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.lpDesktop=desktop.data();PROCESS_INFORMATION info{};
    deadline.Remaining();
    if(!CreateProcessAsUserW(token.value,executable.c_str(),command.data(),nullptr,nullptr,FALSE,
            CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,environment.data(),root.c_str(),&startup,&info))HostDenied();
    child.process=Handle(info.hProcess);child.thread=Handle(info.hThread);child.pid=info.dwProcessId;
    if(!AssignProcessToJobObject(child.job.value,child.process.value))HostDenied();
    child.identity=ProcessIdentity(child.pid);if(Utf8Path(child.identity.at("image").get<std::string>())!=executable)HostDenied();
    if(!expectedSha.empty()&&child.identity.at("image_sha256").get_ref<const std::string&>()!=expectedSha)HostDenied();
    LPWSTR expectedSid=nullptr;if(!ConvertSidToStringSidW(owner.value,&expectedSid))HostDenied();
    auto expectedText=std::filesystem::path(expectedSid).u8string();bool sameUser=child.identity.at("user")==std::string(expectedText.begin(),expectedText.end());LocalFree(expectedSid);if(!sameUser)HostDenied();
    DWORD size=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&size);std::vector<unsigned char> user(size);
    if(!GetTokenInformation(token.value,TokenUser,user.data(),size,&size)||!EqualSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,owner.value))HostDenied();
    if(ResumeThread(child.thread.value)==DWORD(-1))HostDenied();child.thread.Reset();
}
inline Handle Pipe(const std::wstring& endpoint,const std::string& ownerSid){
    auto text=L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;"+Utf8Path(ownerSid).wstring()+L")";PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(),SDDL_REVISION_1,&descriptor,nullptr))HostDenied();
    struct Free {PSECURITY_DESCRIPTOR value;~Free(){LocalFree(value);}} free{descriptor};
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    Handle pipe(CreateNamedPipeW(endpoint.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,300001,300001,5000,&attributes));
    if(pipe.value==INVALID_HANDLE_VALUE)HostDenied();return pipe;
}
}
#endif
