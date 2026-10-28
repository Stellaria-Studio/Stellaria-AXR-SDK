// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/WindowsFrontend.hpp"
#include "axr/WindowsInstallation.hpp"
#include "axr/Security.hpp"
#if defined(_WIN32)
#include "WindowsInteractiveHost.hpp"
#include <array>
#include <sddl.h>
#include <aclapi.h>
#endif
namespace Stellaria::AXR {
namespace {
[[noreturn]] void Denied(const char* code="windows_frontend_sandbox_required"){throw std::runtime_error(code);}
#if defined(_WIN32)
using WindowsInteractiveHost::Handle;
std::string Text(PSID sid){LPWSTR value=nullptr;if(!ConvertSidToStringSidW(sid,&value))Denied();
    auto raw=std::filesystem::path(value).u8string();LocalFree(value);return std::string(raw.begin(),raw.end());}
bool Access(HANDLE token,const std::string& package){
    auto text=L"O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;"+Utf8Path(package).wstring()+L")";PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(),SDDL_REVISION_1,&descriptor,nullptr))Denied();
    Handle duplicate;if(!DuplicateToken(token,SecurityImpersonation,&duplicate.value)){LocalFree(descriptor);Denied();}
    GENERIC_MAPPING mapping{1,1,1,1};std::array<unsigned char,4096> privileges{};DWORD size=DWORD(privileges.size()),granted=0;BOOL allowed=FALSE;
    auto queried=AccessCheck(descriptor,duplicate.value,1,&mapping,reinterpret_cast<PRIVILEGE_SET*>(privileges.data()),&size,&granted,&allowed);LocalFree(descriptor);
    if(!queried)Denied();return allowed&&(granted&1);
}
struct Profile {
    std::wstring name=L"Stellaria.AXR.Frontend."+Utf8Path(RandomId()).wstring();PSID sid=nullptr;
    Profile(){if(FAILED(CreateAppContainerProfile(name.c_str(),name.c_str(),L"AXR fixed MCP transport",nullptr,0,&sid)))Denied("windows_frontend_profile_failed");}
    ~Profile(){if(sid)FreeSid(sid);DeleteAppContainerProfile(name.c_str());}
};
struct Attributes {
    std::vector<unsigned char> bytes;LPPROC_THREAD_ATTRIBUTE_LIST value=nullptr;
    Attributes(){SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,3,0,&size);bytes.resize(size);value=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());
        if(!InitializeProcThreadAttributeList(value,3,0,&size))Denied();}
    ~Attributes(){DeleteProcThreadAttributeList(value);}
    void Set(DWORD_PTR name,void* data,size_t size){if(!UpdateProcThreadAttribute(value,0,name,data,size,nullptr,nullptr))Denied();}
};
struct Child {Handle process,thread,job;~Child(){job.Reset();if(process.value&&WaitForSingleObject(process.value,0)!=WAIT_OBJECT_0){TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000);}}};
#endif
}
Json WindowsFrontendIdentity(unsigned long pid){
#if defined(_WIN32)
    auto before=ProcessIdentity(pid);Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,DWORD(pid))),token;
    if(!process.value||!OpenProcessToken(process.value,TOKEN_QUERY|TOKEN_DUPLICATE,&token.value))Denied();
    DWORD size=0,container=0;if(!GetTokenInformation(token.value,TokenIsAppContainer,&container,sizeof(container),&size)||!container||Access(token.value,"S-1-15-2-1"))Denied();
    GetTokenInformation(token.value,TokenAppContainerSid,nullptr,0,&size);std::vector<unsigned char> data(size);
    if(!size||!GetTokenInformation(token.value,TokenAppContainerSid,data.data(),size,&size))Denied();
    auto sid=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(data.data())->TokenAppContainer;if(!sid||!IsValidSid(sid)||!Access(token.value,Text(sid)))Denied();
    auto package=Text(sid);GetTokenInformation(token.value,TokenCapabilities,nullptr,0,&size);std::vector<unsigned char> capabilities(size);
    if(!size||!GetTokenInformation(token.value,TokenCapabilities,capabilities.data(),size,&size)||reinterpret_cast<TOKEN_GROUPS*>(capabilities.data())->GroupCount)Denied();
    if(ProcessIdentity(pid)!=before)Denied("windows_frontend_process_changed");
    return {{"pid",before.at("pid")},{"birth",before.at("birth")},{"image_sha256",before.at("image_sha256")},
        {"appcontainer_sid",package},{"profile","windows-appcontainer-mcp-v2"},{"network_allowed",false},{"all_application_packages_access",false}};
#else
    (void)pid;Denied("windows_frontend_platform_required");
#endif
}
int RunWindowsFrontend(){
#if defined(_WIN32)
    auto actual=ProcessIdentity(GetCurrentProcessId());auto image=Utf8Path(actual.at("image").get<std::string>());auto root=image.parent_path();
#ifdef AXR_SECURITY_RELEASE
    if(image!=WindowsInstallationRoot()/L"axr-frontend.exe")Denied("windows_frontend_fixed_image_required");VerifyWindowsInstallation(root);
#endif
    if(actual.at("app_container")==true)Denied("windows_frontend_nested_launch_denied");
    Profile profile;Attributes attributes;SECURITY_CAPABILITIES capabilities{profile.sid,nullptr,0,0};DWORD optout=PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    // Duplicate only the three externally supplied stdio handles. No authority,
    // credential, file, process or caller environment handle can be inherited.
    Handle input,output,error;HANDLE handles[3];Handle* copies[]={&input,&output,&error};DWORD identifiers[]={STD_INPUT_HANDLE,STD_OUTPUT_HANDLE,STD_ERROR_HANDLE};
    for(unsigned i=0;i<3;++i){auto original=GetStdHandle(identifiers[i]);
        if(!original||original==INVALID_HANDLE_VALUE||!DuplicateHandle(GetCurrentProcess(),original,GetCurrentProcess(),&copies[i]->value,0,TRUE,DUPLICATE_SAME_ACCESS))Denied("windows_frontend_stdio_required");handles[i]=copies[i]->value;}
    attributes.Set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,&capabilities,sizeof(capabilities));
    attributes.Set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,&optout,sizeof(optout));attributes.Set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles));
    Handle token;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))Denied();auto env=WindowsInteractiveHost::Environment(token.value,root);
    Child child;child.job=Handle(CreateJobObjectW(nullptr,nullptr));JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit=1;limits.ProcessMemoryLimit=512ull*1024*1024;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{JOB_OBJECT_UILIMIT_ALL};
    if(!child.job.value||!SetInformationJobObject(child.job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))||
       !SetInformationJobObject(child.job.value,JobObjectBasicUIRestrictions,&ui,sizeof(ui)))Denied();
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;startup.lpAttributeList=attributes.value;
    startup.StartupInfo.hStdInput=handles[0];startup.StartupInfo.hStdOutput=handles[1];startup.StartupInfo.hStdError=handles[2];
    auto command=L"\""+image.wstring()+L"\" --sandbox-mcp";PROCESS_INFORMATION info{};wchar_t system[MAX_PATH];auto size=GetSystemDirectoryW(system,MAX_PATH);if(!size||size>=MAX_PATH)Denied();
    if(!CreateProcessW(image.c_str(),command.data(),nullptr,nullptr,TRUE,EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,
        env.data(),system,&startup.StartupInfo,&info))Denied("windows_frontend_launch_failed");
    child.process=Handle(info.hProcess);child.thread=Handle(info.hThread);
    if(!AssignProcessToJobObject(child.job.value,child.process.value))Denied();auto witness=WindowsFrontendIdentity(info.dwProcessId);
    if(witness.at("appcontainer_sid")!=Text(profile.sid)||witness.at("image_sha256")!=actual.at("image_sha256"))Denied("windows_frontend_process_changed");
    if(ResumeThread(child.thread.value)==DWORD(-1))Denied();child.thread.Reset();input.Reset();output.Reset();error.Reset();
    if(WaitForSingleObject(child.process.value,INFINITE)!=WAIT_OBJECT_0)Denied();DWORD exit=1;if(!GetExitCodeProcess(child.process.value,&exit))Denied();return int(exit);
#else
    Denied("windows_frontend_platform_required");
#endif
}
void ExposeWindowsAuthorityIdentity(const std::string& ownerSid){
#if defined(_WIN32)
    auto actual=ProcessIdentity(GetCurrentProcessId());
#ifdef AXR_SECURITY_RELEASE
    if(actual.at("user")!="S-1-5-18"||Utf8Path(actual.at("image").get<std::string>())!=WindowsInstallationRoot()/L"axr-authority.exe")Denied("windows_frontend_authority_required");
    VerifyWindowsInstallation(WindowsInstallationRoot());
#endif
    if(ownerSid.rfind("S-1-5-21-",0)!=0||ownerSid.find_first_not_of("S-0123456789")!=std::string::npos)Denied();
    WindowsInteractiveHost::Sid owner(ownerSid),packages("S-1-15-2-2");
    auto grant=[&](HANDLE object,DWORD rights){
        PACL previous=nullptr,next=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
        if(GetSecurityInfo(object,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&previous,nullptr,&descriptor)!=ERROR_SUCCESS)Denied();
        EXPLICIT_ACCESSW entries[2]{};PSID sids[]={owner.value,packages.value};
        for(unsigned i=0;i<2;++i){entries[i].grfAccessPermissions=rights;entries[i].grfAccessMode=GRANT_ACCESS;entries[i].grfInheritance=NO_INHERITANCE;
            entries[i].Trustee.TrusteeForm=TRUSTEE_IS_SID;entries[i].Trustee.ptstrName=static_cast<LPWSTR>(sids[i]);}
        auto code=SetEntriesInAclW(2,entries,previous,&next);bool ok=code==ERROR_SUCCESS&&SetSecurityInfo(object,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,next,nullptr)==ERROR_SUCCESS;
        if(next)LocalFree(next);if(descriptor)LocalFree(descriptor);if(!ok)Denied("windows_frontend_identity_query_acl_failed");
    };
    grant(GetCurrentProcess(),PROCESS_QUERY_LIMITED_INFORMATION);
    Handle token;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|READ_CONTROL|WRITE_DAC,&token.value))Denied();grant(token.value,TOKEN_QUERY);
#else
    (void)ownerSid;Denied("windows_frontend_platform_required");
#endif
}
}
