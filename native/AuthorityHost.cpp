// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Fixed embedded-runtime host. No user site, PYTHONPATH, caller-selected module,
// script, executable or startup arguments enter the authority interpreter.
#include "axr/ProtectedStore.hpp"
#include "axr/Security.hpp"
#include "axr/WindowsInstallation.hpp"
#include "axr/WindowsFrontend.hpp"
#include <Python.h>
#include <iostream>
#include <atomic>
#include <fstream>
#if defined(__APPLE__)
#include <Security/Security.h>
#include <sandbox.h>
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#endif
using namespace Stellaria::AXR;
namespace {
std::atomic<bool> stopRequested=false;
std::string lastErrorCode;
void Installed(const std::filesystem::path& root,bool requireOwnership=true){
#if defined(__APPLE__)
    SecCodeRef dynamic=nullptr;SecStaticCodeRef code=nullptr;
    if(SecCodeCopySelf(kSecCSDefaultFlags,&dynamic)!=errSecSuccess)throw std::runtime_error("authority_installed_identity_required");
    auto status=SecCodeCopyStaticCode(dynamic,kSecCSDefaultFlags,&code);CFRelease(dynamic);
    if(status!=errSecSuccess||!code)throw std::runtime_error("authority_installed_identity_required");
    status=SecStaticCodeCheckValidity(code,SecCSFlags(kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode),nullptr);CFRelease(code);
    if(status!=errSecSuccess)throw std::runtime_error("authority_bundle_integrity_failed");
    if(!requireOwnership)return; // Separate validation identity has no authority keys.
    // Installation is root-owned and immutable to the owner user's business
    // process. A writable, even correctly signed development bundle is refused.
    for(const auto& entry:std::filesystem::recursive_directory_iterator(root)){
        struct stat info{};if(lstat(entry.path().c_str(),&info)||S_ISLNK(info.st_mode)||info.st_uid!=0||(info.st_mode&0022))throw std::runtime_error("authority_installation_not_protected");
    }
    struct stat info{};if(lstat(root.c_str(),&info)||info.st_uid!=0||(info.st_mode&0022))throw std::runtime_error("authority_installation_not_protected");
    // A writable ancestor could rename/replace an otherwise protected bundle.
    for(auto parent=root.parent_path();!parent.empty();parent=parent.parent_path()){
        struct stat ancestor{};
        if(lstat(parent.c_str(),&ancestor)||S_ISLNK(ancestor.st_mode)||ancestor.st_uid!=0||(ancestor.st_mode&0022))throw std::runtime_error("authority_installation_ancestor_not_protected");
        if(parent==parent.root_path())break;
    }
#elif defined(_WIN32)
    if(!requireOwnership)return; // Separate validator cannot open formal keys/stores.
    VerifyWindowsInstallation(root.parent_path());
#else
    (void)root;throw std::runtime_error("authority_platform_unavailable");
#endif
}
void Configure(PyConfig& config,const std::filesystem::path& root){
    PyPreConfig pre;PyPreConfig_InitIsolatedConfig(&pre);pre.utf8_mode=1;
    if(PyStatus_Exception(Py_PreInitialize(&pre)))throw std::runtime_error("authority_runtime_preinitialization_failed");
    PyConfig_InitIsolatedConfig(&config);config.parse_argv=0;config.use_environment=0;config.user_site_directory=0;config.site_import=0;
    if(PyStatus_Exception(PyConfig_SetString(&config,&config.stdio_encoding,L"utf-8"))||
       PyStatus_Exception(PyConfig_SetString(&config,&config.stdio_errors,L"strict")))throw std::runtime_error("authority_runtime_encoding_failed");
    config.write_bytecode=0;config.install_signal_handlers=1;config.module_search_paths_set=1;
    auto standard=root/"python-runtime.zip";
    if(!std::filesystem::exists(standard))standard=root/"python312.zip";
    for(const auto& path:{standard,root/"lib-dynload",root/"packages"}){
        if(!std::filesystem::exists(path))throw std::runtime_error("authority_bundled_runtime_missing");
        auto value=path.wstring();if(PyStatus_Exception(PyWideStringList_Append(&config.module_search_paths,value.c_str())))throw std::runtime_error("authority_runtime_configuration_failed");
    }
}
int Serve(bool initialize=false,bool ownerControl=false,bool refresh=false,bool recover=false,bool reconfigure=false){
#ifdef AXR_SECURITY_RELEASE
#if !defined(AXR_OWNER_HOST) && !defined(AXR_VALIDATION_HOST) && !defined(AXR_FRONTEND_HOST)
    ProtectedStore bootstrap("Stellaria.AXR.Bootstrap");
#endif
#if defined(_WIN32)
    auto identity=ProcessIdentity(GetCurrentProcessId());
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
#else
    auto identity=ProcessIdentity(unsigned(getpid()));
#endif
#if !defined(_WIN32) || !defined(AXR_OWNER_DEPLOYMENT)
    if(identity.at("signature_valid")!=true)throw std::runtime_error("authority_installed_identity_required");
#endif
    if(stopRequested)return 0;
    auto exe=Utf8Path(identity.at("image").get<std::string>());
#if defined(__APPLE__)
    auto root=exe.parent_path().parent_path()/"Resources";
#else
    auto root=exe.parent_path()/"runtime";
#endif
    // Protect the dependency closure as well as Python resources. A writable
    // Frameworks sibling must never be accepted as an installed authority.
#if defined(__APPLE__)
    Installed(exe.parent_path().parent_path().parent_path(),
#ifdef AXR_VALIDATION_HOST
        false
#else
        true
#endif
    );
#else
#ifdef AXR_VALIDATION_HOST
    Installed(root,false);
#else
    Installed(root);
#endif
#endif
#ifdef AXR_FRONTEND_HOST
#if defined(__APPLE__)
    // Applied before importing any Python or reading any MCP request. The
    // fixed installed executable has no alternative unsandboxed entry point.
    auto frontendConfig=Json::parse(std::ifstream(root/"deployment.json"));
    if(frontendConfig.contains("deployment_source")){
        if(frontendConfig!=Json{{"version",2},{"application_module","axr_applications.wechat"},{"deployment_source","installation"}})
            throw std::runtime_error("authority_deployment_configuration_invalid");
        auto file=root.parent_path().parent_path().parent_path()/"deployment.json";
        for(auto node=file;!node.empty();node=node.parent_path()){
            struct stat info{};
            if(lstat(node.c_str(),&info)||S_ISLNK(info.st_mode)||info.st_uid!=0||(info.st_mode&0022))
                throw std::runtime_error("authority_installation_not_protected");
            if(node==node.root_path())break;
        }
        if(std::filesystem::file_size(file)>32768)throw std::runtime_error("authority_deployment_configuration_invalid");
        frontendConfig=Json::parse(std::ifstream(file));
    }
    auto endpoint=frontendConfig.at("deployment").at("endpoint").get<std::string>();
    if(endpoint.empty()||endpoint[0]!='/'||endpoint.size()>100)throw std::runtime_error("frontend_endpoint_invalid");
    auto quote=[](const std::string& s){return Json(s).dump();};
    std::string profile="(version 1)(deny default)(import \"system.sb\")(allow sysctl-read)"
      "(allow file-read* (subpath \"/System/Library\") (subpath \"/usr/lib\") (literal \"/dev/urandom\") (literal \"/dev/null\"))"
      "(allow file-read* (subpath "+quote(exe.parent_path().parent_path().string())+"))"
      "(allow file-read* (subpath \"/Library/Application Support/Stellaria AXR/AXR Authority.app\"))"
      "(allow file-read* (literal \"/Library/Application Support/Stellaria AXR/deployment.json\"))"
      "(allow file-read-metadata (literal \"/\") (subpath \"/Library\") (subpath \"/Users\") (subpath \"/private/var\"))"
      "(allow file-read* file-write* (literal "+quote(endpoint)+"))"
      "(allow network-outbound (remote unix-socket (literal "+quote(endpoint)+")))";
    char* error=nullptr;
    if(sandbox_init(profile.c_str(),0,&error)){if(error)sandbox_free_error(error);throw std::runtime_error("frontend_os_sandbox_required");}
#elif defined(_WIN32)
    // The unsandboxed entry only starts the fixed sandboxed self. Verify the
    // real token before importing Python or reading the first MCP request.
    WindowsFrontendIdentity(GetCurrentProcessId());
#else
    throw std::runtime_error("frontend_os_sandbox_unavailable");
#endif
#endif
    PyConfig config;Configure(config,root);
    auto status=Py_InitializeFromConfig(&config);PyConfig_Clear(&config);
    if(PyStatus_Exception(status))throw std::runtime_error("authority_runtime_initialization_failed");
    auto module=PyImport_ImportModule(
#ifdef AXR_OWNER_HOST
        "axr.authority_owner"
#elif defined(AXR_VALIDATION_HOST)
        "axr.authority_validate"
#elif defined(AXR_FRONTEND_HOST)
        "axr.authority_frontend"
#else
        reconfigure?"axr.authority_reconfigure":recover?"axr.authority_recover":refresh?"axr.authority_update":initialize?"axr.authority_setup":"axr.authority_main"
#endif
    );
    if(!module){
#ifdef AXR_VALIDATION_HOST
        PyErr_PrintEx(0); // Fixed synthetic import check; no authority or live data.
#endif
        PyErr_Clear();Py_FinalizeEx();throw std::runtime_error("authority_bootstrap_import_failed");}
    PyObject* result=nullptr;
    if(initialize){auto path=root.u8string();
        if(ownerControl)result=PyObject_CallMethod(module,"main","ss",reinterpret_cast<const char*>(path.c_str()),"control");
        else result=PyObject_CallMethod(module,"main","s",reinterpret_cast<const char*>(path.c_str()));}
    else result=PyObject_CallMethod(module,"main",nullptr);
    Py_DECREF(module);
    bool ok=result!=nullptr;if(result)Py_DECREF(result);else {
        // Only bounded machine error codes cross diagnostics. No traceback,
        // file path, chat text, native credential or arbitrary exception text.
        PyObject *type=nullptr,*value=nullptr,*trace=nullptr;
        PyErr_Fetch(&type,&value,&trace);PyErr_NormalizeException(&type,&value,&trace);
        auto text=value?PyObject_Str(value):nullptr;auto raw=text?PyUnicode_AsUTF8(text):nullptr;
        std::string code=raw?raw:"authority_operation_failed";
        if(code.empty()||code.size()>100||code.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")!=std::string::npos)code="authority_operation_failed";
        lastErrorCode=code;
        std::string kind=type&&PyType_Check(type)?reinterpret_cast<PyTypeObject*>(type)->tp_name:"RuntimeError";
        if(kind.size()>80||kind.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")!=std::string::npos)kind="RuntimeError";
        std::cerr<<Json{{"error_code",code},{"exception_type",kind}}.dump()<<'\n';
        Py_XDECREF(text);Py_XDECREF(type);Py_XDECREF(value);Py_XDECREF(trace);
#ifdef AXR_VALIDATION_HOST
        PyErr_PrintEx(0);
#endif
        PyErr_Clear();}Py_FinalizeEx();
    if(!ok)throw std::runtime_error("authority_service_stopped_or_unqualified");return 0;
#else
    throw std::runtime_error("authority_formal_build_required");
#endif
}
#if defined(_WIN32)
SERVICE_STATUS_HANDLE serviceHandle=nullptr;SERVICE_STATUS serviceStatus{};int serviceAction=0;
void WINAPI Control(DWORD code){if(code==SERVICE_CONTROL_STOP){serviceStatus.dwCurrentState=SERVICE_STOP_PENDING;SetServiceStatus(serviceHandle,&serviceStatus);stopRequested=true;if(Py_IsInitialized())PyErr_SetInterrupt();}}
void WINAPI ServiceMain(DWORD,LPWSTR*){
    serviceHandle=RegisterServiceCtrlHandlerW(L"StellariaAXRAuthority",Control);if(!serviceHandle)return;
    serviceStatus.dwServiceType=SERVICE_WIN32_OWN_PROCESS;serviceStatus.dwControlsAccepted=SERVICE_ACCEPT_STOP;serviceStatus.dwCurrentState=SERVICE_RUNNING;SetServiceStatus(serviceHandle,&serviceStatus);
    try{Serve(serviceAction==1||serviceAction==3||serviceAction==4,false,serviceAction==2,serviceAction==3,serviceAction==4);}catch(...){
        if(!(serviceAction==1&&lastErrorCode=="authority_already_initialized")){
            serviceStatus.dwWin32ExitCode=ERROR_SERVICE_SPECIFIC_ERROR;serviceStatus.dwServiceSpecificExitCode=1;}}
    serviceStatus.dwCurrentState=SERVICE_STOPPED;SetServiceStatus(serviceHandle,&serviceStatus);
}
#endif
}
int main(int argc,char** argv){
    try{
#ifdef AXR_OWNER_HOST
#if defined(_WIN32)
        if(argc==2&&std::string_view(argv[1])=="--owner-control")return Serve(true,true);
#endif
        if(argc!=2||std::string_view(argv[1])!="--owner-enroll")throw std::runtime_error("owner_fixed_entrypoint_required");
        return Serve(true);
#elif defined(AXR_FRONTEND_HOST)
#if defined(_WIN32)
        if(argc==2&&std::string_view(argv[1])=="--mcp")return RunWindowsFrontend();
        if(argc!=2||std::string_view(argv[1])!="--sandbox-mcp")throw std::runtime_error("frontend_fixed_entrypoint_required");
#else
        if(argc!=2||std::string_view(argv[1])!="--mcp")throw std::runtime_error("frontend_fixed_entrypoint_required");
#endif
        return Serve(true);
#elif defined(AXR_VALIDATION_HOST)
        if(argc!=2||std::string_view(argv[1])!="--validate-runtime")throw std::runtime_error("validation_fixed_entrypoint_required");
        return Serve(true);
#else
#if defined(_WIN32)
        if(argc==2&&(std::string_view(argv[1])=="--service"||std::string_view(argv[1])=="--initialize-service"||std::string_view(argv[1])=="--refresh-service"||std::string_view(argv[1])=="--recover-service"||std::string_view(argv[1])=="--reconfigure-service")){
            serviceAction=std::string_view(argv[1])=="--initialize-service"?1:std::string_view(argv[1])=="--refresh-service"?2:std::string_view(argv[1])=="--recover-service"?3:std::string_view(argv[1])=="--reconfigure-service"?4:0;
            SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(L"StellariaAXRAuthority"),ServiceMain},{nullptr,nullptr}};
            if(!StartServiceCtrlDispatcherW(table))throw std::runtime_error("authority_service_dispatch_failed");return 0;
        }
#endif
        if(argc==2&&std::string_view(argv[1])=="--initialize-owner")return Serve(true);
#if defined(__APPLE__) || defined(_WIN32)
        if(argc==2&&std::string_view(argv[1])=="--refresh-owner-build")return Serve(true,false,true);
#endif
        if(argc!=2||std::string_view(argv[1])!="--serve")throw std::runtime_error("authority_fixed_entrypoint_required");
        return Serve();
#endif
    }catch(const std::exception& e){std::cerr<<Json{{"error",e.what()},{"authority_started",false}}.dump()<<'\n';return 1;}
}
