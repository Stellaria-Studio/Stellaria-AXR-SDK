// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// AXR process argument encoding and bounded worker lifecycle.
#include "axr/Core.hpp"
#include <chrono>
#include <thread>
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif
namespace Stellaria::AXR {
struct WorkerSupervisor::Impl {
    WorkerProcessState state=WorkerProcessState::Stopped;
    int exitCode=0; unsigned timeoutMs=15000;
    std::chrono::steady_clock::time_point startedAt{};
#if defined(_WIN32)
    PROCESS_INFORMATION process{};HANDLE job{};
#else
    pid_t process=-1;
#endif
};
WorkerSupervisor::WorkerSupervisor():impl_(std::make_unique<Impl>()){}
WorkerSupervisor::~WorkerSupervisor(){Stop();}
#if defined(_WIN32)
static std::wstring QuoteWindowsArgument(const std::wstring& value) {
    // Preserve empty arguments and Windows command-line quoting.
    if(!value.empty() && value.find_first_of(L" \t\"")==std::wstring::npos)return value;
    std::wstring result=L"\"";size_t slashes=0;
    for(wchar_t character:value) {
        if(character==L'\\')++slashes;
        else if(character==L'\"'){result.append(slashes*2+1,L'\\');result.push_back(character);slashes=0;}
        else{result.append(slashes,L'\\');slashes=0;result.push_back(character);}
    }
    result.append(slashes*2,L'\\');result.push_back(L'\"');return result;
}
#endif
bool WorkerSupervisor::Start(const std::filesystem::path& executable,const std::vector<std::string>& arguments,unsigned timeoutMs) {
    if(impl_->state==WorkerProcessState::Running||impl_->state==WorkerProcessState::Starting||
       !std::filesystem::is_regular_file(executable)||timeoutMs==0)return false;
    Stop();impl_->state=WorkerProcessState::Starting;impl_->exitCode=0;impl_->timeoutMs=timeoutMs;
#if defined(_WIN32)
    std::wstring command=QuoteWindowsArgument(executable.wstring());
    for(const auto& argument:arguments)command+=L" "+QuoteWindowsArgument(Utf8Path(argument).wstring());
    STARTUPINFOW startup{};startup.cb=sizeof(startup);
    std::vector<wchar_t> mutableCommand(command.begin(),command.end());mutableCommand.push_back(L'\0');
    if(!CreateProcessW(executable.wstring().c_str(),mutableCommand.data(),nullptr,nullptr,FALSE,
        CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,nullptr,&startup,&impl_->process)) {
        impl_->state=WorkerProcessState::Stopped;return false;
    }
    impl_->job=CreateJobObjectW(nullptr,nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit=4;limits.ProcessMemoryLimit=512ull*1024*1024;
    if(!impl_->job||!SetInformationJobObject(impl_->job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))||
       !AssignProcessToJobObject(impl_->job,impl_->process.hProcess)){Stop();return false;}
    ResumeThread(impl_->process.hThread);
#else
    std::vector<std::string> storage{executable.string()};storage.insert(storage.end(),arguments.begin(),arguments.end());
    std::vector<char*> argv;for(auto& value:storage)argv.push_back(value.data());argv.push_back(nullptr);
    posix_spawnattr_t attrs;posix_spawnattr_init(&attrs);
    posix_spawnattr_setflags(&attrs,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attrs,0);
    const int result=posix_spawn(&impl_->process,storage.front().c_str(),nullptr,&attrs,argv.data(),environ);
    posix_spawnattr_destroy(&attrs);
    if(result!=0){impl_->process=-1;impl_->state=WorkerProcessState::Stopped;return false;}
#endif
    impl_->startedAt=std::chrono::steady_clock::now();impl_->state=WorkerProcessState::Running;return true;
}
WorkerProcessState WorkerSupervisor::Poll() {
    if(impl_->state!=WorkerProcessState::Running)return impl_->state;
#if defined(_WIN32)
    if(WaitForSingleObject(impl_->process.hProcess,0)==WAIT_OBJECT_0){DWORD code=0;GetExitCodeProcess(impl_->process.hProcess,&code);impl_->exitCode=int(code);impl_->state=code==0?WorkerProcessState::Exited:WorkerProcessState::Crashed;return impl_->state;}
#else
    int status=0;const auto result=waitpid(impl_->process,&status,WNOHANG);
    if(result==impl_->process) {
        // Reap children still in this worker's process group before losing the PID.
        kill(-impl_->process,SIGKILL);
        impl_->exitCode=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);impl_->process=-1;
        impl_->state=impl_->exitCode==0?WorkerProcessState::Exited:WorkerProcessState::Crashed;return impl_->state;
    }
#endif
    if(std::chrono::steady_clock::now()-impl_->startedAt>std::chrono::milliseconds(impl_->timeoutMs)) {
        Stop();impl_->exitCode=124;impl_->state=WorkerProcessState::TimedOut;
    }
    return impl_->state;
}
void WorkerSupervisor::Stop() {
    if(!impl_)return;
#if defined(_WIN32)
    if(impl_->process.hProcess){TerminateProcess(impl_->process.hProcess,125);WaitForSingleObject(impl_->process.hProcess,5000);CloseHandle(impl_->process.hThread);CloseHandle(impl_->process.hProcess);impl_->process={};}
    if(impl_->job){CloseHandle(impl_->job);impl_->job=nullptr;}
#else
    if(impl_->process>0){kill(-impl_->process,SIGKILL);int status=0;while(waitpid(impl_->process,&status,0)<0&&errno==EINTR){}impl_->process=-1;}
#endif
    impl_->state=WorkerProcessState::Stopped;
}
int WorkerSupervisor::ExitCode()const{return impl_->exitCode;}
}
