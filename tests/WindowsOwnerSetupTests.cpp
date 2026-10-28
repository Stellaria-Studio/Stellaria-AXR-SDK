// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "../src/WindowsSetupTransport.hpp"
#include "axr/Security.hpp"
#include <cassert>
#include <iostream>
#include <thread>
using namespace Stellaria::AXR;
using namespace Stellaria::AXR::WindowsSetupTransport;
namespace {
struct Pair {
    std::wstring endpoint;HANDLE server=INVALID_HANDLE_VALUE,client=INVALID_HANDLE_VALUE;
    Pair(){endpoint=L"\\\\.\\pipe\\Stellaria.AXR.Test.Setup."+Utf8Path(RandomId()).wstring();
        server=CreateNamedPipeW(endpoint.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,1000,nullptr);
        assert(server!=INVALID_HANDLE_VALUE);}
    void Open(){client=CreateFileW(endpoint.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,nullptr);assert(client!=INVALID_HANDLE_VALUE);
        DWORD mode=PIPE_READMODE_MESSAGE;assert(SetNamedPipeHandleState(client,&mode,nullptr,nullptr));}
    ~Pair(){if(client!=INVALID_HANDLE_VALUE)CloseHandle(client);if(server!=INVALID_HANDLE_VALUE)CloseHandle(server);}
};
}
int main(){
    auto actual=ProcessIdentity(GetCurrentProcessId());
    {Pair pair;std::exception_ptr failure;
     std::thread worker([&]{try{Deadline budget(Now()+5);Connect(pair.server,budget);
        assert((Receive(pair.server,1024,budget,false,actual)==Json{{"request","fixture"}}));
        Send(pair.server,{{"response","fixture"}},budget,false,actual);}catch(...){failure=std::current_exception();}});
     pair.Open();Deadline budget(Now()+5);Send(pair.client,{{"request","fixture"}},budget,true,actual);
     assert((Receive(pair.client,1024,budget,true,actual)==Json{{"response","fixture"}}));worker.join();if(failure)std::rethrow_exception(failure);}
    {Pair pair;bool denied=false;auto start=GetTickCount64();
     try{Connect(pair.server,Deadline(Now()+0.1));}catch(const std::exception& error){denied=std::string(error.what())=="windows_owner_setup_expired";}
     assert(denied&&GetTickCount64()-start<2000);}
    {Pair pair;pair.Open();Deadline budget(Now()+2);Connect(pair.server,budget);bool denied=false;
     try{Receive(pair.server,1024,Deadline(Now()+0.1),false,actual);}catch(const std::exception& error){denied=std::string(error.what())=="windows_owner_setup_expired";}
     assert(denied);}
    {Pair pair;pair.Open();Deadline budget(Now()+2);Connect(pair.server,budget);auto wrong=actual;wrong["birth"]="different";bool denied=false;
     try{Receive(pair.server,1024,budget,false,wrong);}catch(...){denied=true;}assert(denied);}
    {Pair pair;pair.Open();Deadline budget(Now()+2);Connect(pair.server,budget);bool denied=false;auto start=GetTickCount64();
     auto check=[&]{if(GetTickCount64()-start>100)throw std::runtime_error("synthetic_scope_stopped");};
     try{Receive(pair.server,1024,Deadline(Now()+5,check),false,actual);}catch(const std::exception& error){denied=std::string(error.what())=="synthetic_scope_stopped";}
     assert(denied&&GetTickCount64()-start<1000);}
    {Pair pair;pair.Open();Deadline budget(Now()+2);Connect(pair.server,budget);std::string raw(256,'x');
     assert(Transfer(pair.client,raw.data(),DWORD(raw.size()),true,budget)==raw.size());bool denied=false;
     try{Receive(pair.server,100,budget,false,actual);}catch(...){denied=true;}assert(denied);}
    std::cout<<"native setup message roundtrip, identity, bounds and cancellation passed; no service or owner launch\n";
}
