// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Sandboxing witness used only with synthetic fixture data / loopback TCP.
#include "axr/Core.hpp"
#include <iostream>
#include <fstream>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
int main(){using namespace Stellaria::AXR;Json output;try{
    std::string line;std::getline(std::cin,line);if(line.size()>4096)return 2;auto request=Json::parse(line);
    if(request.at("op")=="read"){
        std::ifstream file(Utf8Path(request.at("path").get<std::string>()),std::ios::binary);
        output={{"allowed",bool(file)}};
    }else if(request.at("op")=="network"){
#ifdef _WIN32
        WSADATA data;WSAStartup(MAKEWORD(2,2),&data);
#endif
        auto handle=socket(AF_INET,SOCK_STREAM,0);sockaddr_in address{};address.sin_family=AF_INET;
        address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(request.at("port").get<unsigned short>());
#ifdef _WIN32
        // AppContainer/WFP may silently drop loopback TCP instead of returning
        // access denied. A blocking connect can wait past the supervisor limit.
        // Bound the witness itself; the unsandboxed control must still connect.
        bool allowed=false;u_long nonblocking=1;
        if(handle!=INVALID_SOCKET&&ioctlsocket(handle,FIONBIO,&nonblocking)==0){
            int result=connect(handle,reinterpret_cast<sockaddr*>(&address),sizeof(address));
            if(result==0)allowed=true;
            else if(WSAGetLastError()==WSAEWOULDBLOCK){
                fd_set writable,errors;FD_ZERO(&writable);FD_ZERO(&errors);
                FD_SET(handle,&writable);FD_SET(handle,&errors);timeval timeout{1,500000};
                if(select(0,nullptr,&writable,&errors,&timeout)>0&&FD_ISSET(handle,&writable)&&!FD_ISSET(handle,&errors)){
                    int error=0,length=sizeof(error);
                    allowed=getsockopt(handle,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&length)==0&&error==0;
                }
            }
        }
        if(handle!=INVALID_SOCKET)closesocket(handle);WSACleanup();
#else
        bool allowed=connect(handle,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0;
        if(handle>=0)close(handle);
#endif
        output={{"allowed",allowed}};
    }else return 2;
}catch(...){return 2;}std::cout<<output.dump()<<std::endl;}
