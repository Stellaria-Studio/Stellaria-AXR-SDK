// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#define NOMINMAX
#include <windows.h>
#include <userconsentverifierinterop.h>
#include <iostream>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include "axr/Core.hpp"
int main(){using namespace winrt::Windows::Security::Credentials::UI;Stellaria::AXR::Json result;HWND window=nullptr;
    try{winrt::init_apartment(winrt::apartment_type::multi_threaded);std::string line;std::getline(std::cin,line);
        if(line.size()>1024||Stellaria::AXR::Json::parse(line).at("op")!="owner_auth")throw std::runtime_error("request_denied");
        auto status=UserConsentVerifier::CheckAvailabilityAsync().get();
        if(status!=UserConsentVerifierAvailability::Available)throw std::runtime_error("owner_auth_unavailable");
        // Desktop apps use HWND interop, not the UWP CoreWindow API.
        window=CreateWindowExW(WS_EX_TOPMOST,L"STATIC",L"AXR: authenticate the exact operation reviewed in your owner terminal / panel.",
            WS_OVERLAPPED|WS_CAPTION|WS_VISIBLE,200,200,650,100,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
        if(!window)throw std::runtime_error("owner_window_unavailable");
        auto interop=winrt::get_activation_factory<UserConsentVerifier,IUserConsentVerifierInterop>();
        winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult> operation{nullptr};
        winrt::hstring message=L"Authorize the exact AXR operation reviewed in your local owner terminal or panel.";
        winrt::check_hresult(interop->RequestVerificationForWindowAsync(window,static_cast<HSTRING>(winrt::get_abi(message)),
            winrt::guid_of<decltype(operation)>(),reinterpret_cast<void**>(winrt::put_abi(operation))));
        result={{"verified",operation.get()==UserConsentVerificationResult::Verified}};
    }catch(...){result={{"error","owner_auth_failed_or_unavailable"}};}
    if(window)DestroyWindow(window);std::cout<<result.dump()<<std::endl;return 0;}
