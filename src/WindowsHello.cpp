// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/WindowsHello.hpp"
#include "axr/TrustRoot.hpp"
#include "axr/Security.hpp"
#include "axr/WindowsInstallation.hpp"
#include <cmath>
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Core.h>
#include <winrt/Windows.Storage.Streams.h>
#include <chrono>
#endif
namespace Stellaria::AXR {
namespace {
#if defined(_WIN32)
using namespace winrt::Windows::Security::Credentials;
using namespace winrt::Windows::Security::Cryptography;
using namespace winrt::Windows::Security::Cryptography::Core;
void OwnerHost(){
    // Always enforced, including reference builds: tests must never pop Hello.
    auto identity=ProcessIdentity(GetCurrentProcessId());
    auto image=Utf8Path(identity.at("image").get<std::string>());
    if(image.filename()!=L"axr-owner.exe")throw std::runtime_error("hello_protected_owner_host_required");
    DWORD session=0;
    if(identity.at("user")=="S-1-5-18"||!ProcessIdToSessionId(GetCurrentProcessId(),&session)||session==0)
        throw std::runtime_error("hello_interactive_owner_required");
    try{VerifyWindowsInstallation(image.parent_path());}
    catch(...){throw std::runtime_error("hello_owner_installation_required");}
}
template<class Operation,class Duration> auto Await(Operation operation,Duration budget){
    using winrt::Windows::Foundation::AsyncStatus;
    if(operation.wait_for(budget)!=AsyncStatus::Completed){
        operation.Cancel();throw std::runtime_error("hello_operation_cancelled_failed_or_expired");
    }
    return operation.GetResults();
}
struct Apartment {
    Apartment(){winrt::init_apartment(winrt::apartment_type::multi_threaded);}
    ~Apartment(){winrt::uninit_apartment();}
};
std::string Bytes(const winrt::Windows::Storage::Streams::IBuffer& buffer,size_t maximum){
    if(!buffer||buffer.Length()>maximum)throw std::runtime_error("hello_result_budget");
    winrt::com_array<uint8_t> bytes;CryptographicBuffer::CopyToByteArray(buffer,bytes);
    return std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size());
}
struct EnrollmentReview {
    double expires=0;ULONGLONG monotonicEnd=0;bool accepted=false;
    HWND details=nullptr,confirm=nullptr,cancel=nullptr;
};
bool Expired(const EnrollmentReview& review){return Now()>=review.expires||GetTickCount64()>=review.monotonicEnd;}
LRESULT CALLBACK EnrollmentWindow(HWND window,UINT message,WPARAM wparam,LPARAM lparam){
    auto state=reinterpret_cast<EnrollmentReview*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){state=static_cast<EnrollmentReview*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(state));}
    if(!state)return DefWindowProcW(window,message,wparam,lparam);
    if(message==DM_GETDEFID)return MAKELRESULT(IDCANCEL,DC_HASDEFID);
    if(message==WM_SIZE){
        auto width=LOWORD(lparam),height=HIWORD(lparam);int scale=int(GetDpiForWindow(window));
        int gap=MulDiv(16,scale,96),buttonWidth=MulDiv(150,scale,96),buttonHeight=MulDiv(36,scale,96);
        MoveWindow(state->details,gap,gap,width-2*gap,height-3*gap-buttonHeight,TRUE);
        MoveWindow(state->confirm,width-2*buttonWidth-2*gap,height-gap-buttonHeight,buttonWidth,buttonHeight,TRUE);
        MoveWindow(state->cancel,width-buttonWidth-gap,height-gap-buttonHeight,buttonWidth,buttonHeight,TRUE);return 0;
    }
    if(message==WM_COMMAND&&(LOWORD(wparam)==IDOK||LOWORD(wparam)==IDCANCEL)){
        state->accepted=LOWORD(wparam)==IDOK&&!Expired(*state);DestroyWindow(window);return 0;
    }
    if(message==WM_TIMER&&Expired(*state)){DestroyWindow(window);return 0;}
    if(message==WM_CLOSE){DestroyWindow(window);return 0;}
    if(message==WM_DESTROY){KillTimer(window,1);return 0;}
    if(message==WM_NCDESTROY)SetWindowLongPtrW(window,GWLP_USERDATA,0);
    return DefWindowProcW(window,message,wparam,lparam);
}
bool ReviewEnrollment(std::string_view text,double expires,bool enrollment=true){
    HMODULE module=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&EnrollmentWindow),&module))throw std::runtime_error("hello_review_unavailable");
    constexpr auto name=L"Stellaria.AXR.Owner.EnrollmentReview.v2";
    WNDCLASSEXW existing{};existing.cbSize=sizeof(existing);
    if(!GetClassInfoExW(module,name,&existing)){
        WNDCLASSEXW type{};type.cbSize=sizeof(type);type.lpfnWndProc=EnrollmentWindow;type.hInstance=module;
        type.hCursor=LoadCursorW(nullptr,MAKEINTRESOURCEW(32512));type.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);type.lpszClassName=name;
        if(!RegisterClassExW(&type))throw std::runtime_error("hello_review_unavailable");
    }else if(existing.lpfnWndProc!=EnrollmentWindow)throw std::runtime_error("hello_review_unavailable");
    auto remaining=std::min(expires-Now(),180.0);if(remaining<=0)return false;
    EnrollmentReview state{expires,GetTickCount64()+ULONGLONG(remaining*1000)};
    RECT screen{};if(!SystemParametersInfoW(SPI_GETWORKAREA,0,&screen,0))throw std::runtime_error("hello_review_unavailable");
    int width=std::min(800L,screen.right-screen.left-40),height=std::min(680L,screen.bottom-screen.top-40);
    HWND window=CreateWindowExW(WS_EX_CONTROLPARENT,name,enrollment?L"微信代理 · 首次登记所有者":L"微信代理 · 所有者授权审查",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_THICKFRAME,
        screen.left+(screen.right-screen.left-width)/2,screen.top+(screen.bottom-screen.top-height)/2,width,height,nullptr,nullptr,module,&state);
    if(!window)throw std::runtime_error("hello_review_unavailable");
    struct Close {HWND window;~Close(){if(IsWindow(window))DestroyWindow(window);}} close{window};
    auto review=winrt::to_hstring(text);
    state.details=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
        0,0,0,0,window,nullptr,module,nullptr);
    state.confirm=CreateWindowExW(0,L"BUTTON",L"确认并继续",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,0,0,0,0,window,reinterpret_cast<HMENU>(IDOK),module,nullptr);
    state.cancel=CreateWindowExW(0,L"BUTTON",L"取消",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,0,0,0,0,window,reinterpret_cast<HMENU>(IDCANCEL),module,nullptr);
    if(!state.details||!state.confirm||!state.cancel||!SetTimer(window,1,250,nullptr))throw std::runtime_error("hello_review_unavailable");
    for(auto control:{state.details,state.confirm,state.cancel})SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),TRUE);
    SendMessageW(state.details,EM_SETLIMITTEXT,65536,0);SetWindowTextW(state.details,review.c_str());
    RECT client{};GetClientRect(window,&client);SendMessageW(window,WM_SIZE,0,MAKELPARAM(client.right,client.bottom));
    ShowWindow(window,SW_SHOW);SetForegroundWindow(window);SetFocus(state.cancel);
    MSG message{};
    while(IsWindow(window)){
        if(Expired(state)){DestroyWindow(window);break;}
        auto result=GetMessageW(&message,nullptr,0,0);
        if(result<=0){if(result==0)PostQuitMessage(int(message.wParam));return false;}
        if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}
    }
    return state.accepted&&!Expired(state);
}
#endif
}
struct WindowsHelloOwnerKey::Impl {
    std::string publicKey;
#if defined(_WIN32)
    KeyCredential key{nullptr};
#endif
};
bool ReviewWindowsOwner(std::string review,double expires){
    if(review.empty()||review.size()>65536||review.find('\0')!=std::string::npos||
       !std::isfinite(expires)||expires<=Now()||expires>Now()+180)throw std::runtime_error("hello_owner_review_invalid");
#if defined(_WIN32)
    OwnerHost();
    try{return ReviewEnrollment(review,expires,false);}
    catch(const winrt::hresult_error&){throw std::runtime_error("hello_review_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
WindowsHelloOwnerKey::WindowsHelloOwnerKey():impl_(std::make_unique<Impl>()){}
std::unique_ptr<WindowsHelloOwnerKey> WindowsHelloOwnerKey::Provision(std::string review,double expires){
    if(review.empty()||review.size()>65536||review.find('\0')!=std::string::npos||
            !std::isfinite(expires)||expires<=Now()||expires>Now()+180)throw std::runtime_error("hello_enrollment_review_invalid");
#if defined(_WIN32)
    OwnerHost(); // Also before local review; ordinary Python must never show UI.
    try{
        Apartment apartment;
        if(!Await(KeyCredentialManager::IsSupportedAsync(),std::chrono::seconds(15)))throw std::runtime_error("hello_provider_unavailable");
        if(!ReviewEnrollment(review,expires))throw std::runtime_error("hello_enrollment_cancelled_or_expired");
        auto remaining=expires-Now();if(remaining<=0)throw std::runtime_error("hello_enrollment_cancelled_or_expired");
        auto result=Await(KeyCredentialManager::RequestCreateAsync(L"Stellaria.AXR.Owner.v2.owner-presence-v2",
            KeyCredentialCreationOption::FailIfExists),std::chrono::milliseconds(int64_t(std::min(remaining,60.0)*1000)));
        if(result.Status()==KeyCredentialStatus::CredentialAlreadyExists)throw std::runtime_error("hello_existing_credential_requires_explicit_recovery");
        if(result.Status()!=KeyCredentialStatus::Success||Now()>=expires)throw std::runtime_error("hello_enrollment_failed_or_expired");
        auto key=std::unique_ptr<WindowsHelloOwnerKey>(new WindowsHelloOwnerKey());key->impl_->key=result.Credential();
        key->impl_->publicKey=Bytes(key->impl_->key.RetrievePublicKey(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo),294);
        if(key->impl_->publicKey.size()!=294)throw std::runtime_error("hello_public_key_profile_unsupported");
        return key;
    }catch(const winrt::hresult_error&){throw std::runtime_error("hello_enrollment_failed_or_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
std::unique_ptr<WindowsHelloOwnerKey> WindowsHelloOwnerKey::Recover(std::string review,double expires){
    if(review.empty()||review.size()>64000||review.find('\0')!=std::string::npos||!std::isfinite(expires)||expires<=Now()||expires>Now()+180)
        throw std::runtime_error("hello_enrollment_review_invalid");
#if defined(_WIN32)
    OwnerHost();
    try{
        Apartment apartment;
        if(!Await(KeyCredentialManager::IsSupportedAsync(),std::chrono::seconds(15)))throw std::runtime_error("hello_provider_unavailable");
        auto opened=Await(KeyCredentialManager::OpenAsync(L"Stellaria.AXR.Owner.v2.owner-presence-v2"),std::chrono::seconds(15));
        if(opened.Status()!=KeyCredentialStatus::Success)throw std::runtime_error("hello_enrolled_credential_unavailable");
        auto key=std::unique_ptr<WindowsHelloOwnerKey>(new WindowsHelloOwnerKey());key->impl_->key=opened.Credential();
        key->impl_->publicKey=Bytes(key->impl_->key.RetrievePublicKey(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo),294);
        if(key->impl_->publicKey.size()!=294)throw std::runtime_error("hello_public_key_profile_unsupported");
        review+="\r\nWindows Hello public key SHA-256: "+Digest(key->impl_->publicKey);
        if(!ReviewEnrollment(review,expires,false)||Now()>=expires)throw std::runtime_error("hello_enrollment_cancelled_or_expired");
        return key;
    }catch(const winrt::hresult_error&){throw std::runtime_error("hello_provider_failed_or_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
WindowsHelloOwnerKey::WindowsHelloOwnerKey(std::string expectedPublicKey):impl_(std::make_unique<Impl>()){
    if(expectedPublicKey.size()!=294)throw std::runtime_error("hello_enrolled_public_key_required");
#if defined(_WIN32)
    OwnerHost(); // Before WinRT initialization, discovery or any possible UI.
    try{
        Apartment apartment;
        if(!Await(KeyCredentialManager::IsSupportedAsync(),std::chrono::seconds(15)))
            throw std::runtime_error("hello_provider_unavailable");
        auto result=Await(KeyCredentialManager::OpenAsync(L"Stellaria.AXR.Owner.v2.owner-presence-v2"),std::chrono::seconds(15));
        if(result.Status()!=KeyCredentialStatus::Success)throw std::runtime_error("hello_enrolled_credential_unavailable");
        impl_->key=result.Credential();
        auto publicKey=Bytes(impl_->key.RetrievePublicKey(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo),294);
        if(!ConstantEqual(publicKey,expectedPublicKey))throw std::runtime_error("hello_enrolled_public_key_changed");
        impl_->publicKey=std::move(publicKey);
    }catch(const winrt::hresult_error&){throw std::runtime_error("hello_provider_failed_or_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
WindowsHelloOwnerKey::~WindowsHelloOwnerKey()=default;
std::string WindowsHelloOwnerKey::PublicKey() const {return impl_->publicKey;}
Json WindowsHelloOwnerKey::Attestation() const {
#if defined(_WIN32)
    try{
        Apartment apartment;
        auto result=Await(impl_->key.GetAttestationAsync(),std::chrono::seconds(30));
        if(result.Status()!=KeyCredentialAttestationStatus::Success)throw std::runtime_error("hello_attestation_unavailable");
        auto statement=Bytes(result.AttestationBuffer(),65536),chain=Bytes(result.CertificateChainBuffer(),65536);
        auto hex=[](std::string_view value){constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(value.size()*2);
            for(unsigned char c:value){out+=digits[c>>4];out+=digits[c&15];}return out;};
        return {{"statement",hex(statement)},{"certificate_chain",hex(chain)}};
    }catch(const winrt::hresult_error&){throw std::runtime_error("hello_attestation_failed_or_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
std::string WindowsHelloOwnerKey::Sign(std::string_view message) const {
    if(message.empty()||message.size()>MaximumFrameBytes)throw std::runtime_error("hello_message_budget");
#if defined(_WIN32)
    try{
        Apartment apartment;
        auto bytes=winrt::array_view<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()),
            reinterpret_cast<const uint8_t*>(message.data()+message.size()));
        // RequestSignAsync prompts for each operation. Never reuse a boolean
        // UserConsentVerifier result or issue a silent TPM signature instead.
        auto result=Await(impl_->key.RequestSignAsync(CryptographicBuffer::CreateFromByteArray(bytes)),std::chrono::seconds(60));
        if(result.Status()!=KeyCredentialStatus::Success)throw std::runtime_error("hello_signature_cancelled_or_failed");
        auto signature=Bytes(result.Result(),256);
        if(!VerifyOwnerSignature(impl_->publicKey,message,signature))throw std::runtime_error("hello_signature_invalid");
        return signature;
    }catch(const winrt::hresult_error&){throw std::runtime_error("hello_signature_failed_or_unavailable");}
#else
    throw std::runtime_error("windows_hello_required");
#endif
}
}
