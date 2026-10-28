// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#include "axr/ProtectedStore.hpp"
#include "axr/Security.hpp"
#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <wincred.h>
#endif
#ifndef AXR_AUTHORITY_KEYCHAIN_GROUP
#define AXR_AUTHORITY_KEYCHAIN_GROUP ""
#endif
namespace Stellaria::AXR {
namespace {
void Name(std::string_view name){if(name.empty()||name.size()>200||name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")!=std::string::npos)throw std::runtime_error("protected_store_name_invalid");}
#if defined(__APPLE__)
CFStringRef String(std::string_view value){return CFStringCreateWithBytes(nullptr,reinterpret_cast<const UInt8*>(value.data()),value.size(),kCFStringEncodingUTF8,false);}
CFMutableDictionaryRef Query(const std::string& space,const std::string& name){
    auto query=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    auto service=String(space),account=String(name),group=String(AXR_AUTHORITY_KEYCHAIN_GROUP);
    CFDictionarySetValue(query,kSecClass,kSecClassGenericPassword);CFDictionarySetValue(query,kSecAttrService,service);
    CFDictionarySetValue(query,kSecAttrAccount,account);
    if(!std::string_view(AXR_AUTHORITY_KEYCHAIN_GROUP).empty()){
        CFDictionarySetValue(query,kSecAttrAccessGroup,group);CFDictionarySetValue(query,kSecUseDataProtectionKeychain,kCFBooleanTrue);
    }
    CFRelease(service);CFRelease(account);CFRelease(group);return query;
}
#endif
}
ProtectedStore::ProtectedStore(std::string space):namespace_(std::move(space)){Name(namespace_);Identity();}
void ProtectedStore::Identity() const {
#if defined(__APPLE__)
#ifndef AXR_OWNER_DEPLOYMENT
    if(std::string_view(AXR_AUTHORITY_KEYCHAIN_GROUP).empty())throw std::runtime_error("protected_keychain_group_not_configured");
#endif
    const auto identity=ProcessIdentity(unsigned(getpid()));
#ifdef AXR_SECURITY_RELEASE
    RequireProtectedHost(identity);
#endif
    if(identity.at("signature_valid")!=true||identity.at("hardened_runtime")!=true||identity.at("signing_id")!="org.stellaria.axr.authority")throw std::runtime_error("protected_service_identity_required");
#elif defined(_WIN32)
    HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))throw std::runtime_error("protected_service_identity_required");
    DWORD length=0;GetTokenInformation(token,TokenUser,nullptr,0,&length);std::vector<unsigned char> buffer(length);
    bool valid=length&&GetTokenInformation(token,TokenUser,buffer.data(),length,&length)&&IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,WinLocalSystemSid);
    CloseHandle(token);if(!valid)throw std::runtime_error("protected_service_identity_required");
#ifdef AXR_SECURITY_RELEASE
    RequireProtectedHost(ProcessIdentity(GetCurrentProcessId()));
#endif
#else
    throw std::runtime_error("protected_store_platform_unavailable");
#endif
}
std::string ProtectedStore::Get(const std::string& name) const {
    Name(name);Identity();
#if defined(__APPLE__)
    auto query=Query(namespace_,name);CFDictionarySetValue(query,kSecUseAuthenticationUI,kSecUseAuthenticationUIFail);CFDictionarySetValue(query,kSecReturnData,kCFBooleanTrue);CFDictionarySetValue(query,kSecMatchLimit,kSecMatchLimitOne);
    CFTypeRef result=nullptr;auto status=SecItemCopyMatching(query,&result);CFRelease(query);
    if(status==errSecItemNotFound)throw std::runtime_error("owner_secret_not_provisioned");
    if(status!=errSecSuccess||!result)throw std::runtime_error("protected_store_access_denied");
    if(CFGetTypeID(result)!=CFDataGetTypeID()){CFRelease(result);throw std::runtime_error("protected_store_record_invalid");}
    auto data=(CFDataRef)result;std::string value(reinterpret_cast<const char*>(CFDataGetBytePtr(data)),CFDataGetLength(data));CFRelease(result);return value;
#elif defined(_WIN32)
    std::wstring target(namespace_.begin(),namespace_.end());target+=L":"+std::wstring(name.begin(),name.end());PCREDENTIALW credential=nullptr;
    if(!CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&credential))throw std::runtime_error(GetLastError()==ERROR_NOT_FOUND?"owner_secret_not_provisioned":"protected_store_access_denied");
    std::string value(reinterpret_cast<char*>(credential->CredentialBlob),credential->CredentialBlobSize);CredFree(credential);return value;
#else
    throw std::runtime_error("protected_store_platform_unavailable");
#endif
}
void ProtectedStore::Put(const std::string& name,std::string_view bytes) const {
    Name(name);Identity();if(bytes.size()>4096)throw std::runtime_error("protected_store_record_budget");
#if defined(__APPLE__)
    auto query=Query(namespace_,name);auto value=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(bytes.data()),bytes.size());
    auto update=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFDictionarySetValue(update,kSecValueData,value);
    auto status=SecItemUpdate(query,update);CFRelease(update);
    if(status==errSecItemNotFound){
        CFDictionarySetValue(query,kSecValueData,value);
        if(std::string_view(AXR_AUTHORITY_KEYCHAIN_GROUP).empty()){
            // Native creator ACL pins the self-deployed authority application;
            // it does not grant the owner's other Python applications access.
            SecTrustedApplicationRef application=nullptr;SecAccessRef access=nullptr;
            auto identity=ProcessIdentity(unsigned(getpid()));auto image=identity.at("image").get<std::string>();
            if(SecTrustedApplicationCreateFromPath(image.c_str(),&application)!=errSecSuccess){CFRelease(value);CFRelease(query);throw std::runtime_error("protected_store_acl_unavailable");}
            const void* values[]={application};auto applications=CFArrayCreate(nullptr,values,1,&kCFTypeArrayCallBacks);
            auto title=String(namespace_);auto created=SecAccessCreate(title,applications,&access);CFRelease(title);CFRelease(applications);CFRelease(application);
            if(created!=errSecSuccess||!access){CFRelease(value);CFRelease(query);throw std::runtime_error("protected_store_acl_unavailable");}
            CFDictionarySetValue(query,kSecAttrAccess,access);CFRelease(access);
        }else CFDictionarySetValue(query,kSecAttrAccessible,kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
        status=SecItemAdd(query,nullptr);
    }
    CFRelease(value);CFRelease(query);if(status!=errSecSuccess)throw std::runtime_error("protected_store_write_denied");
#elif defined(_WIN32)
    std::wstring target(namespace_.begin(),namespace_.end());target+=L":"+std::wstring(name.begin(),name.end());
    CREDENTIALW credential{};credential.Type=CRED_TYPE_GENERIC;credential.TargetName=target.data();credential.CredentialBlobSize=DWORD(bytes.size());
    credential.CredentialBlob=reinterpret_cast<LPBYTE>(const_cast<char*>(bytes.data()));credential.Persist=CRED_PERSIST_LOCAL_MACHINE;
    if(!CredWriteW(&credential,0))throw std::runtime_error("protected_store_write_denied");
#else
    (void)bytes;throw std::runtime_error("protected_store_platform_unavailable");
#endif
}
}
