// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Wire layout: Microsoft TSS.MSR PCPTool.v11/inc/TpmAtt.h and TPM 2.0
// TPMS_ATTEST/TPMT_PUBLIC. Independent bounded parser; no private TPM blobs
// or optional unauthenticated PCP flags are treated as hardware evidence.
#include "axr/WindowsAttestation.hpp"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if defined(_WIN32)
#define NOMINMAX
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <windows.h>
#include <wincrypt.h>
#endif
namespace Stellaria::AXR {
namespace {
struct Reader {
    std::string_view value;size_t offset=0;
    std::string_view Take(size_t n){if(n>value.size()-offset)throw std::runtime_error("attestation_truncated");auto part=value.substr(offset,n);offset+=n;return part;}
    uint32_t Number(size_t n,bool little=false){auto part=Take(n);uint32_t result=0;for(size_t i=0;i<n;++i)result|=uint32_t(uint8_t(part[i]))<<(8*(little?i:n-1-i));return result;}
    std::string_view Blob(){return Take(Number(2));}
    void End(){if(offset!=value.size())throw std::runtime_error("attestation_trailing_data");}
};
using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
Key Public(std::string_view data){auto cursor=reinterpret_cast<const unsigned char*>(data.data());
    Key key(d2i_PUBKEY(nullptr,&cursor,long(data.size())),EVP_PKEY_free);
    if(!key||cursor!=reinterpret_cast<const unsigned char*>(data.data()+data.size())||EVP_PKEY_is_a(key.get(),"RSA")!=1)
        throw std::runtime_error("attestation_rsa_required");
    int size=i2d_PUBKEY(key.get(),nullptr);if(size!=int(data.size()))throw std::runtime_error("attestation_noncanonical_key");
    std::string canonical(size,'\0');auto output=reinterpret_cast<unsigned char*>(canonical.data());
    if(i2d_PUBKEY(key.get(),&output)!=size||canonical!=data)throw std::runtime_error("attestation_noncanonical_key");
    return key;
}
std::string SHA256(std::string_view value){std::string result(32,'\0');unsigned n=0;
    if(EVP_Digest(value.data(),value.size(),reinterpret_cast<unsigned char*>(result.data()),&n,EVP_sha256(),nullptr)!=1||n!=32)throw std::runtime_error("attestation_hash_failed");return result;}
bool Statement(std::string_view ownerPublicKey,std::string_view aikPublicKey,std::string_view statement){
    if(ownerPublicKey.size()!=294||aikPublicKey.size()>1024||statement.size()>65536)return false;
    auto owner=Public(ownerPublicKey);auto aik=Public(aikPublicKey);
    if(EVP_PKEY_get_bits(owner.get())!=2048||EVP_PKEY_get_bits(aik.get())<2048||EVP_PKEY_get_bits(aik.get())>4096)return false;
    Reader outer{statement};
    if(outer.Number(4,true)!=0x5344414b||outer.Number(4,true)!=2||outer.Number(4,true)!=24)return false; // KADS, TPM2
    auto attestSize=outer.Number(4,true),signatureSize=outer.Number(4,true),keySize=outer.Number(4,true);
    auto attest=outer.Take(attestSize),signature=outer.Take(signatureSize),key=outer.Take(keySize);outer.End();
    if(signature.size()!=size_t(EVP_PKEY_get_size(aik.get())))return false;
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> verify(EVP_MD_CTX_new(),EVP_MD_CTX_free);EVP_PKEY_CTX* operation=nullptr;
    // The legacy Windows PCP envelope fixes SHA-1 for this AIK certification.
    // It is never accepted for an owner challenge, authority root or permit.
    if(!verify||EVP_DigestVerifyInit(verify.get(),&operation,EVP_sha1(),nullptr,aik.get())!=1||
       !operation||EVP_PKEY_CTX_set_rsa_padding(operation,RSA_PKCS1_PADDING)<=0||
       EVP_DigestVerify(verify.get(),reinterpret_cast<const unsigned char*>(signature.data()),signature.size(),
           reinterpret_cast<const unsigned char*>(attest.data()),attest.size())!=1)return false;
    Reader pcp{key};
    if(pcp.Number(4,true)!=0x4d504350)return false; // PCPM
    auto header=pcp.Number(4,true);if(header<52||header>64||pcp.Number(4,true)!=2)return false;
    pcp.Number(4,true); // Unauthenticated storage flags cannot prove presence.
    auto publicSize=pcp.Number(4,true);uint64_t total=header+uint64_t(publicSize);
    for(int i=0;i<8;++i)total+=pcp.Number(4,true);
    if(total!=key.size())return false;
    pcp.Take(header-pcp.offset);Reader sizedPublic{pcp.Take(publicSize)};
    auto publicArea=sizedPublic.Blob();sizedPublic.End();Reader area{publicArea};
    if(area.Number(2)!=1||area.Number(2)!=0x000b)return false; // RSA, SHA256 name
    auto attributes=area.Number(4);
    if((attributes&0x00040032)!=0x00040032||(attributes&0x00010000))return false; // fixedTPM/parent/origin/sign, unrestricted
    area.Blob(); // Signed authPolicy; not a claim of a particular Hello policy.
    if(area.Number(2)!=0x0010)return false; // TPM_ALG_NULL symmetric for signing key
    auto scheme=area.Number(2);
    if(scheme==0x0014){if(area.Number(2)!=0x000b)return false;}
    else if(scheme!=0x0010)return false; // NULL or RSASSA/SHA256, no negotiation
    if(area.Number(2)!=2048)return false;
    auto exponent=area.Number(4);if(exponent!=0&&exponent!=65537)return false;
    auto modulus=area.Blob();area.End();if(modulus.size()!=256)return false;
    BIGNUM* rawN=nullptr;BIGNUM* rawE=nullptr;
    if(EVP_PKEY_get_bn_param(owner.get(),OSSL_PKEY_PARAM_RSA_N,&rawN)!=1)return false;
    std::unique_ptr<BIGNUM,decltype(&BN_free)> n(rawN,BN_free);
    if(EVP_PKEY_get_bn_param(owner.get(),OSSL_PKEY_PARAM_RSA_E,&rawE)!=1)return false;
    std::unique_ptr<BIGNUM,decltype(&BN_free)> e(rawE,BN_free);
    std::string expected(256,'\0');
    if(!BN_is_word(e.get(),65537)||BN_bn2binpad(n.get(),reinterpret_cast<unsigned char*>(expected.data()),256)!=256||expected!=modulus)return false;
    Reader certify{attest};
    if(certify.Number(4)!=0xff544347||certify.Number(2)!=0x8017)return false;
    certify.Blob();certify.Blob();certify.Take(17);certify.Take(8); // signer, nonce, clock, firmware
    auto name=certify.Blob();certify.Blob();certify.End();
    return name==std::string("\0\x0b",2)+SHA256(publicArea);
}
#if defined(_WIN32)
bool AIKUsage(PCCERT_CONTEXT cert){
    DWORD size=0;if(!CertGetEnhancedKeyUsage(cert,CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,nullptr,&size)||size>8192)return false;
    std::vector<unsigned char> buffer(size);auto usage=reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());
    if(!CertGetEnhancedKeyUsage(cert,CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,usage,&size))return false;
    for(DWORD i=0;i<usage->cUsageIdentifier;++i)if(std::string_view(usage->rgpszUsageIdentifier[i])=="2.23.133.8.3")return true;
    return false;
}
struct Store {HCERTSTORE value=nullptr;~Store(){if(value)CertCloseStore(value,0);}};
struct Engine {HCERTCHAINENGINE value=nullptr;~Engine(){if(value)CertFreeCertificateChainEngine(value);}};
struct Certificate {PCCERT_CONTEXT value=nullptr;~Certificate(){if(value)CertFreeCertificateContext(value);}};
struct Chain {PCCERT_CHAIN_CONTEXT value=nullptr;~Chain(){if(value)CertFreeCertificateChain(value);}};
bool Attestation(std::string_view publicKey,std::string_view statement,std::string_view encodedChain,const std::vector<std::string>& roots,bool machine=false){
    if(publicKey.size()!=294||statement.size()>65536||encodedChain.empty()||encodedChain.size()>65536||(!machine&&roots.empty())||roots.size()>8)return false;
    Store trust{machine?CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_READONLY_FLAG|CERT_STORE_OPEN_EXISTING_FLAG,L"ROOT"):
        CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,CERT_STORE_CREATE_NEW_FLAG,nullptr)};
    if(!trust.value)return false;
    for(const auto& root:roots){if(root.empty()||root.size()>8192||!CertAddEncodedCertificateToStore(trust.value,X509_ASN_ENCODING,
            reinterpret_cast<const BYTE*>(root.data()),DWORD(root.size()),CERT_STORE_ADD_NEW,nullptr))return false;}
    CRYPT_DATA_BLOB data{DWORD(encodedChain.size()),reinterpret_cast<BYTE*>(const_cast<char*>(encodedChain.data()))};
    Store supplied{CertOpenStore(CERT_STORE_PROV_PKCS7,PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,0,CERT_STORE_READONLY_FLAG,&data)};
    if(!supplied.value)return false;
    Certificate aik;PCCERT_CONTEXT current=nullptr;size_t count=0;
    while((current=CertEnumCertificatesInStore(supplied.value,current))){
        if(++count>16){CertFreeCertificateContext(current);return false;}
        if(AIKUsage(current)){
            if(aik.value){CertFreeCertificateContext(current);return false;}
            aik.value=CertDuplicateCertificateContext(current);
        }
    }
    if(!aik.value)return false;
    const unsigned char* certificateBytes=aik.value->pbCertEncoded;
    std::unique_ptr<X509,decltype(&X509_free)> leaf(d2i_X509(nullptr,&certificateBytes,aik.value->cbCertEncoded),X509_free);
    if(!leaf||X509_check_ca(leaf.get())!=0)return false;
    Engine engine;CERT_CHAIN_ENGINE_CONFIG config{};config.cbSize=sizeof(config);config.hExclusiveRoot=trust.value;
    config.dwFlags=CERT_CHAIN_USE_LOCAL_MACHINE_STORE|CERT_CHAIN_DISABLE_AIA;config.dwUrlRetrievalTimeout=5000;config.MaximumCachedCertificates=32;
    if(!CertCreateCertificateChainEngine(&config,&engine.value))return false;
    char oid[]="2.23.133.8.3";LPSTR usages[]={oid};CERT_CHAIN_PARA parameters{};parameters.cbSize=sizeof(parameters);
    parameters.RequestedUsage.dwType=USAGE_MATCH_TYPE_AND;parameters.RequestedUsage.Usage={1,usages};parameters.dwUrlRetrievalTimeout=5000;
    Chain chain;
    if(!CertGetCertificateChain(engine.value,aik.value,nullptr,supplied.value,&parameters,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT|CERT_CHAIN_DISABLE_AIA|CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,nullptr,&chain.value)||
            !chain.value||chain.value->TrustStatus.dwErrorStatus||chain.value->cChain!=1||chain.value->rgpChain[0]->cElement<2||chain.value->rgpChain[0]->cElement>8)return false;
    CERT_CHAIN_POLICY_PARA policy{};policy.cbSize=sizeof(policy);CERT_CHAIN_POLICY_STATUS status{};status.cbSize=sizeof(status);
    if(!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE,chain.value,&policy,&status)||status.dwError)return false;
    const auto& spki=aik.value->pCertInfo->SubjectPublicKeyInfo;DWORD size=0;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,&spki,0,nullptr,nullptr,&size)||size>1024)return false;
    std::string aikKey(size,'\0');
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,&spki,0,nullptr,aikKey.data(),&size))return false;
    return Statement(publicKey,aikKey,statement);
}
#endif
}
bool VerifyWindowsHelloStatement(std::string_view owner,std::string_view aik,std::string_view statement){
    try{return Statement(owner,aik,statement);}catch(...){return false;}
}
bool VerifyWindowsHelloAttestation(std::string_view owner,std::string_view statement,std::string_view chain,const std::vector<std::string>& roots){
#if defined(_WIN32)
    try{return Attestation(owner,statement,chain,roots);}catch(...){return false;}
#else
    (void)owner;(void)statement;(void)chain;(void)roots;return false;
#endif
}
bool VerifyWindowsHelloAttestationMachine(std::string_view owner,std::string_view statement,std::string_view chain){
#if defined(_WIN32)
    try{return Attestation(owner,statement,chain,{},true);}catch(...){return false;}
#else
    (void)owner;(void)statement;(void)chain;return false;
#endif
}
std::string WindowsMachineCABundle(){
#if defined(_WIN32)
    Store roots{CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_READONLY_FLAG|CERT_STORE_OPEN_EXISTING_FLAG,L"ROOT")};
    if(!roots.value)throw std::runtime_error("windows_public_roots_unavailable");
    std::string pem;PCCERT_CONTEXT certificate=nullptr;unsigned count=0;
    while((certificate=CertEnumCertificatesInStore(roots.value,certificate))){
        // Managed/CI machines can carry more than 512 public machine roots.
        // Retain the overall 2 MiB output cap; never truncate a trust bundle.
        if(++count>4096||certificate->cbCertEncoded>65536){CertFreeCertificateContext(certificate);throw std::runtime_error("windows_public_roots_budget");}
        DWORD size=0;
        if(!CryptBinaryToStringA(certificate->pbCertEncoded,certificate->cbCertEncoded,CRYPT_STRING_BASE64HEADER,nullptr,&size)||size>131072){CertFreeCertificateContext(certificate);throw std::runtime_error("windows_public_roots_invalid");}
        std::string text(size,'\0');
        if(!CryptBinaryToStringA(certificate->pbCertEncoded,certificate->cbCertEncoded,CRYPT_STRING_BASE64HEADER,text.data(),&size)){
            CertFreeCertificateContext(certificate);throw std::runtime_error("windows_public_roots_invalid");}
        if(!text.empty()&&text.back()=='\0')text.pop_back();pem+=text;
        if(pem.size()>2*1024*1024){CertFreeCertificateContext(certificate);throw std::runtime_error("windows_public_roots_budget");}
    }
    if(!count)throw std::runtime_error("windows_public_roots_unavailable");return pem;
#else
    throw std::runtime_error("windows_public_roots_platform_required");
#endif
}
}
