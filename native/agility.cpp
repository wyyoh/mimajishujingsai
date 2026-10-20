#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <cstring>
#include <string>
#include <stdexcept>
#include <climits>

thread_local std::string grid_private_password;
int grid_password_callback(char* buffer,int size,int,void*) {
    if(grid_private_password.empty() || grid_private_password.size()>=static_cast<size_t>(size)) return 0;
    memcpy(buffer,grid_private_password.data(),grid_private_password.size());
    return static_cast<int>(grid_private_password.size());
}
extern "C" void grid_set_password(const char* password) {
    if(!grid_private_password.empty()) OPENSSL_cleanse(grid_private_password.data(),grid_private_password.size());
    grid_private_password=password?password:"";
}

namespace {
thread_local std::string agility_error;
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void failed(const std::exception& exc) { agility_error=exc.what(); ERR_clear_error(); }
EVP_PKEY* load_sm2(const char* path, bool secret) {
    FILE* file=fopen(path,"rb"); check(file,"SM2_KEY_UNAVAILABLE");
    EVP_PKEY* result=secret?PEM_read_PrivateKey(file,nullptr,grid_password_callback,nullptr):PEM_read_PUBKEY(file,nullptr,nullptr,nullptr);
    fclose(file);
    if (!result || !EVP_PKEY_is_a(result,"SM2")) { EVP_PKEY_free(result); throw std::runtime_error("SM2_KEY_ALGORITHM_MISMATCH"); }
    return result;
}
}

extern "C" {
const char* grid_agility_error() { return agility_error.c_str(); }
int grid_sm3(const unsigned char* data, size_t length, unsigned char* out) {
    unsigned int written=0;
    try { check(EVP_Digest(data,length,out,&written,EVP_sm3(),nullptr)==1 && written==32,"SM3_FAILED"); return 1; }
    catch(const std::exception& exc) { failed(exc); return -1; }
}
int grid_sm2_sign(const char* path,const unsigned char* data,size_t length,const char* identity,unsigned char* out,size_t* out_length) {
    EVP_PKEY* key=nullptr; EVP_PKEY_CTX* context=nullptr; EVP_MD_CTX* digest=nullptr;
    try {
        check(identity && strlen(identity)>0 && strlen(identity)<=255,"SM2_ID_INVALID");
        key=load_sm2(path,true); context=EVP_PKEY_CTX_new(key,nullptr); digest=EVP_MD_CTX_new();
        check(context && digest,"SM2_CONTEXT_FAILED");
        check(EVP_PKEY_CTX_set1_id(context,identity,strlen(identity))==1,"SM2_ID_FAILED");
        EVP_MD_CTX_set_pkey_ctx(digest,context);
        check(EVP_DigestSignInit(digest,nullptr,EVP_sm3(),nullptr,key)==1 && EVP_DigestSign(digest,out,out_length,data,length)==1,"SM2_SIGN_FAILED");
        EVP_MD_CTX_free(digest); EVP_PKEY_CTX_free(context); EVP_PKEY_free(key); return 1;
    } catch(const std::exception& exc) { failed(exc); EVP_MD_CTX_free(digest); EVP_PKEY_CTX_free(context); EVP_PKEY_free(key); return -1; }
}
int grid_sm2_verify(const char* path,const unsigned char* data,size_t length,const char* identity,const unsigned char* signature,size_t signature_length) {
    EVP_PKEY* key=nullptr; EVP_PKEY_CTX* context=nullptr; EVP_MD_CTX* digest=nullptr;
    try {
        check(identity && strlen(identity)>0 && strlen(identity)<=255,"SM2_ID_INVALID");
        key=load_sm2(path,false); context=EVP_PKEY_CTX_new(key,nullptr); digest=EVP_MD_CTX_new();
        check(context && digest,"SM2_CONTEXT_FAILED");
        check(EVP_PKEY_CTX_set1_id(context,identity,strlen(identity))==1,"SM2_ID_FAILED");
        EVP_MD_CTX_set_pkey_ctx(digest,context);
        check(EVP_DigestVerifyInit(digest,nullptr,EVP_sm3(),nullptr,key)==1,"SM2_VERIFY_INIT_FAILED");
        int result=EVP_DigestVerify(digest,signature,signature_length,data,length);
        EVP_MD_CTX_free(digest); EVP_PKEY_CTX_free(context); EVP_PKEY_free(key); ERR_clear_error(); return result==1?1:0;
    } catch(const std::exception& exc) { failed(exc); EVP_MD_CTX_free(digest); EVP_PKEY_CTX_free(context); EVP_PKEY_free(key); return -1; }
}
// Fixed 128-bit key, 96-bit nonce and 128-bit tag. Callers own nonce uniqueness.
int grid_sm4_gcm(int encrypt,const unsigned char* key,const unsigned char* nonce,const unsigned char* aad,size_t aad_length,const unsigned char* input,size_t length,unsigned char* tag,unsigned char* out) {
    EVP_CIPHER* cipher=nullptr; EVP_CIPHER_CTX* context=nullptr; int count=0,tail=0;
    try {
        check(length<=16*1024*1024 && aad_length<=65536,"SM4_INPUT_TOO_LARGE");
        cipher=EVP_CIPHER_fetch(nullptr,"SM4-GCM",nullptr); context=EVP_CIPHER_CTX_new();
        check(cipher && context,"SM4_GCM_UNAVAILABLE");
        check(EVP_CipherInit_ex(context,cipher,nullptr,nullptr,nullptr,encrypt)==1 && EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,nullptr)==1 && EVP_CipherInit_ex(context,nullptr,nullptr,key,nonce,encrypt)==1,"SM4_INIT_FAILED");
        check(EVP_CipherUpdate(context,nullptr,&count,aad,static_cast<int>(aad_length))==1,"SM4_AAD_FAILED");
        check(EVP_CipherUpdate(context,out,&count,input,static_cast<int>(length))==1,"SM4_CIPHER_FAILED");
        if (!encrypt) check(EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_TAG,16,tag)==1,"SM4_TAG_FAILED");
        int valid=EVP_CipherFinal_ex(context,out+count,&tail);
        if (!valid) { if (length) OPENSSL_cleanse(out,length); EVP_CIPHER_CTX_free(context); EVP_CIPHER_free(cipher); ERR_clear_error(); return 0; }
        check(static_cast<size_t>(count+tail)==length,"SM4_LENGTH_FAILED");
        if (encrypt) check(EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_GET_TAG,16,tag)==1,"SM4_TAG_FAILED");
        EVP_CIPHER_CTX_free(context); EVP_CIPHER_free(cipher); return 1;
    } catch(const std::exception& exc) { failed(exc); if (length<=16*1024*1024 && length) OPENSSL_cleanse(out,length); EVP_CIPHER_CTX_free(context); EVP_CIPHER_free(cipher); return -1; }
}
}
