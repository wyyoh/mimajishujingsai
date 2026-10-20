#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <chrono>
#include <cstring>
#include <string>
#include <sstream>
#include <stdexcept>
#include <dlfcn.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <cerrno>

int grid_password_callback(char*,int,int,void*);

namespace {
thread_local std::string last_error;
thread_local std::string info;
constexpr uint32_t MAX_FRAME = 16 * 1024 * 1024;
void require(bool ok, const char* msg) { if (!ok) throw std::runtime_error(msg); }
void fail(const std::exception& e) {
    last_error = e.what();
    unsigned long code = ERR_get_error();
    if(code) { char b[256]; ERR_error_string_n(code,b,sizeof b); last_error += std::string(": ")+b; }
}
EVP_PKEY* key(const char* path, bool priv) {
    FILE* f=fopen(path,"rb"); require(f,"key file unavailable");
    EVP_PKEY* k=priv?PEM_read_PrivateKey(f,nullptr,grid_password_callback,nullptr):PEM_read_PUBKEY(f,nullptr,nullptr,nullptr);
    fclose(f); require(k,"key parse failed"); return k;
}
void require_p256(EVP_PKEY* k){
    char name[80];size_t length=0;
    require(EVP_PKEY_is_a(k,"EC") && EVP_PKEY_get_utf8_string_param(k,OSSL_PKEY_PARAM_GROUP_NAME,name,sizeof name,&length)==1,"SIGNATURE_KEY_ALGORITHM_MISMATCH");
    require(strcmp(name,"prime256v1")==0 || strcmp(name,"P-256")==0 || strcmp(name,"secp256r1")==0,"SIGNATURE_KEY_ALGORITHM_MISMATCH");
}
struct Listener { SSL_CTX* ctx=nullptr; int fd=-1; std::string group,peer; ~Listener(){ if(fd>=0)close(fd); if(ctx)SSL_CTX_free(ctx); } };
struct Connection { SSL_CTX* ctx=nullptr; SSL* ssl=nullptr; int fd=-1; std::string evidence; ~Connection(){ if(ssl){SSL_free(ssl);} if(ctx)SSL_CTX_free(ctx); if(fd>=0)close(fd); } };
SSL_CTX* context(bool server,const char* ca,const char* cert,const char* pk,const char* group) {
    SSL_CTX* c=SSL_CTX_new(server?TLS_server_method():TLS_client_method()); require(c,"TLS context failed");
    try {
        require(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1,"TLS version configuration failed");
        require(SSL_CTX_set1_groups_list(c,group)==1,"TLS_GROUP_UNAVAILABLE");
        require(SSL_CTX_set_ciphersuites(c,"TLS_AES_256_GCM_SHA384")==1,"TLS cipher configuration failed");
        require(SSL_CTX_load_verify_locations(c,ca,nullptr)==1,"trust root unavailable");
        SSL_CTX_set_default_passwd_cb(c,grid_password_callback);
        require(SSL_CTX_use_certificate_chain_file(c,cert)==1 && SSL_CTX_use_PrivateKey_file(c,pk,SSL_FILETYPE_PEM)==1 && SSL_CTX_check_private_key(c)==1,"TLS credential configuration failed");
        SSL_CTX_set_verify(c,SSL_VERIFY_PEER|(server?SSL_VERIFY_FAIL_IF_NO_PEER_CERT:0),nullptr);
        SSL_CTX_set_session_cache_mode(c,SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(c,0); SSL_CTX_set_max_early_data(c,0);
        SSL_CTX_set_options(c,SSL_OP_NO_TICKET);
        return c;
    } catch(...) { SSL_CTX_free(c); throw; }
}
void timeout(int fd) { timeval tv{90,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv); }
void handshake(Connection* c,bool server,const std::string& group,const std::string& peer) {
    auto start=std::chrono::steady_clock::now();
    require((server?SSL_accept(c->ssl):SSL_connect(c->ssl))==1,"TLS_HANDSHAKE_FAILED");
    auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
    require(SSL_get_verify_result(c->ssl)==X509_V_OK,"TLS_PEER_CHAIN_INVALID");
    X509* certificate=SSL_get1_peer_certificate(c->ssl); require(certificate,"TLS_PEER_CERTIFICATE_MISSING");
    bool identity=X509_check_host(certificate,peer.c_str(),peer.size(),X509_CHECK_FLAG_NO_WILDCARDS,nullptr)==1;
    unsigned char fingerprint[EVP_MAX_MD_SIZE]; unsigned int fingerprint_size=0;
    require(X509_digest(certificate,EVP_sha256(),fingerprint,&fingerprint_size)==1 && fingerprint_size==32,"TLS_PEER_FINGERPRINT_FAILED");
    const char* digits="0123456789abcdef"; std::string peer_fingerprint;
    for(unsigned int i=0;i<fingerprint_size;++i){peer_fingerprint+=digits[fingerprint[i]>>4];peer_fingerprint+=digits[fingerprint[i]&15];}
    int cert_nid=X509_get_signature_nid(certificate); X509_free(certificate);
    require(identity,"TLS_PEER_IDENTITY_INVALID");
    const char* actual=SSL_get0_group_name(c->ssl); require(actual,"TLS_GROUP_UNKNOWN");
    std::string normalized=actual;
    if(normalized=="x25519")normalized="X25519";
    require(group==normalized,"TLS_GROUP_MISMATCH");
    require(SSL_version(c->ssl)==TLS1_3_VERSION,"TLS_VERSION_MISMATCH");
    require(!SSL_session_reused(c->ssl),"TLS_SESSION_RESUMPTION_FORBIDDEN");
    unsigned char random[16]; require(RAND_bytes(random,sizeof random)==1,"random source failed");
    const char* hex="0123456789abcdef"; std::string id; for(auto x:random){id+=hex[x>>4];id+=hex[x&15];}
    std::ostringstream o;
    o << "{\"connection_id\":\""<<id<<"\",\"tls_version\":\""<<SSL_get_version(c->ssl)<<"\",\"actual_group\":\""<<normalized<<"\",\"actual_group_raw\":\""<<actual
      <<"\",\"record_cipher\":\""<<SSL_get_cipher_name(c->ssl)<<"\",\"peer_verified\":true,\"peer_chain_verified\":true,\"peer_identity_verified\":true,\"peer_name\":\""<<peer
      <<"\",\"peer_certificate_sha256\":\""<<peer_fingerprint<<"\",\"certificate_signature_algorithm\":\""<<OBJ_nid2sn(cert_nid)<<"\",\"session_reused\":false,\"early_data_accepted\":false,\"handshake_ns\":"<<ns
      <<",\"handshake_bytes_read\":"<<BIO_number_read(SSL_get_rbio(c->ssl))<<",\"handshake_bytes_written\":"<<BIO_number_written(SSL_get_wbio(c->ssl))<<"}";
    c->evidence=o.str();
}
void write_all(SSL* s,const unsigned char* p,size_t n) { while(n){size_t done=0;require(SSL_write_ex(s,p,n,&done)==1 && done,"TLS_WRITE_FAILED");p+=done;n-=done;} }
void read_all(SSL* s,unsigned char* p,size_t n) { while(n){size_t done=0;require(SSL_read_ex(s,p,n,&done)==1 && done,"TLS_READ_FAILED");p+=done;n-=done;} }
}
extern "C" {
int grid_sandbox(const char* project,const char* runtime,const char* job,const char* role){
    int rules=-1;
    try{
        require(std::string(runtime).find(std::string(project)+"/")!=0,"runtime must be outside source tree for role isolation");
        int abi=syscall(SYS_landlock_create_ruleset,nullptr,0,LANDLOCK_CREATE_RULESET_VERSION);
        require(abi>=3,"LANDLOCK_ABI_3_REQUIRED");
        uint64_t handled=(1ULL<<15)-1;
        landlock_ruleset_attr attr{};attr.handled_access_fs=handled;
        rules=syscall(SYS_landlock_create_ruleset,&attr,sizeof attr,0);require(rules>=0,"LANDLOCK_CREATE_FAILED");
        uint64_t read=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR|LANDLOCK_ACCESS_FS_EXECUTE;
        auto allow=[&](const std::string& path,uint64_t access,bool optional=false){
            int fd=open(path.c_str(),O_PATH|O_CLOEXEC);
            if(fd<0){require(optional,"LANDLOCK_PATH_UNAVAILABLE");return;}
            struct stat st{};fstat(fd,&st);
            if(!S_ISDIR(st.st_mode))access &= LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_WRITE_FILE|LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_TRUNCATE;
            landlock_path_beneath_attr p{};p.parent_fd=fd;p.allowed_access=access;
            int rc=syscall(SYS_landlock_add_rule,rules,LANDLOCK_RULE_PATH_BENEATH,&p,0);close(fd);require(rc==0,"LANDLOCK_ADD_RULE_FAILED");
        };
        for(const char* p:{"/usr","/lib","/lib64","/etc/ssl","/etc/ld.so.cache","/dev/urandom","/dev/random"})allow(p,read,true);
        allow("/dev/null",read|LANDLOCK_ACCESS_FS_WRITE_FILE,true);
        allow(project,read);
        allow(std::string(runtime)+"/public",read);
        allow(std::string(runtime)+"/"+role,read);
        allow(std::string(job)+"/"+role,handled);
        allow(std::string(job)+"/events",handled);
        require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"NO_NEW_PRIVS_FAILED");
        require(prctl(PR_SET_DUMPABLE,0)==0,"DUMPABLE_RESTRICTION_FAILED");
        require(syscall(SYS_landlock_restrict_self,rules,0)==0,"LANDLOCK_RESTRICT_FAILED");close(rules);return abi;
    }catch(const std::exception& e){fail(e);if(rules>=0)close(rules);return -1;}
}
const char* grid_error(){return last_error.c_str();}
const char* grid_library_info(){
    Dl_info d{}; dladdr(reinterpret_cast<void*>(SSL_new),&d);
    info=std::string("{\"openssl\":\"")+OpenSSL_version(OPENSSL_VERSION)+"\",\"ssl_path\":\""+(d.dli_fname?d.dli_fname:"")+"\"}"; return info.c_str();
}
int grid_sign(const char* path,int pq,const unsigned char* data,size_t n,const char* domain,unsigned char* out,size_t* out_len) {
    EVP_PKEY* k=nullptr; EVP_MD_CTX* m=nullptr; EVP_PKEY_CTX* p=nullptr; EVP_SIGNATURE* sig=nullptr;
    try {
        k=key(path,true);
        if(pq) {
            require(EVP_PKEY_is_a(k,"ML-DSA-65"),"SIGNATURE_KEY_ALGORITHM_MISMATCH");
            p=EVP_PKEY_CTX_new_from_pkey(nullptr,k,nullptr); require(p,"signature context failed");
            sig=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr); require(sig,"ML-DSA unavailable");
            OSSL_PARAM params[]={OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,const_cast<char*>(domain),strlen(domain)),OSSL_PARAM_construct_end()};
            require(EVP_PKEY_sign_message_init(p,sig,params)==1,"ML-DSA initialization failed");
            require(EVP_PKEY_sign(p,out,out_len,data,n)==1,"ML-DSA signing failed");
        } else {
            require_p256(k);
            m=EVP_MD_CTX_new(); require(m,"digest context failed");
            require(EVP_DigestSignInit(m,nullptr,EVP_sha256(),nullptr,k)==1 && EVP_DigestSign(m,out,out_len,data,n)==1,"ECDSA signing failed");
        }
        EVP_SIGNATURE_free(sig); EVP_PKEY_CTX_free(p); EVP_MD_CTX_free(m); EVP_PKEY_free(k); return 1;
    } catch(const std::exception& e) {fail(e);EVP_SIGNATURE_free(sig);EVP_PKEY_CTX_free(p);EVP_MD_CTX_free(m);EVP_PKEY_free(k);return -1;}
}
int grid_verify(const char* path,int pq,const unsigned char* data,size_t n,const char* domain,const unsigned char* signature,size_t sn) {
    EVP_PKEY* k=nullptr; EVP_MD_CTX* m=nullptr; EVP_PKEY_CTX* p=nullptr; EVP_SIGNATURE* sig=nullptr;
    try {
        k=key(path,false); int result=0;
        if(pq){
            require(EVP_PKEY_is_a(k,"ML-DSA-65"),"SIGNATURE_KEY_ALGORITHM_MISMATCH");
            p=EVP_PKEY_CTX_new_from_pkey(nullptr,k,nullptr); require(p,"signature context failed");
            sig=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr); require(sig,"ML-DSA unavailable");
            OSSL_PARAM params[]={OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,const_cast<char*>(domain),strlen(domain)),OSSL_PARAM_construct_end()};
            require(EVP_PKEY_verify_message_init(p,sig,params)==1,"ML-DSA initialization failed");
            result=EVP_PKEY_verify(p,signature,sn,data,n);
        } else {
            require_p256(k);
            m=EVP_MD_CTX_new(); require(m,"digest context failed");
            require(EVP_DigestVerifyInit(m,nullptr,EVP_sha256(),nullptr,k)==1,"ECDSA initialization failed");
            result=EVP_DigestVerify(m,signature,sn,data,n);
        }
        EVP_SIGNATURE_free(sig);EVP_PKEY_CTX_free(p);EVP_MD_CTX_free(m);EVP_PKEY_free(k);ERR_clear_error();return result==1?1:0;
    }catch(const std::exception& e){fail(e);EVP_SIGNATURE_free(sig);EVP_PKEY_CTX_free(p);EVP_MD_CTX_free(m);EVP_PKEY_free(k);return -1;}
}
void* grid_tls_listen(const char* host,int port,const char* ca,const char* cert,const char* pk,const char* group,const char* peer){
    auto l=new Listener();
    try {l->ctx=context(true,ca,cert,pk,group);l->group=group;l->peer=peer;
        l->fd=socket(AF_INET,SOCK_STREAM,0);require(l->fd>=0,"socket failed");int one=1;setsockopt(l->fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
        sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);require(inet_pton(AF_INET,host,&a.sin_addr)==1,"invalid listen address");
        require(bind(l->fd,reinterpret_cast<sockaddr*>(&a),sizeof a)==0 && listen(l->fd,16)==0,"listener bind failed");return l;
    }catch(const std::exception& e){fail(e);delete l;return nullptr;}
}
void* grid_tls_accept(void* ptr){auto l=static_cast<Listener*>(ptr);auto c=new Connection();
    try{c->fd=accept(l->fd,nullptr,nullptr);require(c->fd>=0,"accept failed");timeout(c->fd);c->ssl=SSL_new(l->ctx);require(c->ssl,"SSL allocation failed");require(SSL_set_fd(c->ssl,c->fd)==1,"SSL socket failed");handshake(c,true,l->group,l->peer);return c;}
    catch(const std::exception& e){fail(e);delete c;return nullptr;}
}
void* grid_tls_connect(const char* host,int port,const char* ca,const char* cert,const char* pk,const char* group,const char* peer){auto c=new Connection();
    try{c->ctx=context(false,ca,cert,pk,group);c->fd=socket(AF_INET,SOCK_STREAM,0);require(c->fd>=0,"socket failed");timeout(c->fd);
        sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);require(inet_pton(AF_INET,host,&a.sin_addr)==1,"invalid connect address");
        require(connect(c->fd,reinterpret_cast<sockaddr*>(&a),sizeof a)==0,"TLS_CONNECT_FAILED");
        c->ssl=SSL_new(c->ctx);require(c->ssl,"SSL allocation failed");SSL_set_tlsext_host_name(c->ssl,peer);require(SSL_set1_host(c->ssl,peer)==1 && SSL_set_fd(c->ssl,c->fd)==1,"TLS identity configuration failed");
        handshake(c,false,group,peer);return c;
    }catch(const std::exception& e){fail(e);delete c;return nullptr;}
}
const char* grid_tls_evidence(void* ptr){return static_cast<Connection*>(ptr)->evidence.c_str();}
int grid_tls_export(void* ptr,const char* label,unsigned char* out,size_t length){try{require(ptr && label && length==16,"TLS_EXPORT_ARGUMENT_INVALID");auto c=static_cast<Connection*>(ptr);require(SSL_export_keying_material(c->ssl,out,length,label,strlen(label),nullptr,0,0)==1,"TLS_EXPORT_FAILED");return 1;}catch(const std::exception& e){fail(e);return -1;}}
const char* grid_tls_traffic(void* ptr){auto c=static_cast<Connection*>(ptr);info=std::string("{\"sent\":")+std::to_string(BIO_number_written(SSL_get_wbio(c->ssl)))+",\"received\":"+std::to_string(BIO_number_read(SSL_get_rbio(c->ssl)))+"}";return info.c_str();}
int grid_tls_send(void* ptr,const unsigned char* p,size_t n){try{require(n>0&&n<=MAX_FRAME,"FRAME_SIZE_INVALID");uint32_t len=htonl(n);auto s=static_cast<Connection*>(ptr)->ssl;write_all(s,reinterpret_cast<unsigned char*>(&len),4);write_all(s,p,n);return 1;}catch(const std::exception& e){fail(e);return -1;}}
int grid_tls_recv(void* ptr,unsigned char* p,size_t cap){try{auto s=static_cast<Connection*>(ptr)->ssl;uint32_t len;read_all(s,reinterpret_cast<unsigned char*>(&len),4);len=ntohl(len);require(len>0&&len<=MAX_FRAME&&len<=cap,"FRAME_SIZE_INVALID");read_all(s,p,len);return len;}catch(const std::exception& e){fail(e);return -1;}}
void grid_tls_close(void* ptr){delete static_cast<Connection*>(ptr);}
void grid_tls_listener_close(void* ptr){delete static_cast<Listener*>(ptr);}
}
