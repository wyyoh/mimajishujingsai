/* Independent GmSSL test peer only. Never linked into the application. */
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int hex(const char *s, unsigned char *out, size_t capacity) {
    size_t n = strlen(s); if (n%2 || n/2>capacity) return -1;
    for(size_t i=0;i<n/2;i++) { unsigned int b; if(sscanf(s+2*i,"%2x",&b)!=1) return -1; out[i]=(unsigned char)b; }
    return (int)(n/2);
}
int main(int argc,char **argv) {
    unsigned char input[65536],output[65552],keybytes[16],nonce[12],aad[4096],tag[16];
    size_t n; if(argc<2) return 2;
    if(!strcmp(argv[1],"keygen")) {
        if(argc!=3) return 2;
        SM2_KEY key; FILE *public_file=fopen(argv[2],"wb"); if(!public_file) return 2;
        int ok=sm2_key_generate(&key)==1 && sm2_public_key_info_to_pem(&key,public_file)==1 && sm2_private_key_to_pem(&key,stdout)==1;
        fclose(public_file); memset(&key,0,sizeof key); return ok?0:2;
    }
    n=fread(input,1,sizeof input,stdin); if(ferror(stdin) || !feof(stdin)) return 2;
    if(!strcmp(argv[1],"sign")) {
        if(argc!=4) return 2;
        SM2_KEY key; SM2_SIGN_CTX ctx; size_t length=0;
        FILE *file=fopen(argv[2],"rb"); if(!file) return 2;
        int ok=sm2_private_key_from_pem(&key,file)==1; fclose(file);
        if(!ok || sm2_sign_init(&ctx,&key,argv[3],strlen(argv[3]))!=1 || sm2_sign_update(&ctx,input,n)!=1 || sm2_sign_finish(&ctx,output,&length)!=1) return 2;
        fwrite(output,1,length,stdout); memset(&key,0,sizeof key); memset(&ctx,0,sizeof ctx); return 0;
    }
    if(!strcmp(argv[1],"sm3")) { SM3_CTX ctx; sm3_init(&ctx); sm3_update(&ctx,input,n); sm3_finish(&ctx,output); fwrite(output,1,32,stdout); return 0; }
    if(argc<3 || hex(argv[2],keybytes,sizeof keybytes)!=16) return 2;
    SM4_KEY key; sm4_set_encrypt_key(&key,keybytes);
    if(!strcmp(argv[1],"block")) { if(n!=16) return 2; sm4_encrypt(&key,input,output); fwrite(output,1,16,stdout); return 0; }
    if(argc<5 || hex(argv[3],nonce,sizeof nonce)!=12) return 2;
    int aadlen=hex(argv[4],aad,sizeof aad); if(aadlen<0) return 2;
    if(!strcmp(argv[1],"gcm-encrypt")) {
        if(sm4_gcm_encrypt(&key,nonce,12,aad,(size_t)aadlen,input,n,output,16,tag)!=1) return 2;
        fwrite(output,1,n,stdout); fwrite(tag,1,16,stdout); return 0;
    }
    if(!strcmp(argv[1],"gcm-decrypt") && argc==6 && hex(argv[5],tag,sizeof tag)==16) {
        if(sm4_gcm_decrypt(&key,nonce,12,aad,(size_t)aadlen,input,n,tag,16,output)!=1) { memset(output,0,sizeof output); return 2; }
        fwrite(output,1,n,stdout); return 0;
    }
    return 2;
}
