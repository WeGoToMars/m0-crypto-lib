/* SPDX-License-Identifier: MIT
 * One complete-buffer operation per wrapper; all setup is included. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "m0crypto/chacha20poly1305.h"
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include "monocypher.h"
#include "crypto/chacha.h"
#define POLY1305 OSSL_POLY1305
#include "crypto/poly1305.h"
#undef POLY1305

typedef struct {
    uint8_t *out;
    const uint8_t *in;
    size_t len;
    const uint8_t *key, *nonce, *aad;
    size_t aad_len;
    uint8_t *tag;
    int status;
} Job;

void run_m0c_chacha(Job *j) {
    j->status = m0c_chacha20_xor(j->out,j->in,j->len,j->key,j->nonce,1);
}
void run_wolf_chacha(Job *j) {
    ChaCha c;
    int r=wc_Chacha_SetKey(&c,j->key,32);
    if (!r) r=wc_Chacha_SetIV(&c,j->nonce,1);
    if (!r) r=wc_Chacha_Process(&c,j->out,j->in,j->len);
    j->status=r;
}
void run_mono_chacha(Job *j) {
    crypto_chacha20_ietf(j->out,j->in,j->len,j->key,j->nonce,1);
    j->status=0;
}
static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void ossl_chacha(Job *j, uint8_t *out, const uint8_t *in, size_t n, uint32_t ctr) {
    unsigned int k[8],iv[4];
    for (unsigned i=0;i<8;i++) k[i]=load32(j->key+4*i);
    iv[0]=ctr;
    for (unsigned i=0;i<3;i++) iv[i+1]=load32(j->nonce+4*i);
    ChaCha20_ctr32(out,in,n,k,iv);
}
void run_ossl_chacha(Job *j) {
    ossl_chacha(j,j->out,j->in,j->len,1); j->status=0;
}
void run_m0c_encrypt(Job *j) {
    j->status=m0c_chacha20poly1305_encrypt(j->out,j->tag,j->in,j->len,j->aad,j->aad_len,j->key,j->nonce);
}
void run_m0c_decrypt(Job *j) {
    j->status=m0c_chacha20poly1305_decrypt(j->out,j->tag,j->in,j->len,j->aad,j->aad_len,j->key,j->nonce);
}
void run_wolf_encrypt(Job *j) {
    j->status=wc_ChaCha20Poly1305_Encrypt(j->key,j->nonce,j->aad,j->aad_len,j->in,j->len,j->out,j->tag);
}
void run_wolf_decrypt(Job *j) {
    j->status=wc_ChaCha20Poly1305_Decrypt(j->key,j->nonce,j->aad,j->aad_len,j->in,j->len,j->tag,j->out);
}
void run_mono_encrypt(Job *j) {
    crypto_aead_ctx c;
    crypto_aead_init_ietf(&c,j->key,j->nonce);
    crypto_aead_write(&c,j->out,j->tag,j->aad,j->aad_len,j->in,j->len);
    crypto_wipe(&c,sizeof c); j->status=0;
}
void run_mono_decrypt(Job *j) {
    crypto_aead_ctx c;
    crypto_aead_init_ietf(&c,j->key,j->nonce);
    j->status=crypto_aead_read(&c,j->out,j->tag,j->aad,j->aad_len,j->in,j->len);
    crypto_wipe(&c,sizeof c);
}
/* OpenSSL's portable kernels with benchmark-owned RFC 8439 composition.
 * This measures neither EVP dispatch nor a full OpenSSL installation. */
static void ossl_tag(Job *j,const uint8_t *ct,uint8_t tag[16]) {
    uint8_t block[64]={0},lengths[16]={0};
    static const uint8_t zero[16]={0};
    OSSL_POLY1305 p;
    ossl_chacha(j,block,block,64,0);
    Poly1305_Init(&p,block);
    Poly1305_Update(&p,j->aad,j->aad_len);
    Poly1305_Update(&p,zero,(16-j->aad_len%16)%16);
    Poly1305_Update(&p,ct,j->len);
    Poly1305_Update(&p,zero,(16-j->len%16)%16);
    for(unsigned i=0;i<4;i++) {
        lengths[i]=(uint8_t)(j->aad_len>>(8*i));
        lengths[8+i]=(uint8_t)(j->len>>(8*i));
    }
    Poly1305_Update(&p,lengths,16);
    Poly1305_Final(&p,tag);
    crypto_wipe(block,sizeof block);
}
void run_ossl_encrypt(Job *j) {
    ossl_chacha(j,j->out,j->in,j->len,1);
    ossl_tag(j,j->out,j->tag); j->status=0;
}
void run_ossl_decrypt(Job *j) {
    uint8_t tag[16]; uint32_t diff=0;
    ossl_tag(j,j->in,tag);
    for(unsigned i=0;i<16;i++) diff|=tag[i]^j->tag[i];
    j->status=diff?-1:0;
    if (!diff) ossl_chacha(j,j->out,j->in,j->len,1);
    crypto_wipe(tag,sizeof tag);
}
