/* Benchmark build: declarations for the Ed25519 code in curve25519.c. The benchmark
 * calls only the X25519 functions, so --gc-sections drops every caller of these. */
#ifndef M0C_COMPAT_EVP_H
#define M0C_COMPAT_EVP_H
#include <stddef.h>
#include <openssl/crypto.h>
#define SN_sha512 "SHA512"
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties);
void EVP_MD_free(EVP_MD *md);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, void *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size,
               const EVP_MD *type, void *impl);
#endif
