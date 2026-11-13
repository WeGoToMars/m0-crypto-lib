/* Benchmark build: the provider dispatch types prov/blake2.h names in declarations. */
#ifndef M0C_COMPAT_CRYPTO_EVP_H
#define M0C_COMPAT_CRYPTO_EVP_H
typedef int OSSL_FUNC_digest_get_ctx_params_fn(void *, void *);
typedef int OSSL_FUNC_digest_set_ctx_params_fn(void *, const void *);
typedef const void *OSSL_FUNC_digest_gettable_ctx_params_fn(void *, void *);
typedef const void *OSSL_FUNC_digest_settable_ctx_params_fn(void *, void *);
#endif
