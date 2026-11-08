/* wolfCrypt benchmark configuration. Upstream licensing: GPLv3/commercial.
 * Leave CPU backend selection to wolfSSL and the ARMv6-M target macros. */
#ifndef M0C_BENCH_WOLFSSL_USER_SETTINGS_H
#define M0C_BENCH_WOLFSSL_USER_SETTINGS_H
#define WOLFCRYPT_ONLY
#define HAVE_CHACHA
#define HAVE_POLY1305           /* AEAD bench: wolfSSL Poly1305 C path */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_NO_SOCK
#define NO_ERROR_STRINGS
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_ASN
#define NO_CODING
#define NO_MD5
#define NO_SHA
#define NO_SHA256
#define NO_HMAC
#define NO_AES
#define NO_DES3
#define NO_RNG
#define NO_OLD_RNGNAME
#define WC_NO_RNG
#define NO_SIG_WRAPPER
#define NO_PWDBASED
#define NO_PKCS12
#define NO_STDIO_FILESYSTEM
#define NO_CTYPE_H
#define WOLFSSL_NO_ASSERT_H
#define NO_WOLFSSL_MEMORY
#define WOLFSSL_NO_MALLOC
#endif
