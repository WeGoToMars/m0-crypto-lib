/* Forced include for the BLAKE2 reference and its wrappers: wolfSSL's blake2s.c exports
 * the same function names, so the reference ones get a ref_ prefix in this image. */
#define blake2s_init ref_blake2s_init
#define blake2s_init_key ref_blake2s_init_key
#define blake2s_init_param ref_blake2s_init_param
#define blake2s_update ref_blake2s_update
#define blake2s_final ref_blake2s_final
#define blake2s ref_blake2s
