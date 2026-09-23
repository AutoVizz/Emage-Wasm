/*
 * Minimal Mbed TLS configuration for EmageWasm / JPSEC.
 *
 * This is a trimmed replacement for upstream's include/mbedtls/mbedtls_config.h
 * (Mbed TLS 3.6.7). It enables only what the JPSEC SEC marker needs:
 * the AES block cipher (256-bit keys) in CTR mode, and SHA3-256 for key
 * derivation. Everything else (TLS, X.509, PSA, other hashes/ciphers/modes)
 * stays disabled to keep the WASM modules small.
 */
#ifndef MBEDTLS_MBEDTLS_CONFIG_H
#define MBEDTLS_MBEDTLS_CONFIG_H

#define MBEDTLS_CONFIG_VERSION 0x03060000

/* AES block cipher, full key schedule (AES-256 for the protected zone). */
#define MBEDTLS_AES_C

/* CTR mode: provides mbedtls_aes_crypt_ctr(), the stream cipher for the zone. */
#define MBEDTLS_CIPHER_MODE_CTR

/* SHA3-256: derives the per-level keys from the previous level's key
 * (256-bit input -> 256-bit output), so no SHAKE variable-output is needed. */
#define MBEDTLS_SHA3_C

#endif /* MBEDTLS_MBEDTLS_CONFIG_H */
