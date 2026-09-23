#include "jpsec_aes.h"

#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/sha3.h>

const uint8_t jpsec_test_key[JPSEC_AES_KEY_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
const uint8_t jpsec_test_iv[JPSEC_AES_IV_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* ---------------------------------------------------------------------- */
/* AES-256-CTR, backed by Mbed TLS (third_party/mbedtls)                  */
/* ---------------------------------------------------------------------- */

void jpsec_aes256_ctr_crypt(const uint8_t key[JPSEC_AES_KEY_BYTES],
                            const uint8_t iv[JPSEC_AES_IV_BYTES],
                            uint8_t *data,
                            size_t len) {
    mbedtls_aes_context ctx;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    size_t nc_off = 0;

    if (len == 0) {
        return;
    }

    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, 256) != 0) {
        mbedtls_aes_free(&ctx);
        return;
    }

    memcpy(nonce_counter, iv, 16);
    memset(stream_block, 0, sizeof(stream_block));
    /* In-place is explicitly supported: output may alias input. */
    (void)mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, nonce_counter, stream_block,
                                data, data);

    mbedtls_aes_free(&ctx);
}

int jpsec_derive_level_keys(const uint8_t key0[JPSEC_AES_KEY_BYTES],
                            int levels,
                            uint8_t *out) {
    size_t i;

    if (levels <= 0 || levels > JPSEC_MAX_LEVELS) {
        return 0;
    }
    memcpy(out, key0, JPSEC_AES_KEY_BYTES);
    for (i = 1; i < (size_t)levels; ++i) {
        (void)mbedtls_sha3(MBEDTLS_SHA3_256,
                           out + (i - 1) * JPSEC_AES_KEY_BYTES,
                           JPSEC_AES_KEY_BYTES,
                           out + i * JPSEC_AES_KEY_BYTES,
                           JPSEC_AES_KEY_BYTES);
    }
    return levels;
}

void jpsec_aes256_ctr_cascade(const uint8_t key0[JPSEC_AES_KEY_BYTES],
                              const uint8_t iv[JPSEC_AES_IV_BYTES],
                              int levels,
                              uint8_t *data,
                              size_t len) {
    uint8_t chain[JPSEC_MAX_LEVELS * JPSEC_AES_KEY_BYTES];
    size_t i;

    if (levels <= 0) {
        levels = 1;
    }
    if (levels > JPSEC_MAX_LEVELS) {
        levels = JPSEC_MAX_LEVELS;
    }
    (void)jpsec_derive_level_keys(key0, levels, chain);
    for (i = 0; i < (size_t)levels; ++i) {
        jpsec_aes256_ctr_crypt(chain + i * JPSEC_AES_KEY_BYTES, iv, data, len);
    }
}

int jpsec_aes256_kat_self_test(void) {
    /* FIPS-197 Appendix C.3 (AES-256 ECB). */
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t pt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    static const uint8_t ct[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };
    /* SHA3-256 of the empty input. */
    static const uint8_t sha3_empty[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    };
    mbedtls_aes_context ctx;
    uint8_t out[32];
    int ret;

    mbedtls_aes_init(&ctx);
    ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, pt, out);
    }
    mbedtls_aes_free(&ctx);
    if (ret != 0 || memcmp(out, ct, 16) != 0) {
        return 0;
    }

    ret = mbedtls_sha3(MBEDTLS_SHA3_256, NULL, 0, out, 32);
    if (ret != 0 || memcmp(out, sha3_empty, 32) != 0) {
        return 0;
    }

    return 1;
}

size_t jpsec_find_marker(const uint8_t *buf, size_t size,
                         uint8_t hi, uint8_t lo, size_t from) {
    size_t i;
    if (from >= size) {
        return size; /* not found */
    }
    for (i = from; i + 1 < size; ++i) {
        if (buf[i] == hi && buf[i + 1] == lo) {
            return i;
        }
    }
    return size;
}

int jpsec_parse_sec(const uint8_t *buf, size_t size, size_t sec_off,
                    uint32_t *zone_start, uint32_t *zone_size,
                    uint16_t *levels) {
    uint32_t lsec;
    if (size == 0 || sec_off > size || size - sec_off < 19) {
        return 0;
    }
    if (buf[sec_off] != 0xff || buf[sec_off + 1] != 0x65) {
        return 0;
    }
    /* Lsec includes the 2-byte length field itself. */
    lsec = ((uint32_t)buf[sec_off + 2] << 8) | buf[sec_off + 3];
    if (lsec < 19 || sec_off + 2 + lsec > size) {
        return 0;
    }
    if (buf[sec_off + 4] != 0x02 ||          /* registry-based form */
        buf[sec_off + 5] != 0x00 || buf[sec_off + 6] != 0x02 ||
        buf[sec_off + 7] != 0x01) {          /* AES-CTR tool, one zone */
        return 0;
    }
    if (zone_start) {
        *zone_start = ((uint32_t)buf[sec_off + JPSEC_SEC_Z_OFFSET    ] << 24) |
                      ((uint32_t)buf[sec_off + JPSEC_SEC_Z_OFFSET + 1] << 16) |
                      ((uint32_t)buf[sec_off + JPSEC_SEC_Z_OFFSET + 2] <<  8) |
                       (uint32_t)buf[sec_off + JPSEC_SEC_Z_OFFSET + 3];
    }
    if (zone_size) {
        *zone_size  = ((uint32_t)buf[sec_off + JPSEC_SEC_T_OFFSET    ] << 24) |
                      ((uint32_t)buf[sec_off + JPSEC_SEC_T_OFFSET + 1] << 16) |
                      ((uint32_t)buf[sec_off + JPSEC_SEC_T_OFFSET + 2] <<  8) |
                       (uint32_t)buf[sec_off + JPSEC_SEC_T_OFFSET + 3];
    }
    if (levels) {
        *levels = (uint16_t)(((uint32_t)buf[sec_off + JPSEC_SEC_LEVELS_OFFSET    ] << 8) |
                             (uint32_t)buf[sec_off + JPSEC_SEC_LEVELS_OFFSET + 1]);
    }
    return 1;
}

void jpsec_patch_sec(uint8_t *buf, size_t size, size_t sec_off,
                     uint32_t zone_start, uint32_t zone_size,
                     uint16_t levels) {
    if (size == 0 || sec_off > size || size - sec_off < 19) {
        return;
    }
    /* Z — 4-byte big-endian */
    buf[sec_off + JPSEC_SEC_Z_OFFSET    ] = (uint8_t)(zone_start >> 24);
    buf[sec_off + JPSEC_SEC_Z_OFFSET + 1] = (uint8_t)(zone_start >> 16);
    buf[sec_off + JPSEC_SEC_Z_OFFSET + 2] = (uint8_t)(zone_start >>  8);
    buf[sec_off + JPSEC_SEC_Z_OFFSET + 3] = (uint8_t)(zone_start       );
    /* T — 4-byte big-endian */
    buf[sec_off + JPSEC_SEC_T_OFFSET    ] = (uint8_t)(zone_size >> 24);
    buf[sec_off + JPSEC_SEC_T_OFFSET + 1] = (uint8_t)(zone_size >> 16);
    buf[sec_off + JPSEC_SEC_T_OFFSET + 2] = (uint8_t)(zone_size >>  8);
    buf[sec_off + JPSEC_SEC_T_OFFSET + 3] = (uint8_t)(zone_size       );
    /* Levels — 2-byte big-endian */
    buf[sec_off + JPSEC_SEC_LEVELS_OFFSET    ] = (uint8_t)(levels >> 8);
    buf[sec_off + JPSEC_SEC_LEVELS_OFFSET + 1] = (uint8_t)(levels       );
}