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

    if (levels <= 0 || levels > JPSEC_MAX_ZONES) {
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

/* ---------------------------------------------------------------------- */
/* SEC zone table                                                         */
/* ---------------------------------------------------------------------- */

/* Zone count reserved by the encoder for the next encoded codestream.  The
 * marker is emitted as a header procedure, so the binding cannot reach the
 * per-tile resolution count from inside OpenJPEG and publishes it here
 * instead. */
static int g_zone_count = 1;

void jpsec_set_zone_count(int zones) {
    if (zones < 1) {
        zones = 1;
    }
    if (zones > JPSEC_MAX_ZONES) {
        zones = JPSEC_MAX_ZONES;
    }
    g_zone_count = zones;
}

int jpsec_get_zone_count(void) {
    return g_zone_count;
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

int jpsec_parse_sec_zones(const uint8_t *buf, size_t size, size_t sec_off,
                          uint32_t *starts, uint32_t *sizes, int max) {
    uint32_t lsec, l;
    int e, i;

    if (buf == NULL || starts == NULL || sizes == NULL || max < 1) {
        return 0;
    }
    if (size == 0 || sec_off > size || size - sec_off < 9) {
        return 0;
    }
    if (buf[sec_off] != 0xff || buf[sec_off + 1] != 0x65) {
        return 0;
    }
    /* Lsec counts the 2-byte length field itself, so the segment body after
     * it is Lsec - 2 bytes and the whole segment spans Lsec + 2 from the
     * marker code. */
    lsec = ((uint32_t)buf[sec_off + 2] << 8) | buf[sec_off + 3];
    if (lsec < 9 || sec_off + 2 + lsec > size) {
        return 0;
    }
    if (buf[sec_off + JPSEC_SEC_FORM_OFFSET] != 0x02 ||   /* registry-based */
        buf[sec_off + JPSEC_SEC_TSEC_OFFSET] != 0x00 ||
        buf[sec_off + JPSEC_SEC_TSEC_OFFSET + 1] != 0x02) {
        return 0;
    }
    e = buf[sec_off + JPSEC_SEC_E_OFFSET];
    l = buf[sec_off + JPSEC_SEC_L_OFFSET];
    if (e < 1 || e > JPSEC_MAX_ZONES || e > max) {
        return 0;
    }
    /* L must account for exactly the zone entries we are about to read. */
    if (l != 2u + (uint32_t)e * JPSEC_ZONE_ENTRY_BYTES) {
        return 0;
    }
    /* Lsec spans the length field, Form, T.sec, E and L, then the zone info:
     * 2 + 1 + 2 + 1 + 1 = 7 bytes of header, and L already contains the
     * per-entry 2-byte index that is part of the 10-byte entry. */
    if (lsec != 5u + l) {
        return 0;
    }
    for (i = 0; i < e; ++i) {
        const uint8_t *z = buf + sec_off + JPSEC_SEC_ZONE_OFFSET +
                           (size_t)i * JPSEC_ZONE_ENTRY_BYTES;
        starts[i] = rd_be32(z + 2);
        sizes[i]  = rd_be32(z + 6);
    }
    return e;
}

void jpsec_patch_sec_zones(uint8_t *buf, size_t size, size_t sec_off,
                           const uint32_t *starts, const uint32_t *sizes,
                           int count) {
    int i;

    if (buf == NULL || starts == NULL || sizes == NULL) {
        return;
    }
    if (count < 1 || count > JPSEC_MAX_ZONES) {
        return;
    }
    /* Only rewrite a table we can actually see in the buffer. */
    if (size == 0 || sec_off > size ||
        size - sec_off < (size_t)9 + (size_t)count * JPSEC_ZONE_ENTRY_BYTES) {
        return;
    }
    if (buf[sec_off + JPSEC_SEC_E_OFFSET] != (uint8_t)count) {
        return;
    }
    for (i = 0; i < count; ++i) {
        uint8_t *z = buf + sec_off + JPSEC_SEC_ZONE_OFFSET +
                     (size_t)i * JPSEC_ZONE_ENTRY_BYTES;
        z[0] = 0;
        z[1] = (uint8_t)i;   /* zone index == resolution level */
        wr_be32(z + 2, starts[i]);
        wr_be32(z + 6, sizes[i]);
    }
}
