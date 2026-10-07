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

int jpsec_key_lookup_tag(const uint8_t key[JPSEC_AES_KEY_BYTES],
                         const uint8_t iv[JPSEC_AES_IV_BYTES],
                         uint8_t out[JPSEC_MAC_ENTRY_BYTES]) {
    uint8_t input[JPSEC_AES_IV_BYTES + JPSEC_AES_KEY_BYTES];
    memcpy(input, iv, JPSEC_AES_IV_BYTES);
    memcpy(input + JPSEC_AES_IV_BYTES, key, JPSEC_AES_KEY_BYTES);
    return mbedtls_sha3(MBEDTLS_SHA3_256, input, sizeof(input), out,
                        JPSEC_MAC_ENTRY_BYTES) == 0;
}

int jpsec_derive_level_keys(const uint8_t key_top[JPSEC_AES_KEY_BYTES],
                            int levels,
                            uint8_t *out) {
    size_t i;

    if (levels <= 0 || levels > JPSEC_MAX_ZONES) {
        return 0;
    }
    memcpy(out + (size_t)(levels - 1) * JPSEC_AES_KEY_BYTES,
           key_top, JPSEC_AES_KEY_BYTES);
    for (i = (size_t)levels - 1; i > 0; --i) {
        if (mbedtls_sha3(MBEDTLS_SHA3_256,
                         out + i * JPSEC_AES_KEY_BYTES,
                         JPSEC_AES_KEY_BYTES,
                         out + (i - 1) * JPSEC_AES_KEY_BYTES,
                         JPSEC_AES_KEY_BYTES) != 0) {
            return 0;
        }
    }
    return levels;
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
/* SEC marker: IV, zone table, cumulative MAC table                        */
/* ---------------------------------------------------------------------- */

/* One level costs a 10-byte zone entry plus a 32-byte MAC. */
#define JPSEC_SEC_ENTRY_TOTAL (JPSEC_ZONE_ENTRY_BYTES + JPSEC_MAC_ENTRY_BYTES)

/* Fixed part of the opaque PID payload: E(2) + IV(16). */
#define JPSEC_PID_FIXED_BYTES 18

/* LPID for a marker carrying `e` levels. */
static uint32_t sec_lpid(int e) {
    return (uint32_t)JPSEC_PID_FIXED_BYTES +
           (uint32_t)e * (uint32_t)JPSEC_SEC_ENTRY_TOTAL;
}

/* Lsec counts itself and the tool block that follows it, but not the marker
 * code: the segment spans 2 + Lsec bytes from the marker code onwards. */
static uint32_t sec_lsec(int e) {
    return (uint32_t)(JPSEC_SEC_FIXED_BYTES - 2) + sec_lpid(e);
}

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

/* Counter block for the next encoded codestream, published for the same reason
 * as the zone count: the marker is written before the binding can reach the
 * payload.  Falls back to the test IV so a caller that never calls
 * jpsec_set_iv() still produces a parseable marker. */
static uint8_t g_iv[JPSEC_AES_IV_BYTES];
static int g_iv_set = 0;

void jpsec_set_iv(const uint8_t iv[JPSEC_AES_IV_BYTES]) {
    if (iv == NULL) {
        memset(g_iv, 0, sizeof(g_iv));
        g_iv_set = 0;
        return;
    }
    memcpy(g_iv, iv, JPSEC_AES_IV_BYTES);
    g_iv_set = 1;
}

const uint8_t *jpsec_get_iv(void) {
    return g_iv_set ? g_iv : jpsec_test_iv;
}

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v      );
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

int jpsec_level_mac(const uint8_t *prev,
                    const uint8_t key[JPSEC_AES_KEY_BYTES],
                    uint32_t level,
                    uint32_t z,
                    uint32_t t,
                    const uint8_t *plain,
                    size_t plain_len,
                    uint8_t out[JPSEC_MAC_ENTRY_BYTES]) {
    mbedtls_sha3_context ctx;
    /* prev(32) || key(32) || level(4) || Z(4) || T(4) */
    uint8_t head[32 + 32 + 4 + 4 + 4];
    int ret = -1;

    if (out == NULL || key == NULL) {
        return 0;
    }

    if (prev != NULL) {
        memcpy(head, prev, JPSEC_MAC_ENTRY_BYTES);
    } else {
        /* Level 0 chains from 32 zero bytes. */
        memset(head, 0, JPSEC_MAC_ENTRY_BYTES);
    }
    memcpy(head + 32, key, JPSEC_AES_KEY_BYTES);
    wr_be32(head + 64, level);
    wr_be32(head + 68, z);
    wr_be32(head + 72, t);

    mbedtls_sha3_init(&ctx);
    /* Streamed rather than concatenated: a finest-level zone is routinely tens
     * of kilobytes and there is no reason to copy it into a scratch buffer. */
    if (mbedtls_sha3_starts(&ctx, MBEDTLS_SHA3_256) == 0 &&
        mbedtls_sha3_update(&ctx, head, sizeof(head)) == 0 &&
        (plain_len == 0 || plain == NULL ||
         mbedtls_sha3_update(&ctx, plain, plain_len) == 0)) {
        ret = mbedtls_sha3_finish(&ctx, out, JPSEC_MAC_ENTRY_BYTES);
    }
    mbedtls_sha3_free(&ctx);
    return ret == 0 ? 1 : 0;
}

int jpsec_macs_equal(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    int i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; i < JPSEC_MAC_ENTRY_BYTES; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Byte offset of level i's MAC inside the marker. */
static size_t mac_offset(int count, int i) {
    return (size_t)JPSEC_SEC_ZONE_OFFSET +
           (size_t)count * (size_t)JPSEC_ZONE_ENTRY_BYTES +
           (size_t)i * (size_t)JPSEC_MAC_ENTRY_BYTES;
}

int jpsec_parse_sec_zones(const uint8_t *buf, size_t size, size_t sec_off,
                          uint32_t *starts, uint32_t *sizes, int max,
                          uint8_t *iv_out,
                          uint8_t *macs) {
    uint32_t lsec, lpid, psec;
    int e, i;

    if (buf == NULL || starts == NULL || sizes == NULL || max < 1) {
        return 0;
    }
    if (size == 0 || sec_off > size ||
        size - sec_off < (size_t)JPSEC_SEC_PID_OFFSET + JPSEC_PID_FIXED_BYTES) {
        return 0;
    }
    if (buf[sec_off] != 0xff || buf[sec_off + 1] != 0x65) {
        return 0;
    }
    /* Lsec counts the 2-byte length field itself, so the segment body after it
     * is Lsec - 2 bytes and the whole segment spans Lsec + 2 from the marker
     * code. */
    lsec = rd_be16(buf + sec_off + 2);
    if (lsec < (uint32_t)(JPSEC_SEC_FIXED_BYTES - 2) ||
        sec_off + 2 + lsec > size) {
        return 0;
    }
    /* Registered tool ids live in 0x00000000..0x7FFFFFFF and are assigned by
     * the JPSEC RA; anything in 0x80000000..0xEFFFFFFF is user-defined and
     * needs no registration. */
    if (rd_be32(buf + sec_off + JPSEC_SEC_ID_OFFSET) != JPSEC_TOOL_ID) {
        return 0;
    }
    /* Psec: bits 15-8 reserved and must be zero, bit 7 is FPSEC (either value
     * is legal), and the low 7 bits are the tool count, at least one. */
    psec = rd_be16(buf + sec_off + JPSEC_SEC_TSEC_OFFSET);
    if ((psec & JPSEC_PSEC_RESERVED_MASK) != 0 ||
        (psec & JPSEC_PSEC_TOOLS_MASK) < 1) {
        return 0;
    }
    /* A single tool block, and no standard Zone of Influence: the granularity
     * is carried by our own table inside the opaque PID. */
    if (rd_be16(buf + sec_off + JPSEC_SEC_LZOI_OFFSET) != 0) {
        return 0;
    }
    lpid = rd_be16(buf + sec_off + JPSEC_SEC_LPID_OFFSET);
    if (lsec != (uint32_t)(JPSEC_SEC_FIXED_BYTES - 2) + lpid ||
        sec_off + JPSEC_SEC_PID_OFFSET + lpid > size) {
        return 0;
    }
    e = rd_be16(buf + sec_off + JPSEC_SEC_E_OFFSET);
    if (e < 1 || e > JPSEC_MAX_ZONES || e > max) {
        return 0;
    }
    /* LPID must account for exactly the tables we are about to read. */
    if (lpid != sec_lpid(e)) {
        return 0;
    }
    for (i = 0; i < e; ++i) {
        const uint8_t *z = buf + sec_off + JPSEC_SEC_ZONE_OFFSET +
                           (size_t)i * (size_t)JPSEC_ZONE_ENTRY_BYTES;
        starts[i] = rd_be32(z + 2);
        sizes[i]  = rd_be32(z + 6);
    }
    if (iv_out != NULL) {
        memcpy(iv_out, buf + sec_off + JPSEC_SEC_IV_OFFSET, JPSEC_AES_IV_BYTES);
    }
    if (macs != NULL) {
        for (i = 0; i < e; ++i) {
            memcpy(macs + (size_t)i * (size_t)JPSEC_MAC_ENTRY_BYTES,
                   buf + sec_off + mac_offset(e, i), JPSEC_MAC_ENTRY_BYTES);
        }
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
        size - sec_off < JPSEC_SEC_PID_OFFSET + sec_lpid(count)) {
        return;
    }
    if (rd_be16(buf + sec_off + JPSEC_SEC_E_OFFSET) != (uint16_t)count) {
        return;
    }
    for (i = 0; i < count; ++i) {
        uint8_t *z = buf + sec_off + JPSEC_SEC_ZONE_OFFSET +
                     (size_t)i * (size_t)JPSEC_ZONE_ENTRY_BYTES;
        /* All ten bytes of the entry, so nothing written by the header
         * procedure survives. */
        z[0] = 0;
        z[1] = (uint8_t)i;   /* zone index == resolution level */
        wr_be32(z + 2, starts[i]);
        wr_be32(z + 6, sizes[i]);
    }
}

void jpsec_patch_sec_macs(uint8_t *buf, size_t size, size_t sec_off,
                          const uint8_t *macs, int count) {
    int i;

    if (buf == NULL || macs == NULL) {
        return;
    }
    if (count < 1 || count > JPSEC_MAX_ZONES) {
        return;
    }
    if (size == 0 || sec_off > size ||
        size - sec_off < JPSEC_SEC_PID_OFFSET + sec_lpid(count)) {
        return;
    }
    if (rd_be16(buf + sec_off + JPSEC_SEC_E_OFFSET) != (uint16_t)count) {
        return;
    }
    for (i = 0; i < count; ++i) {
        memcpy(buf + sec_off + mac_offset(count, i),
               macs + (size_t)i * (size_t)JPSEC_MAC_ENTRY_BYTES,
               JPSEC_MAC_ENTRY_BYTES);
    }
}
