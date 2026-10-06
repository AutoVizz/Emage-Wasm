#ifndef JPSEC_AES_H
#define JPSEC_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * AES-256-CTR + JPSEC SEC marker helpers (test / dummy scheme).
 *
 * Granular progressive keys
 * -------------------------
 * The codestream payload (everything after SOD) is split into one protected
 * zone per DWT resolution level.  Level 0 is the coarsest (1 pixel for a fully
 * decomposed image) and level E-1 the finest.  Each zone is encrypted exactly
 * once, with its own key drawn from a hash chain over the caller's master key:
 *
 *     K0 = master key
 *     K1 = SHA3-256(K0), K2 = SHA3-256(K1), ...
 *
 * Because OpenJPEG reconstructs a reduced image from the coarse levels only,
 * supplying K0..Kr is enough to decode at reduction r: every level above r
 * stays encrypted and is never touched.  Key count is therefore the access
 * grant, mirroring `reduction` on the decode side.
 *
 * Marker layout (registry-based form, ISO/IEC 15444-8 / ITU-T T.807 5.5).
 * Offsets are relative to the start of the marker; the segment is variable
 * length because it carries one zone entry per resolution level:
 *
 *   Byte offset  Field         Notes
 *   0..1         marker        FF 65
 *   2..3         Lsec          segment length, including itself: 7 + 10*E
 *   4            Form          0x02 (registry-based)
 *   5..6         T.sec         0x0002 (private AES-CTR tool)
 *   7            E             number of protected zones (= DWT levels)
 *   8            L             length of zone info: 2 + 10*E
 *   9..          zone entries, 10 bytes each:
 *                  +0..1       zone index (resolution level, 0 = coarsest)
 *                  +2..5       Z   start offset, relative to the first byte
 *                                  of the packet payload (i.e. SOD + 2)
 *                  +6..9       T   size in bytes
 *
 * Z is deliberately relative to the payload rather than absolute: the serving
 * layer rebuilds the main header while dropping TLM/PLM/PLT/PPM segments,
 * which shifts every absolute offset.  Relative offsets survive that.
 *
 * The marker never carries key material.
 */
#define JPSEC_SEC_FORM_OFFSET    4
#define JPSEC_SEC_TSEC_OFFSET    5
#define JPSEC_SEC_E_OFFSET       7
#define JPSEC_SEC_L_OFFSET       8
#define JPSEC_SEC_ZONE_OFFSET    9       /* first zone entry */
#define JPSEC_ZONE_ENTRY_BYTES   10      /* 2 index + 4 Z + 4 T */
#define JPSEC_MAX_ZONES          64
#define JPSEC_AES_KEY_BYTES      32      /* AES-256 */
#define JPSEC_AES_IV_BYTES       16

/* Fixed test key and counter block, used as the default when callers do not
 * supply their own. Not embedded in the output file. */
extern const uint8_t jpsec_test_key[JPSEC_AES_KEY_BYTES];
extern const uint8_t jpsec_test_iv[JPSEC_AES_IV_BYTES];

/* Number of zone entries opj_j2k_write_sec() should reserve.  The encoder
 * binding sets this before opj_setup_encoder() because the marker is written
 * as a header procedure, before per-tile parameters exist.  Clamped to
 * 1..JPSEC_MAX_ZONES; defaults to 1. */
void jpsec_set_zone_count(int zones);
int  jpsec_get_zone_count(void);

/* AES-256-CTR in place (NIST SP 800-38A, key=256 bits).  Encryption and
 * decryption are the same operation. */
void jpsec_aes256_ctr_crypt(const uint8_t key[JPSEC_AES_KEY_BYTES],
                            const uint8_t iv[JPSEC_AES_IV_BYTES],
                            uint8_t *data,
                            size_t   len);

/*
 * Derive the granular key chain from `key0`: out[0] = key0 and
 * out[i] = SHA3-256(out[i-1]).  `out` must hold count * 32 bytes.
 * Returns the number of keys written, or 0 if count is out of range.
 */
int jpsec_derive_level_keys(const uint8_t key0[JPSEC_AES_KEY_BYTES],
                            int count,
                            uint8_t *out);

/* Scan `buf[0..size)` for an FF <lo> marker starting at `from`. */
size_t jpsec_find_marker(const uint8_t *buf, size_t size,
                         uint8_t hi, uint8_t lo, size_t from);

/*
 * Parse the zone table of a structurally valid SEC segment at buf[sec_off].
 * On success returns the zone count (>= 1) and fills up to `max` entries of
 * `starts` (payload-relative offsets) and `sizes`; returns 0 on any structural
 * failure, in which case the output arrays are left untouched.
 */
int jpsec_parse_sec_zones(const uint8_t *buf, size_t size, size_t sec_off,
                          uint32_t *starts, uint32_t *sizes, int max);

/*
 * Overwrite the zone table of an already-written SEC segment.  `count` must
 * match the count reserved by jpsec_set_zone_count(), otherwise this is a
 * no-op and the marker is left untouched.
 */
void jpsec_patch_sec_zones(uint8_t *buf, size_t size, size_t sec_off,
                           const uint32_t *starts, const uint32_t *sizes,
                           int count);

#ifdef __cplusplus
}
#endif

#endif /* JPSEC_AES_H */
