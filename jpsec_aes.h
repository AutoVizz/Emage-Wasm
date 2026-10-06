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
 * Offsets are relative to the start of the marker:
 *
 *   Byte offset  Field         Notes
 *   0..1         marker        FF 65
 *   2..3         Lsec          segment length, including itself: 16 + LPID
 *   4..5         Zsec          index of this SEC marker; 0 for the first
 *   6..7         Psec          bits 15-8 reserved (0), bit 7 = FPSEC,
 *                              bits 6-0 = Ntools
 *   8..11        ID            32-bit tool id, 0x80000002 (user-defined range)
 *   12..13       LZOI          length of the Zone of Influence; 0 to skip it
 *   14..15       LPID          length of the tool-specific parameters
 *   16..         PID           opaque to the SEC parser; our payload:
 *
 *      +0..1     E             number of protected zones (= DWT levels)
 *      +2..17    IV            the 16-byte counter block used for every level
 *      +18..     zone entries, 10 bytes each:
 *                   +0..1      zone index (resolution level, 0 = coarsest)
 *                   +2..5      Z   start offset, relative to the first byte
 *                                  of the packet payload (i.e. SOD + 2)
 *                   +6..9      T   size in bytes
 *      +18+10E.. MAC table, 32 bytes each: the cumulative SHA3-256 tag for the
 *                  level, covering every zone from 0 up to this one.
 *
 * The tool id sits in the user-defined range 0x80000000..0xEFFFFFFF, not the
 * registered 0x00000000..0x7FFFFFFF range, so no central registration is needed
 * and we do not collide with a normative tool.
 *
 * FPSEC is set. The flag asks a transcoding or rewriting process that does not
 * understand the tool to forward this segment as-is; clearing it would let such
 * a process discard or alter the zone table and MACs, which is precisely what
 * the serving layer must not do to a window it does not decrypt.
 *
 * Z is deliberately relative to the payload rather than absolute: the serving
 * layer rebuilds the main header while dropping TLM/PLM/PLT/PPM segments, which
 * shifts every absolute offset.  Relative offsets survive that, which is also
 * why the MACs -- which cover Z, T and the zone plaintext -- stay valid across a
 * server-served window.  The IV and MAC tables live inside the marker itself, so
 * the serving layer copies them along with every other main-header segment.
 *
 * LZOI is 0: the standard Zone of Influence is skipped and the granularity is
 * expressed by our own table inside the opaque PID payload instead, which the
 * standard permits for a user-defined tool.
 *
 * The marker never carries key material.  The IV is not secret; publishing it
 * here is what lets a reader decrypt a served window without having to be
 * handed the counter block out of band.
 */
#define JPSEC_SEC_FORM_OFFSET    4      /* Zsec, retained name for the index */
#define JPSEC_SEC_TSEC_OFFSET    6      /* Psec, retained name for the flags  */
#define JPSEC_SEC_ID_OFFSET      8      /* 32-bit tool id                    */
#define JPSEC_SEC_LZOI_OFFSET    12
#define JPSEC_SEC_LPID_OFFSET    14
#define JPSEC_SEC_PID_OFFSET     16
#define JPSEC_SEC_E_OFFSET       16     /* E is the first PID field          */
#define JPSEC_SEC_IV_OFFSET      18     /* inside the PID payload            */
#define JPSEC_SEC_ZONE_OFFSET    34     /* first zone entry, absolute        */
#define JPSEC_SEC_FIXED_BYTES    16     /* marker + length + tool block head */
#define JPSEC_ZONE_ENTRY_BYTES   10     /* 2 index + 4 Z + 4 T               */
#define JPSEC_MAC_ENTRY_BYTES    32     /* SHA3-256                          */
#define JPSEC_MAX_ZONES          64
#define JPSEC_AES_KEY_BYTES      32     /* AES-256                           */
#define JPSEC_AES_IV_BYTES       16

/* User-defined tool id (0x80000000..0xEFFFFFFF). */
#define JPSEC_TOOL_ID            0x80000002u
#define JPSEC_PSEC_FPSEC         0x0080u
#define JPSEC_PSEC_TOOLS_MASK    0x007Fu
#define JPSEC_PSEC_RESERVED_MASK 0xFF00u   /* bits 15-8, must be zero */

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

/* Counter block written into the marker, published by the encoder binding for
 * the same reason as the zone count: the marker is written before the binding
 * can reach the payload.  Copied, so the caller's buffer need not outlive the
 * call. */
void jpsec_set_iv(const uint8_t iv[JPSEC_AES_IV_BYTES]);
const uint8_t *jpsec_get_iv(void);

/* Cumulative MAC for one resolution level:
 *
 *     MAC[-1] = 32 zero bytes
 *     MAC[r]  = SHA3-256( MAC[r-1] || K_r || r || Z_r || T_r || zone plaintext )
 *
 * `prev` is NULL for level 0.  Chaining means a reader holding K0..Ka can
 * recompute the chain up to level a and compare against the stored MAC[a],
 * which transitively authenticates every coarser level as well.  Binding K_r
 * in means a party without the key cannot forge the tag.  Z and T are bound in
 * so the tag also pins each zone's position and extent, and both are
 * payload-relative so they are unchanged by a server-served window.
 *
 * Writes JPSEC_MAC_ENTRY_BYTES to `out`.  Returns 1 on success, 0 if the
 * SHA3 call fails.
 */
int jpsec_level_mac(const uint8_t *prev,
                    const uint8_t key[JPSEC_AES_KEY_BYTES],
                    uint32_t level,
                    uint32_t z,
                    uint32_t t,
                    const uint8_t *plain,
                    size_t plain_len,
                    uint8_t out[JPSEC_MAC_ENTRY_BYTES]);

/* Constant-time comparison, for MAC verification. */
int jpsec_macs_equal(const uint8_t *a, const uint8_t *b);

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
 * Parse the zone table, IV and MAC table of a structurally valid SEC segment at
 * buf[sec_off].  On success returns the zone count (>= 1) and fills up to `max`
 * entries of `starts` (payload-relative offsets) and `sizes`, copies the IV when
 * `iv_out` is non-NULL and copies up to `max` MACs of JPSEC_MAC_ENTRY_BYTES each
 * into `macs` (a flat max*32 buffer) when `macs` is non-NULL.  Returns 0 on any
 * structural failure, in which case the output buffers are left untouched.
 */
int jpsec_parse_sec_zones(const uint8_t *buf, size_t size, size_t sec_off,
                          uint32_t *starts, uint32_t *sizes, int max,
                          uint8_t *iv_out,
                          uint8_t *macs);

/*
 * Overwrite the zone table of an already-written SEC segment.  `count` must
 * match the count reserved by jpsec_set_zone_count(), otherwise this is a
 * no-op and the marker is left untouched.
 */
void jpsec_patch_sec_zones(uint8_t *buf, size_t size, size_t sec_off,
                           const uint32_t *starts, const uint32_t *sizes,
                           int count);

/* Overwrite the MAC table.  Same preconditions as jpsec_patch_sec_zones. */
void jpsec_patch_sec_macs(uint8_t *buf, size_t size, size_t sec_off,
                          const uint8_t *macs, int count);

#ifdef __cplusplus
}
#endif

#endif /* JPSEC_AES_H */
