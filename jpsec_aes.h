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
 * Real marker layout as emitted by OpenJPEG's registry-based "SEC=YES"
 * option (T.807 5.5, registry-based, T.sec=0x0002). The segment is
 * Lsec bytes long; offsets below are relative to the start of the marker:
 *
 *   Byte offset  Field         Notes
 *   0..1         marker        FF 65
 *   2..3         Lsec          segment length (includes itself); 44 for our streams
 *   4            Form          0x02 (registry-based)
 *   5..6         T.sec         0x0002 (private AES-CTR tool)
 *   7            E             0x01 (one protected zone)
 *   8            L             0x04 (zone info length: two 4-byte fields)
 *   9..12        Z             start byte offset of protected data  (4 bytes, big-endian)
 *   13..16       T             size in bytes of protected data      (4 bytes, big-endian)
 *   17..18       Levels        number of encryption levels (2 bytes, big-endian)
 *
 * The zone payload is AES-256-CTR encrypted `Levels` times in a cascade:
 * every level uses the exact same 16-byte IV, and the level keys form a
 * hash chain K1 = SHA3-256(K0), K2 = SHA3-256(K1), ... — a 256-bit input
 * maps to a 256-bit output, so SHA3-256 (fixed length) suffices. Because
 * CTR keystreams XOR, encrypting and decrypting reduce to the same
 * operation, applied in key order 0..Levels-1.
 *
 * Z/T are patched after encoding once the codestream layout is known.
 * Levels is written alongside so the decoder can chain the right number of
 * keys from the caller's K0. The SEC marker never carries any key material.
 */
#define JPSEC_SEC_Z_OFFSET        9
#define JPSEC_SEC_T_OFFSET        13
#define JPSEC_SEC_LEVELS_OFFSET   17
#define JPSEC_MAX_LEVELS          64
#define JPSEC_AES_KEY_BYTES       32   /* AES-256 */
#define JPSEC_AES_IV_BYTES        16

/* Fixed test key and counter block, used as the default when callers do not
 * supply their own. Not embedded in the output file. */
extern const uint8_t jpsec_test_key[JPSEC_AES_KEY_BYTES];
extern const uint8_t jpsec_test_iv[JPSEC_AES_IV_BYTES];

/* Returns 1 if the AES-256 (FIPS-197 C.3) and SHA3-256 (empty-input) KAT
 * vectors pass, i.e. both newly-enabled primitives are sound. */
int jpsec_aes256_kat_self_test(void);

/* AES-256-CTR in place (NIST SP 800-38A, key=256 bits). */
void jpsec_aes256_ctr_crypt(const uint8_t key[JPSEC_AES_KEY_BYTES],
                            const uint8_t iv[JPSEC_AES_IV_BYTES],
                            uint8_t *data,
                            size_t   len);

/*
 * Derive the full level-key chain from `key0`: out[i] = SHA3-256-iterate of
 * out[i-1], with out[0] = key0. `out` must hold levels * 32 bytes.
 * Returns the number of levels written.
 */
int jpsec_derive_level_keys(const uint8_t key0[JPSEC_AES_KEY_BYTES],
                            int levels,
                            uint8_t *out);

/*
 * AES-256-CTR cascade over `data[0..len)`: derives Keys[0..levels) from
 * `key0` and XORs the zone once per level, in key order, all with the same
 * `iv`. Identical cipher and decipher per the CTR XOR property.
 */
void jpsec_aes256_ctr_cascade(const uint8_t key0[JPSEC_AES_KEY_BYTES],
                              const uint8_t iv[JPSEC_AES_IV_BYTES],
                              int levels,
                              uint8_t *data,
                              size_t   len);

/* Scan `buf[0..size)` for an FF <lo> marker starting at `from`. */
size_t jpsec_find_marker(const uint8_t *buf, size_t size,
                         uint8_t hi, uint8_t lo, size_t from);

/*
 * Parse a structurally-valid SEC segment at `buf[sec]` using the layout
 * above. Returns 1 on success and fills the out params; 0 otherwise.
 */
int jpsec_parse_sec(const uint8_t *buf, size_t size, size_t sec_off,
                    uint32_t *zone_start, uint32_t *zone_size,
                    uint16_t *levels);

/*
 * Overwrite the Z/T/Levels fields of an already-written SEC segment.
 */
void jpsec_patch_sec(uint8_t *buf, size_t size, size_t sec_off,
                     uint32_t zone_start, uint32_t zone_size,
                     uint16_t levels);

#ifdef __cplusplus
}
#endif

#endif /* JPSEC_AES_H */