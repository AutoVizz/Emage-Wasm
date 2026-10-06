#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <openjpeg.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "jpsec_aes.h"

using namespace emscripten;

namespace {

struct MemoryReader {
    const uint8_t* data;
    OPJ_SIZE_T size;
    OPJ_SIZE_T offset;
};

OPJ_SIZE_T opj_mem_read(void* p_buffer, OPJ_SIZE_T p_nb_bytes, void* p_user_data) {
    auto* reader = static_cast<MemoryReader*>(p_user_data);
    if (reader->offset >= reader->size) return 0;  // EOF, not an error
    OPJ_SIZE_T bytesToRead = std::min(p_nb_bytes, reader->size - reader->offset);
    std::memcpy(p_buffer, reader->data + reader->offset, bytesToRead);
    reader->offset += bytesToRead;
    return bytesToRead;
}

OPJ_OFF_T opj_mem_skip(OPJ_OFF_T p_nb_bytes, void* p_user_data) {
    auto* reader = static_cast<MemoryReader*>(p_user_data);
    if (p_nb_bytes < 0) return -1;
    reader->offset = std::min(reader->size, reader->offset + static_cast<OPJ_SIZE_T>(p_nb_bytes));
    return p_nb_bytes;
}

OPJ_BOOL opj_mem_seek(OPJ_OFF_T p_nb_bytes, void* p_user_data) {
    auto* reader = static_cast<MemoryReader*>(p_user_data);
    if (p_nb_bytes < 0 || static_cast<OPJ_SIZE_T>(p_nb_bytes) > reader->size) return OPJ_FALSE;
    reader->offset = static_cast<OPJ_SIZE_T>(p_nb_bytes);
    return OPJ_TRUE;
}

// Granular progressive decryption.
//
// The SEC marker carries one zone entry per DWT resolution level, each holding
// a payload-relative byte range. Levels are numbered coarse-first — level 0 is
// the 1-pixel approximation, level E-1 the finest — which is the order
// OpenJPEG consumes when reducing.
//
// `accessLevel` is the highest level the caller may read. The decoder derives
// K0..K_accessLevel from the master key, decrypts exactly those zones, and
// leaves the rest as ciphertext. When the caller holds fewer levels than the
// file contains, the codestream is rebuilt to declare and carry only the
// levels it can read, so OpenJPEG is never handed a packet it cannot parse.
//
// A stream without a SEC marker is plaintext and is left untouched.
struct JpscSecurity {
    bool valid = false;
    size_t payloadStart = 0;              // first byte after SOD
    std::vector<uint32_t> starts;         // payload-relative offsets
    std::vector<uint32_t> sizes;
    uint8_t iv[JPSEC_AES_IV_BYTES] = {}; // counter block, carried in the marker
    std::vector<uint8_t> macs;            // cumulative SHA3-256 tag per level
};

size_t findInHeader(const uint8_t* bytes, size_t size, size_t from, size_t limit,
                    uint8_t hi, uint8_t lo) {
    const size_t m = jpsec_find_marker(bytes, size, hi, lo, from);
    return (m < limit) ? m : size;
}

// A zone table is believable when its offsets never move backwards and the
// first zone lies inside the payload we hold. Trailing zones are allowed to
// overrun: a stream truncated to fewer levels keeps the full table.
//
// Arithmetic is done in 64 bits because starts[z] and sizes[z] are 32-bit
// attacker-controlled fields; summing them as uint32_t could wrap and defeat
// the monotonicity check below.
bool sec_ok_starts(const uint32_t* starts, const uint32_t* sizes, int n,
                   size_t payload) {
    uint64_t prevEnd = 0;
    for (int z = 0; z < n; ++z) {
        const uint64_t start = starts[z];
        if (start < prevEnd) {
            return false;
        }
        prevEnd = start + static_cast<uint64_t>(sizes[z]);
    }
    return static_cast<uint64_t>(starts[0]) <= static_cast<uint64_t>(payload);
}

JpscSecurity computeSecurityZones(const uint8_t* bytes, size_t size) {
    JpscSecurity sec;
    if (size == 0) return sec;

    const size_t soc = jpsec_find_marker(bytes, size, 0xFF, 0x4F, 0);
    if (soc == size || soc + 2 >= size) return sec;
    // The main header is SOC..SOD and is always plaintext, so it is the only
    // region scanned for a security marker. Scanning into the payload would let
    // a coincidental FF 65 pair in packet data trigger spurious decryption.
    const size_t sod = jpsec_find_marker(bytes, size, 0xFF, 0x93, soc + 2);
    const size_t headerEnd = (sod == size) ? size : sod + 2;
    if (sod == size || sod + 2 >= size) return sec;

    uint32_t starts[JPSEC_MAX_ZONES];
    uint32_t sizes[JPSEC_MAX_ZONES];
    uint8_t iv[JPSEC_AES_IV_BYTES];
    uint8_t macs[JPSEC_MAX_ZONES * JPSEC_MAC_ENTRY_BYTES];
    for (size_t i = soc + 2; i + 1 < headerEnd;) {
        const size_t m = jpsec_find_marker(bytes, size, 0xFF, 0x65, i);
        if (m == size || m >= headerEnd - 1) break;
        const int n = jpsec_parse_sec_zones(bytes, size, m, starts, sizes,
                                            JPSEC_MAX_ZONES, iv, macs);
        if (n > 0) {
            // Zones must be ordered and start inside the payload. Zones beyond
            // the bytes we hold are tolerated: a stream previously truncated to
            // fewer levels still carries the full zone table, and OpenJPEG
            // ignores SEC entirely, so the header stays meaningful.
            const size_t payload = size - (sod + 2);
            bool ok = sec_ok_starts(starts, sizes, n, payload);
            if (ok) {
                sec.valid = true;
                sec.payloadStart = sod + 2;
                sec.starts.assign(starts, starts + n);
                sec.sizes.assign(sizes, sizes + n);
                memcpy(sec.iv, iv, JPSEC_AES_IV_BYTES);
                sec.macs.assign(macs, macs + (size_t)n * JPSEC_MAC_ENTRY_BYTES);
            }
            break;
        }
        i = m + 2;  // step past a look-alike FF 65 pair
    }
    return sec;
}

// Recompute the cumulative MAC chain over the now-decrypted zones 0..accessLevel
// and compare it with the tags stored in the marker.
//
// Returns an empty string when the chain verifies, otherwise a message naming
// the first level that failed. Levels above the grant are not touched: their
// bytes are still ciphertext and their tags are meaningless without the key.
//
// The tags cover Z and T as well as the zone plaintext, so this catches a
// relocated or resized zone as well as flipped payload bytes -- which is the
// point: AES-256-CTR on its own detects neither.
std::string verifyAccessibleMacs(uint8_t* bytes, size_t size,
                                 const uint8_t key[JPSEC_AES_KEY_BYTES],
                                 int accessLevel,
                                 const JpscSecurity& sec) {
    if (!sec.valid || sec.macs.size() != sec.sizes.size() * JPSEC_MAC_ENTRY_BYTES) {
        return "";
    }
    if (size <= sec.payloadStart) return "";
    const size_t payload = size - sec.payloadStart;
    const int count = static_cast<int>(sec.sizes.size());
    if (accessLevel < 0 || accessLevel >= count) accessLevel = count - 1;

    uint8_t chain[JPSEC_MAX_ZONES * JPSEC_AES_KEY_BYTES];
    if (jpsec_derive_level_keys(key, accessLevel + 1, chain) != accessLevel + 1) {
        return "failed to derive granular key chain for MAC verification";
    }
    uint8_t computed[JPSEC_MAC_ENTRY_BYTES];
    const uint8_t *prev = nullptr;
    for (int r = 0; r <= accessLevel; ++r) {
        const size_t start = sec.starts[(size_t)r];
        const size_t len = (start >= payload)
            ? 0
            : std::min(static_cast<size_t>(sec.sizes[(size_t)r]), payload - start);
        if (!jpsec_level_mac(prev, chain + (size_t)r * JPSEC_AES_KEY_BYTES,
                             (uint32_t)r, sec.starts[(size_t)r],
                             sec.sizes[(size_t)r],
                             bytes + sec.payloadStart + start, len, computed)) {
            return "failed to recompute level MAC";
        }
        if (!jpsec_macs_equal(computed,
                              &sec.macs[(size_t)r * JPSEC_MAC_ENTRY_BYTES])) {
            return "MAC verification failed at resolution level " +
                   std::to_string(r) + ": the codestream has been modified";
        }
        prev = computed;
    }
    return "";
}

// Decrypt levels 0..accessLevel and return the number of payload bytes those
// levels occupy. accessLevel is clamped to the levels actually present; a
// negative value means "every level in the file".
//
// `size` is the total buffer length. Every zone range is clamped to the bytes
// actually present before it is used for a read or a write, because Z and T
// come straight out of an untrusted codestream: without the clamp a hostile SEC
// marker can declare a T far larger than the payload and turn the in-place
// decrypt into an out-of-bounds heap write.
size_t decryptAccessibleLevels(uint8_t* bytes, size_t size,
                               const uint8_t key[JPSEC_AES_KEY_BYTES],
                               const uint8_t iv[JPSEC_AES_IV_BYTES],
                               int accessLevel,
                               const JpscSecurity& sec) {
    if (!sec.valid || size <= sec.payloadStart) return 0;
    const size_t payload = size - sec.payloadStart;
    const int count = static_cast<int>(sec.sizes.size());
    if (accessLevel < 0 || accessLevel >= count) accessLevel = count - 1;

    uint8_t chain[JPSEC_MAX_ZONES * JPSEC_AES_KEY_BYTES];
    if (jpsec_derive_level_keys(key, accessLevel + 1, chain) != accessLevel + 1) {
        throw std::runtime_error("failed to derive granular key chain");
    }
    size_t keep = 0;
    for (int r = 0; r <= accessLevel; ++r) {
        const size_t start = sec.starts[(size_t)r];
        // A zone that begins past the payload, or that declares more bytes than
        // remain, is treated as empty rather than trusted.
        const size_t len = (start >= payload)
            ? 0
            : std::min(static_cast<size_t>(sec.sizes[(size_t)r]), payload - start);
        if (len > 0) {
            jpsec_aes256_ctr_crypt(chain + (size_t)r * JPSEC_AES_KEY_BYTES, iv,
                                   bytes + sec.payloadStart + start, len);
        }
        if (start + len > keep) {
            keep = start + len;
        }
    }
    // Never report more retained bytes than the buffer holds.
    return keep > payload ? payload : keep;
}

// Cut the codestream down to the payload prefix covered by the levels the
// caller may read, leaving every header segment intact.
//
// The headers are kept verbatim on purpose: rewriting COD's decomposition
// count would make OpenJPEG reinterpret the surviving subbands at the wrong
// scale, and dropping PLT would need a tile-part rebuild with a corrected
// Psot. Truncating the payload alone is enough, because the decode resolution
// factor tells OpenJPEG to stop after the last level it can read. Only Psot is
// corrected, since it otherwise still advertises the full tile-part length.
std::vector<uint8_t> truncateToLevels(const std::vector<uint8_t>& bytes,
                                      const JpscSecurity& sec,
                                      size_t keepBytes) {
    const size_t sod = sec.payloadStart - 2;
    // keepBytes derives from the codestream's own SEC table, so it is clamped to
    // the bytes we actually hold before it becomes an iterator range.
    if (keepBytes > bytes.size() - sec.payloadStart) {
        keepBytes = bytes.size() - sec.payloadStart;
    }
    const size_t sot = findInHeader(bytes.data(), bytes.size(), 0, sod, 0xFF, 0x90);
    if (sot == bytes.size() || sot + 10 > bytes.size()) {
        throw std::runtime_error("cannot truncate codestream: no SOT");
    }
    // SOT is 12 fixed bytes: marker(2) Lsot(2) Isot(2) Psot(4) TPsot(1) TNsot(1).
    std::vector<uint8_t> out;
    out.reserve(sot + 12 + keepBytes + 2);
    out.insert(out.end(), bytes.begin(), bytes.begin() + (sec.payloadStart + keepBytes));

    // Psot = total tile-part length, or 0 when it runs to the end of the file.
    const uint32_t psot = (static_cast<uint32_t>(bytes[sot + 6]) << 24) |
                          (static_cast<uint32_t>(bytes[sot + 7]) << 16) |
                          (static_cast<uint32_t>(bytes[sot + 8]) <<  8) |
                           static_cast<uint32_t>(bytes[sot + 9]);
    if (psot != 0) {
        const uint32_t newPsot = static_cast<uint32_t>(sec.payloadStart + keepBytes - sot);
        out[sot + 6] = static_cast<uint8_t>(newPsot >> 24);
        out[sot + 7] = static_cast<uint8_t>(newPsot >> 16);
        out[sot + 8] = static_cast<uint8_t>(newPsot >>  8);
        out[sot + 9] = static_cast<uint8_t>(newPsot);
    }
    out.push_back(0xFF);
    out.push_back(0xD9);                                  // EOC
    return out;
}
}  // namespace

struct DecodeResult {
    int width = 0;
    int height = 0;
    int numComponents = 0;
    // DWT halvings actually applied (0 = full resolution), and the codestream's
    // resolution count, so a caller can pick a finer or coarser level without
    // re-deriving the decomposition count from the pixel dimensions.
    int reduction = 0;
    int numResolutions = 0;
    val rgbaPixels = val::null();
};

// Read the codestream's resolution count from the already-parsed main header.
// opj_image_t does not carry it, so it is read back out of the tile-component
// coding parameters. Returns 0 when it cannot be determined.
int readNumResolutions(opj_codec_t* codec) {
    opj_codestream_info_v2_t* info = opj_get_cstr_info(codec);
    if (!info) return 0;
    int count = 0;
    if (info->m_default_tile_info.tccp_info) {
        count = static_cast<int>(info->m_default_tile_info.tccp_info[0].numresolutions);
    }
    opj_destroy_cstr_info(&info);
    return count;
}

DecodeResult decodeInternal(const uint8_t* input, size_t inputSize,
                            const uint8_t key[JPSEC_AES_KEY_BYTES],
                            const uint8_t iv[JPSEC_AES_IV_BYTES],
                            int accessLevel,
                            int reduction) {
    if (!input || inputSize == 0) {
        throw std::runtime_error("Invalid input buffer");
    }

    const JpscSecurity sec = computeSecurityZones(input, inputSize);

    // The counter block travels in the marker, so it is authoritative for this
    // codestream.  A caller-supplied IV is only used for a stream with no SEC
    // marker, which by definition has no encryption to undo.
    const uint8_t* useIv = iv;
    if (sec.valid) {
        useIv = sec.iv;
    }

    // Levels the caller may read are decrypted in place; anything finer is
    // left as ciphertext. When the caller holds a subset, the codestream is
    // rebuilt around just those levels so OpenJPEG never meets a packet it
    // cannot parse.
    std::vector<uint8_t> owned;
    const uint8_t* j2kBytes = input;
    size_t bufferSize = inputSize;
    if (sec.valid) {
        const size_t keep = decryptAccessibleLevels(
            const_cast<uint8_t*>(input), inputSize, key, useIv, accessLevel, sec);
        const int total = static_cast<int>(sec.sizes.size());
        const int granted =
            (accessLevel < 0 || accessLevel >= total) ? total - 1 : accessLevel;
        // Integrity is checked on the plaintext the caller may read, before any
        // truncation, so a tampered zone is rejected rather than silently
        // decoded into a plausible-looking image.
        const std::string macError = verifyAccessibleMacs(
            const_cast<uint8_t*>(input), inputSize, key, granted, sec);
        if (!macError.empty()) {
            throw std::runtime_error(macError);
        }
        // Levels are counted coarse-first, so the finest image this key set can
        // reconstruct is the one at resolution level `granted`:
        //     reduction >= total - 1 - granted
        // A finer request is clamped rather than honoured. OpenJPEG does not
        // fail on a truncated payload — it synthesises the missing levels as
        // empty and returns a plausible-looking but wrong image, so silently
        // over-reading would be far worse than a coarser result. The clamped
        // value is reported back in DecodeResult::reduction.
        const int minReduction = total - 1 - granted;
        if (reduction < minReduction) {
            reduction = minReduction;
        }
        if (granted < total - 1) {
            owned = truncateToLevels(
                std::vector<uint8_t>(input, input + inputSize), sec, keep);
            j2kBytes = owned.data();
            bufferSize = owned.size();
        }
    }

    MemoryReader reader{j2kBytes, bufferSize, 0};
    opj_stream_t* stream = opj_stream_create(OPJ_J2K_STREAM_CHUNK_SIZE, OPJ_TRUE);

    opj_stream_set_read_function(stream, opj_mem_read);
    opj_stream_set_skip_function(stream, opj_mem_skip);
    opj_stream_set_seek_function(stream, opj_mem_seek);
    opj_stream_set_user_data(stream, &reader, nullptr);
    opj_stream_set_user_data_length(stream, bufferSize);

    opj_codec_t* codec = opj_create_decompress(OPJ_CODEC_J2K);
    opj_dparameters_t coreParams;
    opj_set_default_decoder_parameters(&coreParams);

    if (!opj_setup_decoder(codec, &coreParams)) {
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        throw std::runtime_error("opj_setup_decoder failed");
    }

    opj_image_t* image = nullptr;
    if (!opj_read_header(stream, codec, &image)) {
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        throw std::runtime_error("Failed to read J2K header");
    }

    // Reduced-resolution decode. opj_set_decoded_resolution_factor() takes a
    // reduction factor — the number of DWT halvings — and decodes only the
    // resolution level that many halvings above the coarsest, so the code blocks
    // and coefficient arrays of the finer levels are never allocated or MQ
    // decoded. It rejects a factor that is not below the codestream's resolution
    // count, so clamp against the count the header declares rather than failing.
    // Must be called after opj_read_header() and before opj_decode().
    int appliedReduction = 0;
    const int numResolutions = readNumResolutions(codec);
    if (reduction > 0 && numResolutions > 1) {
        OPJ_UINT32 resFactor = static_cast<OPJ_UINT32>(reduction);
        if (resFactor >= static_cast<OPJ_UINT32>(numResolutions)) {
            resFactor = static_cast<OPJ_UINT32>(numResolutions) - 1;
        }
        if (opj_set_decoded_resolution_factor(codec, resFactor)) {
            appliedReduction = static_cast<int>(resFactor);
        }
    }

    if (!opj_decode(codec, stream, image)) {
        opj_image_destroy(image);
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        throw std::runtime_error("opj_decode failed");
    }

    opj_stream_destroy(stream);
    opj_destroy_codec(codec);

    // Convert OpenJPEG planar data into a contiguous RGBA buffer ready for Canvas.
    // Components are allowed to have different sizes (4:2:0 and friends), so each
    // one is indexed with its own stride and resampled to the component-0 grid.
    // Sharing a single index across components would read past the end of every
    // subsampled plane.
    const int width = static_cast<int>(image->comps[0].w);
    const int height = static_cast<int>(image->comps[0].h);
    const int numComps = image->numcomps;
    const size_t totalPixels = static_cast<size_t>(width) * height;
    std::vector<uint8_t> rgba(totalPixels * 4, 255);

    // Nearest-neighbour fetch of one component at an (x, y) position on the
    // component-0 grid.
    auto sample = [&image, numComps, width, height](int c, int x, int y) -> uint8_t {
        if (c >= numComps) return 0;
        const opj_image_comp_t& comp = image->comps[c];
        if (!comp.data || comp.w == 0 || comp.h == 0) return 0;
        int sx = x, sy = y;
        if (comp.w != width) sx = static_cast<int>(static_cast<int64_t>(x) * comp.w / width);
        if (comp.h != height) sy = static_cast<int>(static_cast<int64_t>(y) * comp.h / height);
        if (sx < 0) sx = 0;
        if (sy < 0) sy = 0;
        if (sx >= static_cast<int>(comp.w)) sx = static_cast<int>(comp.w) - 1;
        if (sy >= static_cast<int>(comp.h)) sy = static_cast<int>(comp.h) - 1;
        return static_cast<uint8_t>(comp.data[static_cast<size_t>(sy) * comp.w + sx]);
    };

    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            const size_t i = static_cast<size_t>(y) * width + x;
            if (numComps >= 3) { // RGB / YCbCr
                rgba[i * 4 + 0] = sample(0, x, y);
                rgba[i * 4 + 1] = sample(1, x, y);
                rgba[i * 4 + 2] = sample(2, x, y);
            } else if (numComps == 1) { // Grayscale
                const uint8_t val = sample(0, x, y);
                rgba[i * 4 + 0] = val;
                rgba[i * 4 + 1] = val;
                rgba[i * 4 + 2] = val;
            }
        }
    }

    opj_image_destroy(image);

    // Expose memory as Uint8ClampedArray for Canvas ImageData instantiation
    val jsRgba = val::global("Uint8ClampedArray").new_(rgba.size());
    jsRgba.call<void>("set", val(typed_memory_view(rgba.size(), rgba.data())));

    return DecodeResult{width, height, numComps, appliedReduction, numResolutions, jsRgba};
}

// Decrypt with a caller-supplied AES-256 master key and counter block. The
// key/IV are accepted as JS arrays (or typed arrays) and coerced here.
//
// Polymorphic: cryptographic and unencrypted flows share this entry point.
// For unencrypted streams (no SEC marker in the main header) the key/IV are
// optional and ignored — pass null/undefined. Only codestreams that actually
// carry a SEC marker demand a key and an IV, and a clear error is raised then.
//
// `accessLevel` is the highest DWT resolution level the caller may decrypt,
// counted coarse-first: 0 is the 1-pixel approximation. K0..K_accessLevel are
// derived from the master key, exactly the levels OpenJPEG needs to rebuild a
// reduced image, and finer levels stay encrypted and are dropped from the
// codestream handed to it. Pass a negative value to decrypt every level the
// file contains.
//
// `reduction` is the number of DWT halvings to decode at: 0 is the full
// resolution, 1 is half linear scale, and so on. It is clamped to the
// codestream's own resolution count, and the clamped value is reported back in
// DecodeResult::reduction alongside DecodeResult::numResolutions.
DecodeResult decodeRaw(uintptr_t j2kBufferPtr,
                       size_t bufferSize,
                       emscripten::val key,
                       emscripten::val iv,
                       int accessLevel,
                       int reduction) {
    if (!j2kBufferPtr || bufferSize == 0) {
        throw std::runtime_error("Invalid input buffer");
    }

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(j2kBufferPtr);
    const JpscSecurity sec = computeSecurityZones(bytes, bufferSize);

    const bool hasKey = !key.isUndefined() && !key.isNull();
    const bool hasIv  = !iv.isUndefined() && !iv.isNull();

    std::vector<uint8_t> kb(JPSEC_AES_KEY_BYTES, 0);
    std::vector<uint8_t> ib(JPSEC_AES_IV_BYTES, 0);

    if (hasKey) {
        kb = convertJSArrayToNumberVector<uint8_t>(key);
        if (kb.size() != JPSEC_AES_KEY_BYTES) {
            throw std::runtime_error("key must be exactly 32 bytes");
        }
    } else if (sec.valid) {
        throw std::runtime_error(
            "key is required: the codestream is encrypted (SEC marker present)");
    }

    if (hasIv) {
        ib = convertJSArrayToNumberVector<uint8_t>(iv);
        if (ib.size() != JPSEC_AES_IV_BYTES) {
            throw std::runtime_error("iv must be exactly 16 bytes");
        }
    } else if (sec.valid) {
        throw std::runtime_error(
            "iv is required: the codestream is encrypted (SEC marker present)");
    }

    return decodeInternal(bytes, bufferSize, kb.data(), ib.data(), accessLevel,
                          reduction);
}

// Report the per-level protection the decoder sees in a given buffer, without
// modifying it. The progressive UI uses this to show which resolution levels
// are already readable at each assembled stage and which are still ciphertext.
// Offsets are relative to the first payload byte, matching the SEC marker.
struct SecurityZone {
    int hasSec = 0;
    int zoneCount = 0;
    val starts = val::null();
    val sizes = val::null();
    val macs = val::null();   // flat zoneCount * 32 bytes, cumulative per level
    val iv = val::null();     // 16-byte counter block carried in the marker
};

SecurityZone describeSecurityZone(uintptr_t j2kBufferPtr, size_t bufferSize) {
    SecurityZone out;
    if (bufferSize == 0) return out;
    const JpscSecurity sec = computeSecurityZones(
        reinterpret_cast<const uint8_t*>(j2kBufferPtr), bufferSize);
    if (!sec.valid) return out;

    out.hasSec = 1;
    out.zoneCount = static_cast<int>(sec.sizes.size());
    out.starts = val::array();
    out.sizes = val::array();
    for (size_t i = 0; i < sec.sizes.size(); ++i) {
        out.starts.call<void>("push", sec.starts[i]);
        out.sizes.call<void>("push", sec.sizes[i]);
    }
    if (!sec.macs.empty()) {
        out.macs = val::array();
        for (size_t i = 0; i < sec.macs.size(); ++i) {
            out.macs.call<void>("push", sec.macs[i]);
        }
    }
    out.iv = val::array();
    for (int i = 0; i < JPSEC_AES_IV_BYTES; ++i) {
        out.iv.call<void>("push", static_cast<int>(sec.iv[i]));
    }
    return out;
}

EMSCRIPTEN_BINDINGS(j2k_decoder) {
    value_object<DecodeResult>("DecodeResult")
        .field("width", &DecodeResult::width)
        .field("height", &DecodeResult::height)
        .field("numComponents", &DecodeResult::numComponents)
        .field("reduction", &DecodeResult::reduction)
        .field("numResolutions", &DecodeResult::numResolutions)
        .field("rgbaPixels", &DecodeResult::rgbaPixels);

    value_object<SecurityZone>("SecurityZone")
        .field("hasSec", &SecurityZone::hasSec)
        .field("zoneCount", &SecurityZone::zoneCount)
        .field("starts", &SecurityZone::starts)
        .field("sizes", &SecurityZone::sizes)
        .field("macs", &SecurityZone::macs)
        .field("iv", &SecurityZone::iv);

    function("decodeRaw", &decodeRaw);
    function("describeSecurityZone", &describeSecurityZone);
}
