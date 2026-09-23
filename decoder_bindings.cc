#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <openjpeg.h>

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <stdexcept>
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

// JPSEC (dummy AES-CTR scheme): locate the protected byte zone and decrypt it
// in place with the caller-supplied key/counter block before handing the bytes
// to OpenJPEG.
struct JpscZone {
    bool valid = false;
    size_t start = 0;
    size_t end = 0;
    int levels = 1;  // cascade rounds, read from the SEC marker when present
};

// Compute the byte zone [start, end) that must be AES-CTR decrypted before
// handing the buffer to OpenJPEG.
//
// Strategy (in priority order):
//
//  1. Use the Z/T fields stored in the SEC marker — the encoder patches these
//     with the exact byte offsets after compression, so they are authoritative
//     for complete codestreams.  We validate that the declared range fits inside
//     the buffer before trusting it.
//
//  2. For progressive slices the buffer is only a prefix of the full file, so
//     the stored Z/T (which point into the full-file layout) will exceed the
//     buffer size and fail the range check.  In that case we fall back to
//     scanning the HEADER (plaintext) for the SOD marker and use the end of the
//     buffer as the zone end.  We deliberately do NOT scan the encrypted payload
//     for EOC — encrypted data can contain 0xFF 0xD9 at arbitrary positions
//     (false positives), which would cause us to decrypt a shorter zone than the
//     encoder encrypted and corrupt the codestream.
//
//  A stream without a SEC marker is plaintext and is left untouched.
JpscZone computeSecurityZone(const uint8_t* bytes, size_t size) {
    JpscZone zone;
    if (size == 0) return zone;

    const size_t soc = jpsec_find_marker(bytes, size, 0xFF, 0x4F, 0);
    if (soc == size || soc + 2 >= size) return zone;

    // Main header is SOC .. SOD, and only the payload after SOD is ever
    // encrypted.  Only a *structurally valid* SEC segment inside the header
    // counts as a security marker: a coincidental FF 65 pair inside the
    // (possibly encrypted) packet data must not be mistaken for one.  This
    // keeps plaintext codestreams whose payload happens to contain FF 65
    // ("poly" unencrypted flows) free of spurious decryption.
    //
    // Structural validation and field extraction are delegated to
    // jpsec_parse_sec() (layout documented in jpsec_aes.h): registry-based
    // form + T.sec=0x0002 + E=1, with Z/T/Levels read as big-endian fields at
    // segment offsets 9..16 / 17..18.  Level defaults to 1 for streams whose
    // marker predates the Levels field.
    const size_t sod = jpsec_find_marker(bytes, size, 0xFF, 0x93, soc + 2);
    const size_t headerEnd = (sod == size) ? size : sod + 2;

    size_t sec = size;
    uint32_t secStart = 0;
    uint32_t secSize  = 0;
    int levels = 1;
    for (size_t i = soc + 2; i + 1 < headerEnd;) {
        const size_t m = jpsec_find_marker(bytes, size, 0xFF, 0x65, i);
        if (m == size || m >= headerEnd - 1) break;  // nothing (else) in the header
        uint32_t z = 0;
        uint32_t t = 0;
        uint16_t l = 0;
        if (jpsec_parse_sec(bytes, size, m, &z, &t, &l)) {
            sec = m;
            secStart = z;
            secSize = t;
            if (l >= 1 && l <= JPSEC_MAX_LEVELS) levels = l;
            break;
        }
        i = m + 2;  // scan past a look-alike FF 65 pair
    }
    if (sec == size) return zone;  // plaintext stream, nothing to decrypt
    zone.levels = levels;

    // --- Priority 1: SEC marker's stored Z/T (authoritative for full streams) ---
    if (secStart  != 0 && secSize != 0 &&
        static_cast<size_t>(secStart) <  size &&
        static_cast<size_t>(secSize)  <= size - static_cast<size_t>(secStart)) {
        zone.valid = true;
        zone.start = static_cast<size_t>(secStart);
        zone.end   = static_cast<size_t>(secStart) + static_cast<size_t>(secSize);
        return zone;
    }

    // --- Priority 2: scan-based fallback for progressive slices ---
    // The header (SOC .. SOD) is always plaintext, so scanning for SOD here is
    // safe.  We do NOT scan past SOD into the (possibly encrypted) payload.
    if (sod != size && sod + 2 < size) {
        const size_t zoneStart = sod + 2;
        // Use end-of-buffer as zone end.  For assembled progressive streams
        // finalizeStream() appends 0xFF 0xD9 (EOC); check for it so we don't
        // include the EOC itself in the decryption range.
        size_t zoneEnd = size;
        if (size >= 2 &&
            bytes[size - 2] == 0xFF && bytes[size - 1] == 0xD9) {
            zoneEnd = size - 2;
        }
        if (zoneEnd > zoneStart) {
            zone.valid = true;
            zone.start = zoneStart;
            zone.end   = zoneEnd;
        }
    }
    return zone;
}

void decryptJpscZone(uint8_t* bytes,
                     const uint8_t key[JPSEC_AES_KEY_BYTES],
                     const uint8_t iv[JPSEC_AES_IV_BYTES],
                     int levels,
                     const JpscZone& zone) {
    if (!zone.valid) return;
    // levels <= 0 means "as stored in the SEC marker". For header-less
    // windows (no marker) the caller must supply the explicit count.
    if (levels <= 0) levels = zone.levels;
    jpsec_aes256_ctr_cascade(key, iv, levels, bytes + zone.start, zone.end - zone.start);
}
}  // namespace

struct DecodeResult {
    int width = 0;
    int height = 0;
    int numComponents = 0;
    val rgbaPixels = val::null();
};

DecodeResult decodeInternal(uintptr_t j2kBufferPtr, size_t bufferSize,
                            const uint8_t key[JPSEC_AES_KEY_BYTES],
                            const uint8_t iv[JPSEC_AES_IV_BYTES],
                            int levels,
                            const JpscZone& zone) {
    if (!j2kBufferPtr || bufferSize == 0) {
        throw std::runtime_error("Invalid input buffer");
    }

    static const bool kAesKatOk = jpsec_aes256_kat_self_test() == 1;
    if (!kAesKatOk) {
        throw std::runtime_error("AES-256-CTR / SHA3-256 KAT self-test failed");
    }

    uint8_t* j2kBytes = reinterpret_cast<uint8_t*>(j2kBufferPtr);

    decryptJpscZone(j2kBytes, key, iv, levels, zone);

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

    if (!opj_decode(codec, stream, image)) {
        opj_image_destroy(image);
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        throw std::runtime_error("opj_decode failed");
    }

    opj_stream_destroy(stream);
    opj_destroy_codec(codec);

    const int width = image->x1 - image->x0;
    const int height = image->y1 - image->y0;
    const int numComps = image->numcomps;
    const size_t totalPixels = static_cast<size_t>(width) * height;

    // Convert OpenJPEG planar data into a contiguous RGBA buffer ready for Canvas
    std::vector<uint8_t> rgba(totalPixels * 4, 255);

    for (size_t i = 0; i < totalPixels; ++i) {
        if (numComps >= 3) { // RGB
            rgba[i * 4 + 0] = static_cast<uint8_t>(image->comps[0].data[i]);
            rgba[i * 4 + 1] = static_cast<uint8_t>(image->comps[1].data[i]);
            rgba[i * 4 + 2] = static_cast<uint8_t>(image->comps[2].data[i]);
        } else if (numComps == 1) { // Grayscale
            uint8_t val = static_cast<uint8_t>(image->comps[0].data[i]);
            rgba[i * 4 + 0] = val;
            rgba[i * 4 + 1] = val;
            rgba[i * 4 + 2] = val;
        }
    }

    opj_image_destroy(image);

    // Expose memory as Uint8ClampedArray for Canvas ImageData instantiation
    val jsRgba = val::global("Uint8ClampedArray").new_(rgba.size());
    jsRgba.call<void>("set", val(typed_memory_view(rgba.size(), rgba.data())));

    return DecodeResult{width, height, numComps, jsRgba};
}

// Decrypt with a caller-supplied AES-256 cascade key0 and counter block. The
// key/IV are accepted as JS arrays (or typed arrays) and coerced here.
//
// Polymorphic: cryptographic and unencrypted flows share this entry point.
// For unencrypted streams (no SEC marker in the main header) the key/IV are
// optional and ignored — pass null/undefined, levels too. Only codestreams
// that actually carry a SEC marker demand a key and an IV, and a clear error
// is raised then.
//
// `levels` is the cascade depth. Pass 0 (or <= 0) to read it from the SEC
// marker (works for full images and assembled layer-window streams, whose
// headers carry the marker). Header-less layer windows have no marker, so an
// explicit positive count is required there. Encrypted decode is only reached
// once the key is verified to be exactly 32 bytes and the IV exactly 16.
DecodeResult decodeRaw(uintptr_t j2kBufferPtr,
                       size_t bufferSize,
                       emscripten::val key,
                       emscripten::val iv,
                       int levels) {
    if (!j2kBufferPtr || bufferSize == 0) {
        throw std::runtime_error("Invalid input buffer");
    }

    const JpscZone zone =
        computeSecurityZone(reinterpret_cast<const uint8_t*>(j2kBufferPtr),
                            bufferSize);

    const bool hasKey = !key.isUndefined() && !key.isNull();
    const bool hasIv  = !iv.isUndefined() && !iv.isNull();

    std::vector<uint8_t> kb(JPSEC_AES_KEY_BYTES, 0);
    std::vector<uint8_t> ib(JPSEC_AES_IV_BYTES, 0);

    if (hasKey) {
        kb = convertJSArrayToNumberVector<uint8_t>(key);
        if (kb.size() != JPSEC_AES_KEY_BYTES) {
            throw std::runtime_error("key must be exactly 32 bytes");
        }
    } else if (zone.valid) {
        throw std::runtime_error(
            "key is required: the codestream is encrypted (SEC marker present)");
    }

    if (hasIv) {
        ib = convertJSArrayToNumberVector<uint8_t>(iv);
        if (ib.size() != JPSEC_AES_IV_BYTES) {
            throw std::runtime_error("iv must be exactly 16 bytes");
        }
    } else if (zone.valid) {
        throw std::runtime_error(
            "iv is required: the codestream is encrypted (SEC marker present)");
    }

    if (zone.valid && levels > JPSEC_MAX_LEVELS) {
        throw std::runtime_error("levels too high");
    }

    return decodeInternal(j2kBufferPtr, bufferSize, kb.data(), ib.data(), levels, zone);
}

// Report the security zone the decoder would decrypt for a given buffer.  The
// progressive website uses this to show which byte range is still ciphertext at
// each assembled layer stage; it reads exactly the same zone computeSecurityZone()
// derives, without modifying the buffer.
struct SecurityZone {
    int hasSec = 0;
    size_t zoneStart = 0;
    size_t zoneSize = 0;
    int levels = 1;
};

SecurityZone describeSecurityZone(uintptr_t j2kBufferPtr, size_t bufferSize) {
    SecurityZone out;
    if (bufferSize == 0) return out;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(j2kBufferPtr);
    const JpscZone zone = computeSecurityZone(bytes, bufferSize);
    if (zone.valid) {
        out.hasSec = 1;
        out.zoneStart = zone.start;
        out.zoneSize = zone.end - zone.start;
        out.levels = zone.levels;
    }
    return out;
}

EMSCRIPTEN_BINDINGS(j2k_decoder) {
    value_object<DecodeResult>("DecodeResult")
        .field("width", &DecodeResult::width)
        .field("height", &DecodeResult::height)
        .field("numComponents", &DecodeResult::numComponents)
        .field("rgbaPixels", &DecodeResult::rgbaPixels);

    value_object<SecurityZone>("SecurityZone")
        .field("hasSec", &SecurityZone::hasSec)
        .field("zoneStart", &SecurityZone::zoneStart)
        .field("zoneSize", &SecurityZone::zoneSize)
        .field("levels", &SecurityZone::levels);

    function("decodeRaw", &decodeRaw);
    function("describeSecurityZone", &describeSecurityZone);
}