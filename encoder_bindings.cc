#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <openjpeg.h>

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "jpsec_aes.h"

using namespace emscripten;

namespace {

constexpr int kModePterm = 0x10;
constexpr int kModeSegsym = 0x20;

constexpr int kCstySop = 0x02;
constexpr int kCstyEph = 0x04;

// Granular progressive encryption.
//
// The packet payload is split into one protected zone per DWT resolution
// level, taken from the tile-part packet table (PLT), and each zone is
// encrypted exactly once under its own key from the SHA3-256 chain over the
// caller's master key: K(E-1) = key, K(m-1) = SHA3-256(Km).
//
// Because OpenJPEG rebuilds a reduced image from the coarse levels only,
// a holder of Ka derives K0..Ka and decodes at reduction E-1-a without
// learning any finer key. The SEC marker records one zone entry per level so the decoder
// does not have to re-derive the boundaries; offsets are relative to the
// first payload byte, which keeps them valid when the serving layer rebuilds
// the main header. No key material is written to the file.
namespace {

// PLT packet lengths are JPEG variable-length integers: 7 bits per byte,
// big-endian, high bit set on every byte except the last.
uint32_t readPacketLength(const uint8_t*& p) {
    uint32_t v = 0;
    for (int i = 0; i < 5; ++i) {
        const uint8_t b = *p++;
        v = (v << 7) | (b & 0x7fu);
        if (!(b & 0x80u)) {
            return v;
        }
    }
    return v;
}

// Read the packet length table between the SOT and SOD markers and fold it
// into per-resolution byte ranges relative to `payloadStart`.
//
// Layout note: this encoder always emits one tile, one quality layer and no
// precinct partition, so under the default LRCP order each resolution level
// contributes exactly numComponents consecutive packets.
void computeLevelRanges(const std::vector<uint8_t>& data,
                        size_t pltOff,
                        size_t sotOff,
                        size_t payloadStart,
                        int numResolutions,
                        int numComponents,
                        std::vector<uint32_t>& starts,
                        std::vector<uint32_t>& sizes) {
    if (pltOff == data.size()) {
        throw std::runtime_error("granular keys require a PLT packet table");
    }
    if (sotOff >= pltOff) {
        throw std::runtime_error("malformed tile-part header");
    }
    const size_t lplt = ((size_t)data[pltOff + 2] << 8) | data[pltOff + 3];
    if (lplt < 3 || pltOff + 2 + lplt > data.size()) {
        throw std::runtime_error("malformed PLT length");
    }
    // Body after the 2-byte length field: Zplt then the packet lengths.
    const size_t wanted = (size_t)numResolutions * (size_t)numComponents;
    std::vector<uint32_t> lengths;
    lengths.reserve(wanted);

    // Zplt occupies the first body byte; the packet lengths follow.
    const uint8_t* p = data.data() + pltOff + 5;
    const uint8_t* end = data.data() + pltOff + 2 + lplt;
    while (p < end && lengths.size() < wanted) {
        const uint8_t* q = p;
        lengths.push_back(readPacketLength(q));
        p = q;
    }
    if (lengths.size() != wanted) {
        throw std::runtime_error("PLT packet count does not match "
                                 "numResolutions * numComponents");
    }

    size_t offset = 0;
    starts.assign((size_t)numResolutions, 0);
    sizes.assign((size_t)numResolutions, 0);
    for (int r = 0; r < numResolutions; ++r) {
        size_t bytes = 0;
        for (int c = 0; c < numComponents; ++c) {
            bytes += lengths[(size_t)r * (size_t)numComponents + (size_t)c];
        }
        starts[(size_t)r] = (uint32_t)offset;
        sizes[(size_t)r] = (uint32_t)bytes;
        offset += bytes;
    }
    if (payloadStart + offset > data.size()) {
        throw std::runtime_error("packet table overruns the codestream");
    }
}

void applyGranularSecurity(std::vector<uint8_t>& data,
                           const uint8_t key[JPSEC_AES_KEY_BYTES],
                           const uint8_t iv[JPSEC_AES_IV_BYTES],
                           int numResolutions,
                           int numComponents) {
    const size_t soc =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x4F, 0);
    if (soc == data.size()) return;
    const size_t sec =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x65, soc + 2);
    if (sec == data.size()) return;
    const size_t sot =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x90, sec + 2);
    if (sot == data.size()) return;
    const size_t plt =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x58, sot + 2);
    if (plt == data.size()) return;
    const size_t sod =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x93, plt + 2);
    if (sod == data.size()) return;

    const size_t payloadStart = sod + 2;

    std::vector<uint32_t> starts;
    std::vector<uint32_t> sizes;
    computeLevelRanges(data, plt, sot, payloadStart, numResolutions,
                       numComponents, starts, sizes);

    size_t total = 0;
    for (uint32_t s : sizes) {
        total += s;
    }
    // The packet table gives an exact payload extent, so EOC is located
    // arithmetically rather than by scanning for FF D9, which can false
    // positive on arbitrary packet bytes.
    const size_t eoc = payloadStart + total;
    if (eoc + 2 > data.size() || data[eoc] != 0xff || data[eoc + 1] != 0xd9) {
        throw std::runtime_error("EOC does not follow the packet table");
    }

    // The cumulative MAC chain is computed over the plaintext, before any of it
    // is encrypted, and covers Z and T as well so the tag also pins each zone's
    // position and extent.  Both are payload-relative, which is why the tags
    // stay valid when the serving layer rebuilds the main header.
    uint8_t chain[JPSEC_MAX_ZONES * JPSEC_AES_KEY_BYTES];
    if (jpsec_derive_level_keys(key, numResolutions, chain) != numResolutions) {
        throw std::runtime_error("failed to derive granular key chain");
    }
    std::vector<uint8_t> macs((size_t)numResolutions * JPSEC_MAC_ENTRY_BYTES);
    for (int r = 0; r < numResolutions; ++r) {
        const uint8_t *prev = r == 0 ? nullptr
                                     : &macs[(size_t)(r - 1) * JPSEC_MAC_ENTRY_BYTES];
        const uint8_t *plain = data.data() + payloadStart + starts[(size_t)r];
        if (!jpsec_level_mac(prev, chain + (size_t)r * JPSEC_AES_KEY_BYTES,
                             (uint32_t)r, starts[(size_t)r], sizes[(size_t)r],
                             plain, sizes[(size_t)r],
                             &macs[(size_t)r * JPSEC_MAC_ENTRY_BYTES])) {
            throw std::runtime_error("failed to compute level MAC");
        }
    }

    // Encrypt after the tags are taken: the payload is plaintext only here.
    for (int r = 0; r < numResolutions; ++r) {
        if (sizes[(size_t)r] == 0) continue;
        jpsec_aes256_ctr_crypt(chain + (size_t)r * JPSEC_AES_KEY_BYTES, iv,
                               data.data() + payloadStart + starts[(size_t)r],
                               sizes[(size_t)r]);
    }
    jpsec_patch_sec_zones(data.data(), data.size(), sec,
                          starts.data(), sizes.data(), numResolutions);
    jpsec_patch_sec_macs(data.data(), data.size(), sec,
                         macs.data(), numResolutions);
}

}  // namespace

void ojp_error_callback(const char* msg, void* /*client_data*/) {
    fprintf(stderr, "[openjpeg error] %s", msg);
}

void ojp_warning_callback(const char* msg, void* /*client_data*/) {
    fprintf(stderr, "[openjpeg warning] %s", msg);
}

}  // namespace

struct EncodeOptions {
    int width = 0;
    int height = 0;
    int numComponents = 1;
    int precision = 8;
    bool lossless = true;
    int numResolutions = 6;
    int numLayers = 2;
    bool enablePterm = false;
    bool enableSegsym = false;
    bool enableSop = false;
    bool enableEph = false;
    bool enableTlm = false;
    bool enableSec = false;
    // Optional 32-byte AES-256 key and 16-byte IV. Omitted when no encryption
    // is requested. The marker never stores these values.
    emscripten::val key = emscripten::val::undefined();
    emscripten::val iv = emscripten::val::undefined();
};

// Internal helper operating directly on a raw byte pointer.
std::vector<uint8_t> encodeInternal(const uint8_t* pixels,
                                    size_t pixelSize,
                                    const EncodeOptions& opts) {
    const uint8_t* key = jpsec_test_key;
    const uint8_t* iv = jpsec_test_iv;
    uint8_t keyBuf[JPSEC_AES_KEY_BYTES];
    uint8_t ivBuf[JPSEC_AES_IV_BYTES];
    if (!opts.key.isUndefined() && !opts.key.isNull()) {
        std::vector<uint8_t> kb = convertJSArrayToNumberVector<uint8_t>(opts.key);
        if (kb.size() != JPSEC_AES_KEY_BYTES) {
            throw std::runtime_error("key must be exactly 32 bytes");
        }
        std::memcpy(keyBuf, kb.data(), JPSEC_AES_KEY_BYTES);
        key = keyBuf;
    }
    if (!opts.iv.isUndefined() && !opts.iv.isNull()) {
        std::vector<uint8_t> ib = convertJSArrayToNumberVector<uint8_t>(opts.iv);
        if (ib.size() != JPSEC_AES_IV_BYTES) {
            throw std::runtime_error("iv must be exactly 16 bytes");
        }
        std::memcpy(ivBuf, ib.data(), JPSEC_AES_IV_BYTES);
        iv = ivBuf;
    }

    if (opts.width <= 0 || opts.height <= 0) {
        throw std::runtime_error("width/height must be positive");
    }
    // OpenJPEG sizes tcp_rates/tcp_distoratio as fixed [100] arrays, so the
    // layer count is bounded by the codec struct rather than any library policy.
    if (opts.numLayers < 1 || opts.numLayers > 100) {
        throw std::runtime_error("numLayers must be between 1 and 100");
    }
    // One protected zone per resolution level, so the SEC marker's zone table is
    // only sized correctly while the resolution count fits the table.
    if (opts.numResolutions < 1 || opts.numResolutions > JPSEC_MAX_ZONES) {
        throw std::runtime_error(
            "numResolutions must be between 1 and " + std::to_string(JPSEC_MAX_ZONES));
    }
    const size_t expectedBytes = static_cast<size_t>(opts.width) * opts.height *
                                 opts.numComponents;
    if (pixelSize != expectedBytes) {
        throw std::runtime_error(
            "pixel buffer size does not match width*height*numComponents");
    }

    // --- Build the opj_image_t -------------------------------------------------
    std::vector<opj_image_cmptparm_t> cmptparms(opts.numComponents);
    for (auto& c : cmptparms) {
        c.dx = 1;
        c.dy = 1;
        c.w = opts.width;
        c.h = opts.height;
        c.x0 = 0;
        c.y0 = 0;
        c.prec = opts.precision;
        c.sgnd = 0;
    }

    OPJ_COLOR_SPACE colorSpace =
        opts.numComponents >= 3 ? OPJ_CLRSPC_SRGB : OPJ_CLRSPC_GRAY;

    opj_image_t* image =
        opj_image_create(opts.numComponents, cmptparms.data(), colorSpace);
    if (!image) {
        throw std::runtime_error("opj_image_create failed");
    }
    image->x0 = 0;
    image->y0 = 0;
    image->x1 = opts.width;
    image->y1 = opts.height;

    // Convert interleaved JS buffer to OpenJPEG planar arrays
    for (int c = 0; c < opts.numComponents; ++c) {
        OPJ_INT32* dst = image->comps[c].data;
        for (int i = 0; i < opts.width * opts.height; ++i) {
            dst[i] = pixels[i * opts.numComponents + c];
        }
    }

    // --- Encoder parameters ------------------------------------------------
    opj_cparameters_t parameters;
    opj_set_default_encoder_parameters(&parameters);

    parameters.irreversible = opts.lossless ? 0 : 1;
    parameters.numresolution = opts.numResolutions;
    // Progression: always one lossless quality layer.
    // numResolutions determines the number of DWT levels and therefore
    // how many resolution steps the client can progressively decode.
    parameters.tcp_numlayers = 1;
    parameters.tcp_rates[0] = 0.0f;  // 0 = lossless
    parameters.cp_fixed_quality = 0;
    parameters.cp_disto_alloc = 1;
    // prog_order is deliberately left at the OpenJPEG default (OPJ_LRCP).
    // With tcp_numlayers = 1 the layer index is constant, so sorting by
    // (layer, resolution, ...) and by (resolution, layer, ...) yield the same
    // packet order: LRCP and RLCP emit identical codestreams here. Nothing in
    // this project uses quality layers, so declaring RLCP bought nothing and
    // only invited RLCP-specific branches elsewhere. If quality layers are ever
    // added, this must become OPJ_RLCP so a byte prefix stays resolution-major.

    parameters.mode = 0;
    if (opts.enablePterm)  parameters.mode |= kModePterm;
    if (opts.enableSegsym) parameters.mode |= kModeSegsym;

    parameters.csty = 0;
    if (opts.enableSop) parameters.csty |= kCstySop;
    if (opts.enableEph) parameters.csty |= kCstyEph;

    // --- Encode --------------------------------------------------------------
    opj_codec_t* codec = opj_create_compress(OPJ_CODEC_J2K);
    if (!codec) {
        opj_image_destroy(image);
        throw std::runtime_error("opj_create_compress failed");
    }
    opj_set_error_handler(codec, ojp_error_callback, nullptr);
    opj_set_warning_handler(codec, ojp_warning_callback, nullptr);

    if (!opj_setup_encoder(codec, &parameters, image)) {
        opj_destroy_codec(codec);
        opj_image_destroy(image);
        throw std::runtime_error("opj_setup_encoder failed");
    }

    // PLT is emitted unconditionally: the packet table is what lets the
    // encoder split the payload into per-resolution protected zones. TLM is
    // still opt-in. SEC adds a JPSEC security marker to the main header.
    const char* extraOptions[4] = {nullptr, nullptr, nullptr, nullptr};
    int extraOptionCount = 0;
    if (opts.enableTlm) extraOptions[extraOptionCount++] = "TLM=YES";
    extraOptions[extraOptionCount++] = "PLT=YES";
    if (opts.enableSec) extraOptions[extraOptionCount++] = "SEC=YES";
    if (extraOptionCount > 0 &&
        !opj_encoder_set_extra_options(codec, extraOptions)) {
        opj_destroy_codec(codec);
        opj_image_destroy(image);
        throw std::runtime_error("opj_encoder_set_extra_options failed");
    }

    // The SEC segment is written as a header procedure, before any per-tile
    // parameters exist, so the zone count and the counter block are published
    // up front.
    jpsec_set_zone_count(opts.numResolutions);
    jpsec_set_iv(opts.enableSec ? iv : jpsec_test_iv);

    const char* outPath = "/tmp/encode_out.j2k";
    opj_stream_t* stream = opj_stream_create_default_file_stream(outPath, OPJ_FALSE);
    if (!stream) {
        opj_destroy_codec(codec);
        opj_image_destroy(image);
        throw std::runtime_error("opj_stream_create_default_file_stream failed");
    }

    bool ok = opj_start_compress(codec, image, stream);
    ok = ok && opj_encode(codec, stream);
    ok = ok && opj_end_compress(codec, stream);

    opj_stream_destroy(stream);
    opj_destroy_codec(codec);
    opj_image_destroy(image);

    if (!ok) {
        throw std::runtime_error("encode failed");
    }

    FILE* f = fopen(outPath, "rb");
    if (!f) {
        throw std::runtime_error("failed to reopen encoded output from MEMFS");
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> result(static_cast<size_t>(size));
    fread(result.data(), 1, static_cast<size_t>(size), f);
    fclose(f);
    remove(outPath);

    if (opts.enableSec) {
        applyGranularSecurity(result, key, iv, opts.numResolutions,
                              opts.numComponents);
    }

    return result;
}

// High-performance raw pointer overload
emscripten::val encodeRaw(uintptr_t pixelPtr,
                          size_t pixelSize,
                          const EncodeOptions& opts) {
    const uint8_t* pixels = reinterpret_cast<const uint8_t*>(pixelPtr);
    std::vector<uint8_t> result = encodeInternal(pixels, pixelSize, opts);

    // Create JS Uint8Array and bulk-copy encoded bytes using typed_memory_view
    emscripten::val jsArray = emscripten::val::global("Uint8Array").new_(result.size());
    jsArray.call<void>("set", emscripten::val(typed_memory_view(result.size(), result.data())));
    return jsArray;
}

// Expose the granular key chain so a client can display or distribute the
// per-resolution keys after upload. Returns one lowercase hex string per key,
// K0 first, each 32 bytes. The chain is derived locally from the master key;
// nothing here is sent anywhere.
val deriveGranularKeys(emscripten::val key, int count) {
    if (count < 1 || count > JPSEC_MAX_ZONES) {
        throw std::runtime_error("count must be between 1 and 64");
    }
    std::vector<uint8_t> master = convertJSArrayToNumberVector<uint8_t>(key);
    if (master.size() != JPSEC_AES_KEY_BYTES) {
        throw std::runtime_error("key must be exactly 32 bytes");
    }
    uint8_t chain[JPSEC_MAX_ZONES * JPSEC_AES_KEY_BYTES];
    if (jpsec_derive_level_keys(master.data(), count, chain) != count) {
        throw std::runtime_error("failed to derive granular key chain");
    }
    static const char* kHex = "0123456789abcdef";
    val out = val::array();
    for (int i = 0; i < count; ++i) {
        std::string hex;
        hex.reserve(JPSEC_AES_KEY_BYTES * 2);
        for (size_t b = 0; b < JPSEC_AES_KEY_BYTES; ++b) {
            const uint8_t v = chain[(size_t)i * JPSEC_AES_KEY_BYTES + b];
            hex.push_back(kHex[v >> 4]);
            hex.push_back(kHex[v & 0x0f]);
        }
        out.call<void>("push", std::string(hex));
    }
    return out;
}

// Produce an opaque key lookup tag; this is safe to attach to metadata.
std::string keyLookupTag(emscripten::val key, emscripten::val iv) {
    const auto kb = convertJSArrayToNumberVector<uint8_t>(key);
    const auto ib = convertJSArrayToNumberVector<uint8_t>(iv);
    if (kb.size() != JPSEC_AES_KEY_BYTES || ib.size() != JPSEC_AES_IV_BYTES) {
        throw std::runtime_error("lookup requires a 32-byte key and 16-byte IV");
    }
    uint8_t tag[JPSEC_MAC_ENTRY_BYTES];
    if (!jpsec_key_lookup_tag(kb.data(), ib.data(), tag)) {
        throw std::runtime_error("Failed to compute key lookup tag");
    }
    static const char* hex = "0123456789abcdef";
    std::string result;
    for (uint8_t byte : tag) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

EMSCRIPTEN_BINDINGS(j2k_jpsec_encoder) {
    function("keyLookupTag", &keyLookupTag);
    value_object<EncodeOptions>("EncodeOptions")
        .field("width", &EncodeOptions::width)
        .field("height", &EncodeOptions::height)
        .field("numComponents", &EncodeOptions::numComponents)
        .field("precision", &EncodeOptions::precision)
        .field("lossless", &EncodeOptions::lossless)
        .field("numResolutions", &EncodeOptions::numResolutions)
        .field("numLayers", &EncodeOptions::numLayers)
        .field("enablePterm", &EncodeOptions::enablePterm)
        .field("enableSegsym", &EncodeOptions::enableSegsym)
        .field("enableSop", &EncodeOptions::enableSop)
        .field("enableEph", &EncodeOptions::enableEph)
        .field("enableTlm", &EncodeOptions::enableTlm)
        .field("enableSec", &EncodeOptions::enableSec)
        .field("key", &EncodeOptions::key)
        .field("iv", &EncodeOptions::iv);

    function("encodeRaw", &encodeRaw);
    function("deriveGranularKeys", &deriveGranularKeys);
}
