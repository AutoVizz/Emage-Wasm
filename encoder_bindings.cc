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

// Encryption over the entropy-coded payload: the SEC marker (FF 65) emitted by
// the encoder when SEC=YES is set describes a single protected zone (Z = start
// offset, T = size in bytes). After encoding, the zone is encrypted in place as
// an AES-256-CTR cascade of `levels` rounds: every round uses the exact same
// caller-supplied IV, and the round keys form a hash chain K1 = SHA3-256(K0),
// K2 = SHA3-256(K1), ... derived from the caller-supplied 256-bit key0. Z/T and
// the level count are patched into the marker; key material never travels with
// the file — the decoder must be given the same key0 (+ optionally levels).
void applyAesCtrSecurity(std::vector<uint8_t>& data,
                         const uint8_t key[JPSEC_AES_KEY_BYTES],
                         const uint8_t iv[JPSEC_AES_IV_BYTES],
                         int levels) {
    const size_t soc =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x4F, 0);
    if (soc == data.size()) return;
    const size_t sec =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x65, soc + 2);
    if (sec == data.size()) return;
    const size_t sod =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0x93, sec + 2);
    if (sod == data.size()) return;
    const size_t eoc =
        jpsec_find_marker(data.data(), data.size(), 0xFF, 0xD9, sod + 2);
    if (eoc == data.size()) return;

    const size_t zoneStart = sod + 2;
    const size_t zoneSize = eoc - zoneStart;
    if (zoneSize == 0) return;

    if (levels <= 0) levels = 1;
    jpsec_aes256_ctr_cascade(key, iv, levels, data.data() + zoneStart, zoneSize);
    jpsec_patch_sec(data.data(), data.size(), sec,
                    static_cast<uint32_t>(zoneStart),
                    static_cast<uint32_t>(zoneSize),
                    static_cast<uint16_t>(levels));
}

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
    bool enablePlt = false;
    bool enableSec = false;
    int levels = 1;  // AES-256-CTR cascade rounds; keys chained via SHA3-256
    // Optional 32-byte AES-256 key and 16-byte IV. Omitted when no encryption
    // is requested. The marker never stores these values.
    emscripten::val key = emscripten::val::undefined();
    emscripten::val iv = emscripten::val::undefined();
};

// Internal helper operating directly on a raw byte pointer.
std::vector<uint8_t> encodeInternal(const uint8_t* pixels,
                                    size_t pixelSize,
                                    const EncodeOptions& opts) {
    static const bool kAesKatOk = jpsec_aes256_kat_self_test() == 1;
    if (!kAesKatOk) {
        throw std::runtime_error("AES-256-CTR / SHA3-256 KAT self-test failed");
    }

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
    if (opts.levels < 1 || opts.levels > JPSEC_MAX_LEVELS) {
        throw std::runtime_error("levels must be between 1 and 64");
    }
    // OpenJPEG sizes tcp_rates/tcp_distoratio as fixed [100] arrays, so the
    // layer count is bounded by the codec struct rather than any library policy.
    if (opts.numLayers < 1 || opts.numLayers > 100) {
        throw std::runtime_error("numLayers must be between 1 and 100");
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
    parameters.tcp_numlayers = opts.numLayers;
    parameters.cp_fixed_quality = 0;
    parameters.cp_disto_alloc = 1;

    for (int i = 0; i < opts.numLayers; ++i) {
        parameters.tcp_rates[i] =
            (i == opts.numLayers - 1) ? 0.0f
                                       : static_cast<float>(opts.numLayers - i) * 4.0f;
    }
    parameters.prog_order = OPJ_LRCP;

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

    // Emit TLM (main header) and PLT (tile-part header) marker segments so the
    // headers carry the lengths of the tile-parts and packets respectively.
    // SEC adds a JPSEC security marker to the main header.
    const char* extraOptions[3] = {nullptr, nullptr, nullptr};
    int extraOptionCount = 0;
    if (opts.enableTlm) extraOptions[extraOptionCount++] = "TLM=YES";
    if (opts.enablePlt) extraOptions[extraOptionCount++] = "PLT=YES";
    if (opts.enableSec) extraOptions[extraOptionCount++] = "SEC=YES";
    if (extraOptionCount > 0 &&
        !opj_encoder_set_extra_options(codec, extraOptions)) {
        opj_destroy_codec(codec);
        opj_image_destroy(image);
        throw std::runtime_error("opj_encoder_set_extra_options failed");
    }

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
        applyAesCtrSecurity(result, key, iv, opts.levels);
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

EMSCRIPTEN_BINDINGS(j2k_jpsec_encoder) {
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
        .field("enablePlt", &EncodeOptions::enablePlt)
        .field("enableSec", &EncodeOptions::enableSec)
        .field("levels", &EncodeOptions::levels)
        .field("key", &EncodeOptions::key)
        .field("iv", &EncodeOptions::iv);

    function("encodeRaw", &encodeRaw);
}