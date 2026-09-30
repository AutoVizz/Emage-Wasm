// Scratch harness: validates granular per-resolution SEC keys end to end.
const fs = require('fs');
const path = require('path');

const BUILD_DIR = path.join(__dirname, 'cmake-build-wasm');
const encoderModule = require('./cmake-build-wasm/EmageWasmEncoder.js');
const decoderModule = require('./cmake-build-wasm/EmageWasmDecoder.js');

function dataUrl(binary) {
    const bytes = fs.readFileSync(path.join(BUILD_DIR, binary));
    return 'data:application/wasm;base64,' + bytes.toString('base64');
}
const loadModule = (mod, binary) => mod({ locateFile: () => dataUrl(binary) });

const W = 256, H = 256, RES = 6;
const KEY = new Uint8Array(32).fill(0x11);
const IV = new Uint8Array(16).fill(0x22);

let fail = 0;
function check(cond, label) {
    console.log((cond ? 'PASS' : 'FAIL') + '  ' + label);
    if (!cond) fail = 1;
}
function errMsg(e) {
    if (e == null) return 'no error';
    if (e && e.message) return String(e.message);
    if (e && e.excPtr) return 'CppException';
    return String(e);
}
function toHeap(mod, bytes) {
    const ptr = mod._malloc(bytes.length);
    mod.HEAPU8.set(bytes, ptr);
    return ptr;
}
function sum(rgba) {
    let h = 0;
    for (let i = 0; i < rgba.length; ++i) h = (h * 31 + rgba[i]) | 0;
    return h;
}

async function run() {
    const encoder = await loadModule(encoderModule, 'EmageWasmEncoder.wasm');
    const decoder = await loadModule(decoderModule, 'EmageWasmDecoder.wasm');

    const baseOpts = {
        width: W, height: H, numComponents: 3, precision: 8, lossless: true,
        numResolutions: RES, numLayers: 1,
        enablePterm: false, enableSegsym: false, enableSop: false, enableEph: false,
        enableTlm: false, key: KEY, iv: IV,
    };

    const rgb = new Uint8Array(W * H * 3);
    for (let i = 0; i < rgb.length; ++i) rgb[i] = (i * 7) & 0xff;

    const enc = encoder.encodeRaw(toHeap(encoder, rgb), rgb.length, {
        ...baseOpts, numResolutions: RES, enableSec: true,
    });
    const bytes = new Uint8Array(enc);
    console.log(`encoded ${bytes.length} bytes, ${RES} resolutions`);

    // --- plaintext reference, same image, no SEC ---
    const plainEnc = encoder.encodeRaw(toHeap(encoder, rgb), rgb.length, {
        ...baseOpts, numResolutions: RES, enableSec: false,
    });
    const plain = new Uint8Array(plainEnc);

    // --- zone table ---
    const sec = decoder.describeSecurityZone(toHeap(decoder, bytes), bytes.length);
    check(sec.hasSec === 1, 'SEC marker recognised');
    check(sec.zoneCount === RES, `zone count == numResolutions (${sec.zoneCount} vs ${RES})`);
    let contiguous = true, total = 0;
    for (let i = 0; i < sec.starts.length; ++i) {
        if (sec.starts[i] !== total) contiguous = false;
        total += sec.sizes[i];
    }
    check(contiguous, 'zones tile the payload contiguously, coarse-first');
    check(sec.sizes[RES - 1] > 0, 'finest zone is non-empty');
    console.log('  zone sizes:', Array.from(sec.sizes).join(', '));

    // --- full decode with every key ---
    const full = decoder.decodeRaw(toHeap(decoder, bytes), bytes.length, KEY, IV, -1, 0);
    const ref = decoder.decodeRaw(toHeap(decoder, plain), plain.length, undefined, undefined, -1, 0);
    check(full.width === W && full.height === H, `full decode ${full.width}x${full.height}`);
    check(sum(full.rgbaPixels) === sum(ref.rgbaPixels), 'full decode matches plaintext reference');

    // --- partial access ---
    // Access level a is coarse-first, so keys K0..Ka reconstruct the image at
    // resolution level a, which is reduction RES-1-a. Asking for anything
    // finer must clamp to that rather than fabricate missing levels.
    for (let grant = 0; grant < RES; ++grant) {
        const minReduction = RES - 1 - grant;
        for (const ask of [0, 1, 3, 5]) {
            const eff = Math.max(ask, minReduction);
            const got = decoder.decodeRaw(toHeap(decoder, bytes), bytes.length, KEY, IV, grant, ask);
            const exp = decoder.decodeRaw(toHeap(decoder, plain), plain.length, undefined, undefined, -1, eff);
            const expectW = Math.ceil(W / Math.pow(2, eff));
            const expectH = Math.ceil(H / Math.pow(2, eff));
            check(got.width === expectW && got.height === expectH && got.reduction === eff,
                  `access ${grant} ask ${ask} -> ${got.width}x${got.height} r=${got.reduction} (expected ${expectW}x${expectH} r=${eff})`);
            check(sum(got.rgbaPixels) === sum(exp.rgbaPixels),
                  `access ${grant} ask ${ask} pixels match plaintext at r=${eff}`);
        }
    }

    // --- wrong key must not silently succeed ---
    const badKey = new Uint8Array(KEY);
    badKey[0] ^= 0xff;
    let threw = false, res = null;
    try {
        res = decoder.decodeRaw(toHeap(decoder, bytes), bytes.length, badKey, IV, -1, 0);
    } catch (e) { threw = true; }
    check(threw || (res && sum(res.rgbaPixels) !== sum(ref.rgbaPixels)),
          'wrong master key does not yield the reference image');

    // --- unencrypted stream still decodes without a key ---
    const okPlain = decoder.decodeRaw(toHeap(decoder, plain), plain.length, undefined, undefined, -1, 0);
    check(okPlain.width === W, 'unencrypted stream decodes with no key');

    console.log(fail ? '\nRESULT: FAIL' : '\nRESULT: PASS');
    process.exit(fail);
}

run().catch((e) => { console.error('harness error:', errMsg(e)); process.exit(1); });
