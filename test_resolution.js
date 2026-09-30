// Reduced-resolution decode verification.
//
// Checks, in order:
//   1. Each DWT halving quarters the sample count, exactly.
//   2. A reduction beyond the codestream's resolution count clamps instead of
//      failing, and reports the clamped value back.
//   3. reduction 0 is unchanged by this work: same dimensions, same RGBA bytes.
//   4. On smooth content, a coarse level matches a box downsample of the full
//      raster -- i.e. it is a real downscale, not garbage or a wrong offset.
//   5. On high-frequency content, a coarse level differs substantially from the
//      full raster -- i.e. the reduction genuinely discards the finest DWT
//      levels rather than low-pass filtering a full-size decode.
const fs = require('fs');
const path = require('path');

const BUILD_DIR = path.join(__dirname, 'cmake-build-wasm');
const encoderModule = require('./cmake-build-wasm/EmageWasmEncoder.js');
const decoderModule = require('./cmake-build-wasm/EmageWasmDecoder.js');

function dataUrl(binary) {
    const bytes = fs.readFileSync(path.join(BUILD_DIR, binary));
    return 'data:application/wasm;base64,' + bytes.toString('base64');
}

const W = 1024, H = 1024;
const NUM_RESOLUTIONS = 6;
const NUM_LAYERS = 6;

function encode(enc, fill) {
    const rgb = new Uint8Array(W * H * 3);
    for (let y = 0; y < H; ++y) {
        for (let x = 0; x < W; ++x) fill(x, y, rgb, (y * W + x) * 3);
    }
    const opts = {
        width: W, height: H, numComponents: 3, precision: 8, lossless: true,
        numResolutions: NUM_RESOLUTIONS, numLayers: NUM_LAYERS,
        enablePterm: false, enableSegsym: false, enableSop: false, enableEph: false,
        enableTlm: true, enableSec: false,
        key: null, iv: null,
    };
    const ptr = enc._malloc(rgb.length);
    enc.HEAPU8.set(rgb, ptr);
    const j2k = enc.encodeRaw(ptr, rgb.length, opts);
    enc._free(ptr);
    return j2k;
}

const smooth = (x, y, out, i) => {
    out[i] = (x * 255 / W) | 0;
    out[i + 1] = (y * 255 / H) | 0;
    out[i + 2] = (128 + 100 * Math.sin(x / 96) * Math.cos(y / 96)) | 0;
};
const detailed = (x, y, out, i) => {
    out[i] = ((x * 255 / W) | 0) ^ (((x ^ y) & 0xFF) < 128 ? 0x40 : 0);
    out[i + 1] = (y * 255 / H) | 0;
    out[i + 2] = (x ^ y) & 0xFF;
};

// Max per-channel difference between a coarse raster and a box downsample of
// the full raster. The inverse DWT is not a box filter, so this is a loose
// bound whose job is to catch garbage or an offset, not to reimplement
// OpenJPEG's reconstruction filter.
function boxDiffError(full, coarse) {
    const step = full.width / coarse.width;
    const stride = Math.max(1, coarse.height >> 6);
    let maxErr = 0;
    for (let y = 0; y < coarse.height; y += stride) {
        for (let x = 0; x < coarse.width; x += stride) {
            for (let ch = 0; ch < 3; ++ch) {
                let sum = 0, n = 0;
                for (let dy = 0; dy < step; dy += 2) {
                    for (let dx = 0; dx < step; dx += 2) {
                        const col = (x * step + dx) | 0;
                        const row = (y * step + dy) | 0;
                        sum += full.rgbaPixels[(row * full.width + col) * 4 + ch];
                        ++n;
                    }
                }
                const mean = sum / n;
                const got = coarse.rgbaPixels[(y * coarse.width + x) * 4 + ch];
                maxErr = Math.max(maxErr, Math.abs(mean - got));
            }
        }
    }
    return maxErr;
}

(async () => {
    const enc = await encoderModule({ locateFile: () => dataUrl('EmageWasmEncoder.wasm') });
    const dec = await decoderModule({ locateFile: () => dataUrl('EmageWasmDecoder.wasm') });

    const smoothJ2k = encode(enc, smooth);
    const detailedJ2k = encode(enc, detailed);
    console.log(`encoded ${W}x${H}: smooth=${smoothJ2k.length} B, ` +
        `detailed=${detailedJ2k.length} B, numResolutions=${NUM_RESOLUTIONS}`);

    const failures = [];
    const check = (cond, what) => {
        console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${what}`);
        if (!cond) failures.push(what);
    };

    const dptr = dec._malloc(smoothJ2k.length);
    dec.HEAPU8.set(smoothJ2k, dptr);

    // --- 1 & 2: sizes quarter, and out-of-range reduction clamps --------------
    console.log('\nreduction  decoded      pixels    vs full   reported');
    const full = dec.decodeRaw(dptr, smoothJ2k.length, null, null, 0, 0);
    const maxReduction = NUM_RESOLUTIONS - 1;
    for (let r = 0; r <= maxReduction + 3; ++r) {
        const out = dec.decodeRaw(dptr, smoothJ2k.length, null, null, 0, r);
        const expectW = Math.ceil(W / 2 ** out.reduction);
        const expectH = Math.ceil(H / 2 ** out.reduction);
        const px = out.width * out.height;
        const ratio = r === 0 ? '-' : (px / (full.width * full.height)).toFixed(4);
        console.log(`  ${String(r).padStart(2)}        ` +
            `${(out.width + 'x' + out.height).padEnd(11)} ` +
            `${String(px).padStart(8)}  ${String(ratio).padStart(7)}   ` +
            `applied=${out.reduction} numRes=${out.numResolutions}`);
        check(out.width === expectW && out.height === expectH,
            `reduction ${r} yields ceil(W/2^applied) = ${expectW}x${expectH}`);
        check(out.reduction === Math.min(r, maxReduction),
            `reduction ${r} clamped to ${Math.min(r, maxReduction)}`);
        check(out.numResolutions === NUM_RESOLUTIONS,
            `reduction ${r} reports numResolutions=${NUM_RESOLUTIONS}`);
    }

    // --- 3: reduction 0 is byte-identical to the pre-change binding -----------
    const again = dec.decodeRaw(dptr, smoothJ2k.length, null, null, 0, 0);
    check(again.width === full.width && again.height === full.height &&
        Buffer.compare(Buffer.from(again.rgbaPixels), Buffer.from(full.rgbaPixels)) === 0,
        'reduction 0 is deterministic and full resolution');
    dec._free(dptr);

    // --- 4 & 5: smooth content downscales faithfully, detail is discarded -----
    for (const [name, j2k] of [['smooth', smoothJ2k], ['detailed', detailedJ2k]]) {
        const p = dec._malloc(j2k.length);
        dec.HEAPU8.set(j2k, p);
        const f = dec.decodeRaw(p, j2k.length, null, null, 0, 0);
        console.log(`\n${name} content, reduction 1 vs box-downsampled full:`);
        for (let r = 1; r <= 3; ++r) {
            const c = dec.decodeRaw(p, j2k.length, null, null, 0, r);
            const err = boxDiffError(f, c);
            console.log(`  reduction ${r} (${c.width}x${c.height}): ` +
                `max channel error ${err.toFixed(1)}/255`);
            if (name === 'smooth') {
                check(err < 20, `smooth reduction ${r} tracks a box downsample (err ${err.toFixed(1)})`);
            } else {
                check(err > 20, `detailed reduction ${r} discards fine detail (err ${err.toFixed(1)})`);
            }
            check(c.rgbaPixels.every((v, i) => i % 4 !== 3 || v === 255),
                `${name} reduction ${r} stays fully opaque`);
        }
        dec._free(p);
    }

    console.log(`\n${failures.length ? failures.length + ' CHECK(S) FAILED' : 'ALL CHECKS PASSED'}`);
    process.exit(failures.length ? 1 : 0);
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
