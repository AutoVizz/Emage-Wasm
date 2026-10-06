// MAC integrity verification, and the server-byte-arithmetic property that the
// cumulative chain has to survive.
const path = require('path');
const fs = require('fs');
const B = path.join(__dirname, 'cmake-build-wasm');
const encM = require('./cmake-build-wasm/EmageWasmEncoder.js');
const decM = require('./cmake-build-wasm/EmageWasmDecoder.js');
const dataUrl = b => 'data:application/wasm;base64,' +
    fs.readFileSync(path.join(B, b)).toString('base64');

let failed = 0;
const check = (c, m) => { if (!c) failed++; console.log((c ? 'PASS  ' : 'FAIL  ') + m); };
const log = m => console.log('        ' + m);

(async () => {
    const encoder = await encM({ locateFile: () => dataUrl('EmageWasmEncoder.wasm') });
    const decoder = await decM({ locateFile: () => dataUrl('EmageWasmDecoder.wasm') });

    const W = 128, H = 96, RES = 6;
    const KEY = new Uint8Array(32).fill(0x5a);
    const IV = new Uint8Array(16).fill(0x3c);

    const px = new Uint8Array(W * H * 3);
    for (let i = 0; i < px.length; ++i) px[i] = (i * 13 + (i % 251)) & 0xff;

    const encP = encoder._malloc(px.length);
    encoder.HEAPU8.set(px, encP);
    const stream = encoder.encodeRaw(encP, px.length, {
        width: W, height: H, numComponents: 3, precision: 8, lossless: true,
        numResolutions: RES, numLayers: 1, enablePterm: false, enableSegsym: false,
        enableSop: false, enableEph: false, enableTlm: false, enableSec: true,
        key: KEY, iv: IV,
    });
    encoder._free(encP);
    const j2k = Buffer.from(stream);
    log(`encoded ${j2k.length} bytes, ${RES} levels`);

    const inspect = (buf) => {
        const p = decoder._malloc(buf.length);
        decoder.HEAPU8.set(buf, p);
        const z = decoder.describeSecurityZone(p, buf.length);
        const r = {
            hasSec: z.hasSec, zoneCount: z.zoneCount,
            starts: Array.from(z.starts || []), sizes: Array.from(z.sizes || []),
            macs: z.macs ? Array.from(z.macs) : null,
            iv: z.iv ? Array.from(z.iv) : null,
        };
        decoder._free(p);
        return r;
    };
    const decode = (buf, accessLevel) => {
        const p = decoder._malloc(buf.length);
        decoder.HEAPU8.set(buf, p);
        try {
            const d = decoder.decodeRaw(p, buf.length, KEY, IV, accessLevel, 0);
            return { w: d.width, h: d.height, r: d.reduction };
        } finally { decoder._free(p); }
    };

    // ---- 1. the marker carries the IV and one MAC per level ----------------
    const z = inspect(j2k);
    check(z.hasSec === 1, 'SEC marker recognised');
    check(z.zoneCount === RES, `zone count == numResolutions (${z.zoneCount} vs ${RES})`);
    check(Array.isArray(z.iv) && z.iv.length === 16,
        `IV carried in the marker: ${Buffer.from(z.iv || []).toString('hex')}`);
    check(Buffer.from(z.iv || []).equals(Buffer.from(IV)),
        'marker IV equals the IV used to encrypt');
    check(Array.isArray(z.macs) && z.macs.length === RES * 32,
        `MAC table has ${RES} tags (${(z.macs || []).length} bytes)`);
    const macsDistinct = new Set();
    for (let i = 0; i < RES; ++i) macsDistinct.add(Buffer.from(z.macs.slice(i * 32, i * 32 + 32)).toString('hex'));
    check(macsDistinct.size === RES, 'every level carries a distinct cumulative MAC');

    // ---- 2. clean decode still works at every access level -----------------
    for (let a = 0; a < RES; ++a) {
        let d;
        try { d = decode(j2k, a); } catch (e) { check(false, `access ${a} decode threw: ${e.message || e}`); continue; }
        check(d.w > 0 && d.h > 0, `access ${a}: clean decode ${d.w}x${d.h} at reduction ${d.r}`);
    }

    // ---- 3. tampering with payload bytes is rejected -----------------------
    const payloadStart = (() => {
        const sod = j2k.indexOf(Buffer.from([0xff, 0x93]));
        return sod + 2;
    })();
    const tamper = (offset, what) => {
        const t = Buffer.from(j2k);
        t[offset] ^= 0x01;
        let threw = false, msg = '';
        try { decode(t, RES - 1); } catch (e) { threw = true; msg = (e && e.message) || String(e); }
        check(threw, `${what} -> rejected${threw ? ' (' + msg.slice(0, 72) + ')' : ''}`);
    };
    tamper(payloadStart + 2, 'flip a byte in the first zone');
    tamper(payloadStart + z.sizes[0], 'flip a byte just past zone 0');
    tamper(payloadStart + Math.floor(z.sizes[RES - 1] / 2),
        `flip a byte mid finest zone (size ${z.sizes[RES - 1]})`);

    // ---- 4. tampering with a MAC in the header is rejected ------------------
    const sec = j2k.indexOf(Buffer.from([0xff, 0x65]));
    const macBase = sec + 34 + RES * 10;
    const t2 = Buffer.from(j2k);
    t2[macBase + 5] ^= 0x01;
    let threw2 = false, msg2 = '';
    try { decode(t2, RES - 1); } catch (e) { threw2 = true; msg2 = (e && e.message) || String(e); }
    check(threw2, `flip a byte in the MAC table -> rejected${threw2 ? ' (' + msg2.slice(0, 72) + ')' : ''}`);

    // ---- 5. resizing a zone is rejected (MAC covers Z and T) ---------------
    const t3 = Buffer.from(j2k);
    t3.writeUInt32BE(z.sizes[RES - 1] + 4, sec + 34 + (RES - 1) * 10 + 6);
    let threw3 = false;
    try { decode(t3, RES - 1); } catch (e) { threw3 = true; }
    check(threw3, 'alter a zone T in the table -> rejected');

    // ---- 6. a shorter grant only verifies the levels it holds --------------
    let threw4 = false, msg4 = '';
    const t4 = Buffer.from(j2k);
    t4[payloadStart + Math.floor(z.sizes[RES - 1] / 2)] ^= 0x01;
    try { decode(t4, 0); } catch (e) { threw4 = true; msg4 = (e && e.message) || String(e); }
    check(!threw4,
        'corruption above the grant is NOT detected by a coarser grant ' +
        '(by design: a holder of K0..K0 cannot authenticate K1 data)');

    console.log(failed === 0 ? '\nRESULT: PASS' : `\nRESULT: FAIL (${failed})`);
    process.exit(failed === 0 ? 0 : 1);
})();