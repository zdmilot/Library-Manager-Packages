#!/usr/bin/env node
/**
 * build-catalog.js
 *
 * Scans every .hxlibpkg file in packages/ and writes catalog.json
 * with the metadata needed by the Library Manager store UI.
 *
 * The .hxlibpkg format wraps a ZIP in a binary container envelope.
 * Container layout:
 *   [8-byte magic] [4-byte LE payload length] [ZIP payload] [optional signature block]
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

/* ── Container unpacking (mirrors lib/shared.js logic) ────────────── */

const crypto = require('crypto');

const CONTAINER_MAGIC_PKG = Buffer.from([0x48, 0x58, 0x4C, 0x50, 0x4B, 0x47, 0x01, 0x00]);

const CONTAINER_SCRAMBLE_KEY = Buffer.from([
    0x7A, 0x3F, 0xC1, 0xD8, 0x4E, 0x92, 0xB5, 0x16,
    0xA3, 0x0D, 0xE7, 0x68, 0xF4, 0x2C, 0x59, 0x8B,
    0x31, 0xCA, 0x75, 0x0E, 0x96, 0xAF, 0xD2, 0x43,
    0xBC, 0x1A, 0x67, 0xE0, 0x58, 0x84, 0x3B, 0xF9
]);

const CONTAINER_HEADER_SIZE = 48;
const PKG_SIGNING_KEY = 'VenusLibMgr::PackageIntegrity::a7e3f9d1c6b2';

function unpackContainer(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < CONTAINER_HEADER_SIZE) {
        throw new Error('File too small or not a valid container');
    }
    if (buf.compare(CONTAINER_MAGIC_PKG, 0, 8, 0, 8) !== 0) {
        throw new Error('Bad magic number');
    }
    const payloadLen = buf.readUInt32LE(12);
    const storedHmac = buf.slice(16, CONTAINER_HEADER_SIZE);

    if (buf.length < CONTAINER_HEADER_SIZE + payloadLen) {
        throw new Error('Truncated payload');
    }

    const scrambled = buf.slice(CONTAINER_HEADER_SIZE, CONTAINER_HEADER_SIZE + payloadLen);

    // Verify HMAC
    const computedHmac = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(scrambled).digest();
    if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
        throw new Error('HMAC verification failed');
    }

    // De-scramble XOR to recover ZIP
    const zipBuffer = Buffer.alloc(scrambled.length);
    for (let i = 0; i < scrambled.length; i++) {
        zipBuffer[i] = scrambled[i] ^ CONTAINER_SCRAMBLE_KEY[i % CONTAINER_SCRAMBLE_KEY.length];
    }
    return zipBuffer;
}

/* ── Main ─────────────────────────────────────────────────────────── */

const pkgDir     = path.join(__dirname, 'packages');
const catalogOut = path.join(__dirname, 'catalog.json');

if (!fs.existsSync(pkgDir)) {
    fs.mkdirSync(pkgDir, { recursive: true });
}

const files = fs.readdirSync(pkgDir).filter(f => f.toLowerCase().endsWith('.hxlibpkg'));
const catalog = [];

for (const file of files) {
    const filePath = path.join(pkgDir, file);
    try {
        const raw    = fs.readFileSync(filePath);
        const zipBuf = unpackContainer(raw);
        const zip    = new AdmZip(zipBuf);
        const entry  = zip.getEntry('manifest.json');
        if (!entry) { console.warn(`SKIP ${file}: no manifest.json`); continue; }

        const m = JSON.parse(zip.readAsText(entry));
        catalog.push({
            package_file:         file,
            library_name:         m.library_name  || '',
            author:               m.author        || '',
            organization:         m.organization  || '',
            version:              m.version       || '',
            description:          m.description   || '',
            tags:                 m.tags           || [],
            venus_compatibility:  m.venus_compatibility || '',
            github_url:           m.github_url    || '',
            created_date:         m.created_date  || '',
            library_image_base64: m.library_image_base64 || '',
            library_image_mime:   m.library_image_mime   || ''
        });
        console.log(`OK  ${file}  →  ${m.library_name} v${m.version}`);
    } catch (err) {
        console.error(`ERR ${file}: ${err.message}`);
    }
}

catalog.sort((a, b) => a.library_name.localeCompare(b.library_name));
fs.writeFileSync(catalogOut, JSON.stringify(catalog, null, 2));
console.log(`\nWrote catalog.json with ${catalog.length} package(s).`);
