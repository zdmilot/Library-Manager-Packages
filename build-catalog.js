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

/**
 * Derive library name from a package filename by stripping the
 * trailing _v{version}.hxlibpkg portion.
 * E.g. "HSLAppsLib_v1.7.hxlibpkg" → "HSLAppsLib"
 */
function libNameFromFilename(filename) {
    const m = filename.match(/^(.+?)_v[\d.]+\.hxlibpkg$/i);
    return m ? m[1] : filename.replace(/\.hxlibpkg$/i, '');
}

/**
 * Collect .hxlibpkg files from library subdirectories under packages/.
 * Structure:  packages/<LibraryName>/<file>.hxlibpkg
 *
 * If a .hxlibpkg file is found loose in the packages/ root, it is
 * automatically moved into a subdirectory named after the library
 * (derived from the filename) so it is cataloged correctly.
 */
function collectPackageFiles() {
    const results = [];
    const entries = fs.readdirSync(pkgDir, { withFileTypes: true });

    for (const ent of entries) {
        if (ent.isDirectory()) {
            // Scan subdirectory for .hxlibpkg files
            const subDir = path.join(pkgDir, ent.name);
            const subFiles = fs.readdirSync(subDir).filter(f => f.toLowerCase().endsWith('.hxlibpkg'));
            for (const f of subFiles) {
                results.push({ dir: ent.name, file: f, filePath: path.join(subDir, f) });
            }
        } else if (ent.name.toLowerCase().endsWith('.hxlibpkg')) {
            // Auto-organize: move flat file into a library subdirectory
            const libDir = libNameFromFilename(ent.name);
            const destDir = path.join(pkgDir, libDir);
            if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
            const src = path.join(pkgDir, ent.name);
            const dest = path.join(destDir, ent.name);
            fs.renameSync(src, dest);
            console.log(`MOVE ${ent.name}  →  ${libDir}/${ent.name}`);
            results.push({ dir: libDir, file: ent.name, filePath: dest });
        }
    }
    return results;
}

/**
 * Compare two version strings.  Returns positive if a > b, negative if a < b, 0 if equal.
 * Handles dotted numeric versions (e.g. "1.8.4" vs "1.10.0").
 */
function compareVersions(a, b) {
    const pa = String(a).split('.').map(Number);
    const pb = String(b).split('.').map(Number);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const na = pa[i] || 0;
        const nb = pb[i] || 0;
        if (na !== nb) return na - nb;
    }
    return 0;
}

const pkgFiles = collectPackageFiles();

// Collect all version entries grouped by library_name
const libraryMap = new Map(); // library_name → array of version entries

for (const { dir, file, filePath: fp } of pkgFiles) {
    try {
        const raw    = fs.readFileSync(fp);
        const zipBuf = unpackContainer(raw);
        const zip    = new AdmZip(zipBuf);
        const entry  = zip.getEntry('manifest.json');
        if (!entry) { console.warn(`SKIP ${file}: no manifest.json`); continue; }

        const m = JSON.parse(zip.readAsText(entry));
        // Use subdirectory name as grouping key when available, so that
        // multiple versions with divergent manifest library_name values
        // (e.g. "HSLAppsLib", "HSLAppsLib_V1_6") are treated as one library.
        const libName = dir || m.library_name || '';
        const version = m.version      || '';

        // Auto-detect .chm help files from library_files
        const rawLibFiles = m.library_files || [];
        const declaredHelp = m.help_files || [];
        const helpFiles = declaredHelp.slice();
        const libraryFiles = [];
        rawLibFiles.forEach(f => {
            if (path.extname(f).toLowerCase() === '.chm') {
                if (helpFiles.indexOf(f) === -1) helpFiles.push(f);
            } else {
                libraryFiles.push(f);
            }
        });

        const versionEntry = {
            package_file:          file,
            version:               version,
            author:                m.author             || '',
            organization:          m.organization       || '',
            description:           m.description        || '',
            tags:                  m.tags               || [],
            venus_compatibility:   m.venus_compatibility || '',
            github_url:            m.github_url         || '',
            created_date:          m.created_date       || '',
            library_files:         libraryFiles,
            demo_method_files:     m.demo_method_files  || [],
            help_files:            helpFiles,
            bin_files:             m.bin_files           || [],
            labware_files:         m.labware_files       || [],
            com_register_dlls:     m.com_register_dlls   || [],
            install_to_library_root: !!m.install_to_library_root,
            custom_install_subdir: m.custom_install_subdir || '',
            dependencies:          m.dependencies        || [],
            library_image_base64:  m.library_image_base64 || '',
            library_image_mime:    m.library_image_mime   || ''
        };

        if (!libraryMap.has(libName)) libraryMap.set(libName, []);
        libraryMap.get(libName).push(versionEntry);

        const displayPath = dir ? `${dir}/${file}` : file;
        console.log(`OK  ${displayPath}  →  ${libName} v${version}`);
    } catch (err) {
        const displayPath = dir ? `${dir}/${file}` : file;
        console.error(`ERR ${displayPath}: ${err.message}`);
    }
}

// Build catalog: one entry per library with all versions included
const catalog = [];
for (const [libName, versions] of libraryMap) {
    // Sort versions newest first
    versions.sort((a, b) => compareVersions(b.version, a.version));
    const latest = versions[0];

    const catalogEntry = {
        library_name:          libName,
        package_file:          latest.package_file,
        version:               latest.version,
        author:                latest.author,
        organization:          latest.organization,
        description:           latest.description,
        tags:                  latest.tags,
        venus_compatibility:   latest.venus_compatibility,
        github_url:            latest.github_url,
        created_date:          latest.created_date,
        library_image_base64:  latest.library_image_base64,
        library_image_mime:    latest.library_image_mime,
        library_files:         latest.library_files,
        demo_method_files:     latest.demo_method_files,
        help_files:            latest.help_files,
        bin_files:             latest.bin_files,
        labware_files:         latest.labware_files,
        com_register_dlls:     latest.com_register_dlls,
        install_to_library_root: latest.install_to_library_root,
        custom_install_subdir: latest.custom_install_subdir,
        dependencies:          latest.dependencies,
        versions:              versions.map(v => ({
            version:               v.version,
            package_file:          v.package_file,
            created_date:          v.created_date,
            author:                v.author,
            organization:          v.organization,
            description:           v.description,
            tags:                  v.tags,
            venus_compatibility:   v.venus_compatibility,
            github_url:            v.github_url,
            library_files:         v.library_files,
            demo_method_files:     v.demo_method_files,
            help_files:            v.help_files,
            bin_files:             v.bin_files,
            labware_files:         v.labware_files,
            com_register_dlls:     v.com_register_dlls,
            install_to_library_root: v.install_to_library_root,
            custom_install_subdir: v.custom_install_subdir,
            dependencies:          v.dependencies
        }))
    };

    catalog.push(catalogEntry);
    const verList = versions.map(v => 'v' + v.version).join(', ');
    console.log(`  ${libName}: ${versions.length} version(s) [${verList}]`);
}

catalog.sort((a, b) => a.library_name.localeCompare(b.library_name));
fs.writeFileSync(catalogOut, JSON.stringify(catalog, null, 2));
console.log(`\nWrote catalog.json with ${catalog.length} librar${catalog.length !== 1 ? 'ies' : 'y'}.`);
