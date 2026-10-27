const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '../..');
const modulesRoot = path.join(__dirname, 'node_modules');
const vendorRoot = path.join(projectRoot, 'static/vendor');
const licensesRoot = path.join(vendorRoot, 'licenses');
const fontsRoot = path.join(vendorRoot, 'fonts');
const fontFilesRoot = path.join(fontsRoot, 'files');

fs.mkdirSync(licensesRoot, { recursive: true });
fs.mkdirSync(fontFilesRoot, { recursive: true });

const assets = [
    {
        from: path.join(modulesRoot, 'socket.io-client/dist/socket.io.min.js'),
        to: path.join(vendorRoot, 'socket.io.min.js'),
    },
    {
        from: path.join(modulesRoot, 'lucide/dist/umd/lucide.min.js'),
        to: path.join(vendorRoot, 'lucide.min.js'),
    },
];

for (const asset of assets) {
    if (!fs.existsSync(asset.from)) {
        throw new Error(`Expected pinned UI dependency asset is missing: ${asset.from}`);
    }
    fs.copyFileSync(asset.from, asset.to);
}

function fontFaceRules(packageName, cssFiles, facePattern, familyName) {
    const packageRoot = path.join(modulesRoot, packageName);
    const rules = [];

    for (const cssFile of cssFiles) {
        const source = path.join(packageRoot, cssFile);
        if (!fs.existsSync(source)) {
            throw new Error(`Expected pinned font CSS is missing: ${source}`);
        }
        const css = fs.readFileSync(source, 'utf8');
        const faces = css.match(/\/\* [^*]+\*\/\s*@font-face\s*\{[^}]+\}/g) || [];
        for (const face of faces) {
            const label = (face.match(/^\/\*\s*([^*]+)\s*\*\//)?.[1] || '').trim();
            if (!facePattern.test(label)) continue;

            const fontNames = [...face.matchAll(/url\(\.\/files\/([^)]+)\)/g)]
                .map((match) => match[1])
                .filter((name) => name.endsWith('.woff2'));
            if (fontNames.length === 0) {
                throw new Error(`Expected WOFF2 source in ${packageName}/${cssFile}: ${label}`);
            }
            for (const fontName of fontNames) {
                const sourceFont = path.join(packageRoot, 'files', fontName);
                if (!fs.existsSync(sourceFont)) {
                    throw new Error(`Expected pinned font file is missing: ${sourceFont}`);
                }
                fs.copyFileSync(sourceFont, path.join(fontFilesRoot, fontName));
            }

            const localFace = face
                .replace(/,\s*url\(\.\/files\/[^)]+\.woff\)\s*format\('woff'\)/g, '')
                .replaceAll("font-family: 'Inter Variable'", `font-family: '${familyName}'`)
                .replaceAll('./files/', 'fonts/files/');
            rules.push(localFace);
        }
    }

    if (rules.length === 0) {
        throw new Error(`No expected font faces found for ${packageName}`);
    }
    return rules;
}

const bundledFontFaces = [
    ...fontFaceRules(
        '@fontsource-variable/inter',
        ['opsz.css', 'opsz-italic.css'],
        /^inter-latin(?:-ext)?-opsz-(?:normal|italic)$/,
        'Inter',
    ),
    ...fontFaceRules(
        '@fontsource/instrument-serif',
        ['400.css', '400-italic.css'],
        /^instrument-serif-latin(?:-ext)?-400-(?:normal|italic)$/,
        'Instrument Serif',
    ),
];
fs.writeFileSync(path.join(vendorRoot, 'fonts.css'), `${bundledFontFaces.join('\n\n')}\n`);

for (const packageName of ['lucide', 'socket.io-client', 'tailwindcss']) {
    const source = path.join(modulesRoot, packageName, 'LICENSE');
    if (!fs.existsSync(source)) {
        throw new Error(`Expected ${packageName} license file is missing: ${source}`);
    }
    fs.copyFileSync(source, path.join(licensesRoot, `${packageName}.LICENSE.txt`));
}

for (const packageName of ['@fontsource-variable/inter', '@fontsource/instrument-serif']) {
    const source = path.join(modulesRoot, packageName, 'LICENSE');
    if (!fs.existsSync(source)) {
        throw new Error(`Expected ${packageName} license file is missing: ${source}`);
    }
    const licenseName = packageName.replaceAll('/', '-');
    fs.copyFileSync(source, path.join(licensesRoot, `${licenseName}.LICENSE.txt`));
}
