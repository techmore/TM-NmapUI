const path = require('node:path');

const projectRoot = path.resolve(__dirname, '../..');

module.exports = {
    content: [
        path.join(projectRoot, 'templates/**/*.html'),
        path.join(projectRoot, 'static/js/**/*.js'),
        path.join(projectRoot, 'nmap-modern.xsl'),
        path.join(projectRoot, 'nmap-pdf-olive-legacy.xsl'),
    ],
    safelist: [
        // site_chrome.js interpolates these finite severity classes at runtime.
        'text-red-400',
        'text-zinc-400',
    ],
    theme: {
        extend: {
            colors: {
                olive: {
                    50: 'oklch(96% 0.015 110)',
                    100: 'oklch(91% 0.020 110)',
                    200: 'oklch(85% 0.028 110)',
                    300: 'oklch(75% 0.040 110)',
                    400: 'oklch(62% 0.055 110)',
                    500: 'oklch(50% 0.065 110)',
                    600: 'oklch(42% 0.055 110)',
                    700: 'oklch(35% 0.045 110)',
                    800: 'oklch(28% 0.035 110)',
                    900: 'oklch(22% 0.025 110)',
                    950: 'oklch(16% 0.015 110)',
                }
            },
            fontFamily: {
                display: ['Instrument Serif', 'serif'],
                sans: ['Inter', 'system-ui', 'sans-serif'],
            }
        }
    }
};
