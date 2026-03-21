/**
 * Technology Stack Detection Module
 * Wappalyzer-style fingerprinting using HTML + HTTP header analysis.
 */
const https = require('https');
const http = require('http');

// Technology signatures database
const TECH_SIGNATURES = [
    // CMS
    { name: 'WordPress', category: 'CMS', patterns: { html: [/wp-content/i, /wp-includes/i, /wp-json/i], headers: { 'x-powered-by': /WordPress/i }, meta: { generator: /WordPress/i } } },
    { name: 'Drupal', category: 'CMS', patterns: { html: [/Drupal\.settings/i, /sites\/default\/files/i], headers: { 'x-generator': /Drupal/i, 'x-drupal-cache': /./ } } },
    { name: 'Joomla', category: 'CMS', patterns: { html: [/\/templates\/.*\/css/i, /\/media\/jui/i], meta: { generator: /Joomla/i } } },
    { name: 'Shopify', category: 'E-Commerce', patterns: { html: [/cdn\.shopify\.com/i, /Shopify\.theme/i], headers: { 'x-shopify-stage': /./ } } },
    { name: 'Squarespace', category: 'CMS', patterns: { html: [/squarespace\.com/i, /static\.squarespace/i] } },
    { name: 'Wix', category: 'CMS', patterns: { html: [/wix\.com/i, /wixstatic\.com/i, /X-Wix/i] } },
    { name: 'Ghost', category: 'CMS', patterns: { html: [/ghost-/i], meta: { generator: /Ghost/i } } },

    // Frameworks
    { name: 'React', category: 'JS Framework', patterns: { html: [/__NEXT_DATA__/i, /react-root/i, /_reactRootContainer/i, /data-reactroot/i, /react\.production/i] } },
    { name: 'Next.js', category: 'JS Framework', patterns: { html: [/__NEXT_DATA__/i, /_next\/static/i, /next\/dist/i], headers: { 'x-powered-by': /Next\.js/i } } },
    { name: 'Vue.js', category: 'JS Framework', patterns: { html: [/vue\.runtime/i, /v-cloak/i, /data-v-[a-f0-9]/i, /vue\.js/i] } },
    { name: 'Nuxt.js', category: 'JS Framework', patterns: { html: [/__NUXT__/i, /_nuxt\//i] } },
    { name: 'Angular', category: 'JS Framework', patterns: { html: [/ng-app/i, /ng-version/i, /angular\.js/i, /zone\.js/i] } },
    { name: 'Svelte', category: 'JS Framework', patterns: { html: [/svelte-/i, /__svelte/i] } },
    { name: 'jQuery', category: 'JS Library', patterns: { html: [/jquery[.-][\d]/i, /jquery\.min\.js/i] } },
    { name: 'Bootstrap', category: 'CSS Framework', patterns: { html: [/bootstrap\.min\.css/i, /bootstrap\.min\.js/i, /bootstrap\.bundle/i] } },
    { name: 'Tailwind CSS', category: 'CSS Framework', patterns: { html: [/tailwindcss/i, /tailwind\.min\.css/i, /class="[^"]*\b(flex|grid|bg-|text-|p-\d|m-\d|rounded)/i] } },

    // Servers
    { name: 'nginx', category: 'Web Server', patterns: { headers: { 'server': /nginx/i } } },
    { name: 'Apache', category: 'Web Server', patterns: { headers: { 'server': /Apache/i } } },
    { name: 'IIS', category: 'Web Server', patterns: { headers: { 'server': /Microsoft-IIS/i } } },
    { name: 'LiteSpeed', category: 'Web Server', patterns: { headers: { 'server': /LiteSpeed/i } } },
    { name: 'Caddy', category: 'Web Server', patterns: { headers: { 'server': /Caddy/i } } },

    // CDN / Infrastructure
    { name: 'Cloudflare', category: 'CDN', patterns: { headers: { 'server': /cloudflare/i, 'cf-ray': /./ } } },
    { name: 'AWS CloudFront', category: 'CDN', patterns: { headers: { 'x-amz-cf-id': /./, 'via': /CloudFront/i, 'server': /CloudFront/i } } },
    { name: 'Fastly', category: 'CDN', patterns: { headers: { 'x-served-by': /cache/i, 'via': /varnish/i, 'x-fastly-request-id': /./ } } },
    { name: 'Akamai', category: 'CDN', patterns: { headers: { 'x-akamai': /./, 'server': /AkamaiGHost/i } } },
    { name: 'Vercel', category: 'Hosting', patterns: { headers: { 'x-vercel-id': /./, 'server': /Vercel/i } } },
    { name: 'Netlify', category: 'Hosting', patterns: { headers: { 'x-nf-request-id': /./, 'server': /Netlify/i } } },

    // Analytics & Marketing
    { name: 'Google Analytics', category: 'Analytics', patterns: { html: [/google-analytics\.com\/analytics/i, /googletagmanager\.com/i, /gtag\(/i, /UA-\d+-\d+/i, /G-[A-Z0-9]+/i] } },
    { name: 'Google Tag Manager', category: 'Analytics', patterns: { html: [/googletagmanager\.com\/gtm/i, /GTM-[A-Z0-9]+/i] } },
    { name: 'Facebook Pixel', category: 'Analytics', patterns: { html: [/connect\.facebook\.net/i, /fbq\(/i, /facebook\.com\/tr/i] } },
    { name: 'Hotjar', category: 'Analytics', patterns: { html: [/hotjar\.com/i, /hj\(.*identify/i] } },

    // Security
    { name: 'reCAPTCHA', category: 'Security', patterns: { html: [/recaptcha/i, /google\.com\/recaptcha/i] } },
    { name: 'hCaptcha', category: 'Security', patterns: { html: [/hcaptcha\.com/i, /h-captcha/i] } },

    // Languages
    { name: 'PHP', category: 'Language', patterns: { headers: { 'x-powered-by': /PHP/i } } },
    { name: 'ASP.NET', category: 'Language', patterns: { headers: { 'x-powered-by': /ASP\.NET/i, 'x-aspnet-version': /./ } } },
    { name: 'Express.js', category: 'Language', patterns: { headers: { 'x-powered-by': /Express/i } } },
];

/**
 * Detect technologies used by a domain
 */
async function detectTech(domain) {
    const result = {
        detected: [],
        categories: {},
        totalDetected: 0,
    };

    try {
        const response = await fetchPage(domain);
        const { html, headers } = response;

        // Extract meta tags
        const metaTags = {};
        const metaRegex = /<meta[^>]+name=["']([^"']+)["'][^>]+content=["']([^"']+)["'][^>]*>/gi;
        let match;
        while ((match = metaRegex.exec(html)) !== null) {
            metaTags[match[1].toLowerCase()] = match[2];
        }

        // Test each signature
        for (const tech of TECH_SIGNATURES) {
            let detected = false;

            // Check HTML patterns
            if (tech.patterns.html) {
                for (const pattern of tech.patterns.html) {
                    if (pattern.test(html)) {
                        detected = true;
                        break;
                    }
                }
            }

            // Check headers
            if (!detected && tech.patterns.headers) {
                for (const [headerKey, pattern] of Object.entries(tech.patterns.headers)) {
                    const headerValue = headers[headerKey];
                    if (headerValue && pattern.test(headerValue)) {
                        detected = true;
                        break;
                    }
                }
            }

            // Check meta tags
            if (!detected && tech.patterns.meta) {
                for (const [metaKey, pattern] of Object.entries(tech.patterns.meta)) {
                    const metaValue = metaTags[metaKey.toLowerCase()];
                    if (metaValue && pattern.test(metaValue)) {
                        detected = true;
                        break;
                    }
                }
            }

            if (detected) {
                const entry = { name: tech.name, category: tech.category };
                result.detected.push(entry);

                if (!result.categories[tech.category]) {
                    result.categories[tech.category] = [];
                }
                result.categories[tech.category].push(tech.name);
            }
        }

        result.totalDetected = result.detected.length;

    } catch (err) {
        result.error = err.message;
    }

    return result;
}

/**
 * Fetch page HTML and headers
 */
function fetchPage(domain, redirects = 0) {
    return new Promise((resolve, reject) => {
        if (redirects > 5) return reject(new Error('Too many redirects'));

        const url = redirects === 0 ? `https://${domain}` : domain;
        const client = url.startsWith('https') ? https : http;

        const req = client.get(url, {
            timeout: 15000,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
        }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                return fetchPage(res.headers.location, redirects + 1).then(resolve).catch(reject);
            }

            let data = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { 
                data += chunk; 
                if (data.length > 500000) {
                    resolve({ html: data, headers: res.headers });
                    res.destroy(); 
                }
            });
            res.on('end', () => {
                if (!res.destroyed) resolve({ html: data, headers: res.headers });
            });
        });

        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    });
}

module.exports = { detectTech };
