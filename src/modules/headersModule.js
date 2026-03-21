/**
 * HTTP Security Headers Audit Module
 * Fetches target URL and scores the response security headers.
 */
const https = require('https');
const http = require('http');

const SECURITY_HEADERS = [
    {
        name: 'Strict-Transport-Security',
        key: 'strict-transport-security',
        weight: 20,
        description: 'Forces HTTPS connections, preventing downgrade attacks',
        remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    {
        name: 'Content-Security-Policy',
        key: 'content-security-policy',
        weight: 20,
        description: 'Prevents XSS, clickjacking, and code injection attacks',
        remediation: "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    {
        name: 'X-Frame-Options',
        key: 'x-frame-options',
        weight: 10,
        description: 'Prevents clickjacking by controlling iframe embedding',
        remediation: 'Add header: X-Frame-Options: DENY',
    },
    {
        name: 'X-Content-Type-Options',
        key: 'x-content-type-options',
        weight: 10,
        description: 'Prevents MIME type sniffing attacks',
        remediation: 'Add header: X-Content-Type-Options: nosniff',
    },
    {
        name: 'Referrer-Policy',
        key: 'referrer-policy',
        weight: 10,
        description: 'Controls how much referrer info is sent with requests',
        remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
    },
    {
        name: 'Permissions-Policy',
        key: 'permissions-policy',
        weight: 10,
        description: 'Controls access to browser features (camera, mic, geolocation)',
        remediation: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
    {
        name: 'X-XSS-Protection',
        key: 'x-xss-protection',
        weight: 5,
        description: 'Legacy XSS filter (modern browsers use CSP instead)',
        remediation: 'Add header: X-XSS-Protection: 1; mode=block',
    },
    {
        name: 'X-Permitted-Cross-Domain-Policies',
        key: 'x-permitted-cross-domain-policies',
        weight: 5,
        description: 'Restricts Adobe Flash/PDF cross-domain data loading',
        remediation: 'Add header: X-Permitted-Cross-Domain-Policies: none',
    },
    {
        name: 'Cross-Origin-Opener-Policy',
        key: 'cross-origin-opener-policy',
        weight: 5,
        description: 'Isolates browsing context from cross-origin documents',
        remediation: 'Add header: Cross-Origin-Opener-Policy: same-origin',
    },
    {
        name: 'Cross-Origin-Resource-Policy',
        key: 'cross-origin-resource-policy',
        weight: 5,
        description: 'Prevents cross-origin reads of resources',
        remediation: 'Add header: Cross-Origin-Resource-Policy: same-origin',
    },
];

/**
 * Audit security headers for a domain
 */
async function auditHeaders(domain) {
    const result = {
        url: `https://${domain}`,
        grade: 'F',
        score: 0,
        totalWeight: 0,
        earnedWeight: 0,
        headers: {},
        checks: [],
        serverInfo: {},
        missingCount: 0,
        presentCount: 0,
    };

    try {
        const response = await fetchHeaders(domain);
        result.headers = response.headers;
        result.serverInfo = {
            server: response.headers['server'] || 'Not disclosed',
            poweredBy: response.headers['x-powered-by'] || 'Not disclosed',
            statusCode: response.statusCode,
        };

        // Check each security header
        for (const header of SECURITY_HEADERS) {
            const value = response.headers[header.key];
            const present = !!value;

            result.totalWeight += header.weight;

            const check = {
                name: header.name,
                present,
                value: value || null,
                weight: header.weight,
                description: header.description,
                remediation: present ? null : header.remediation,
            };

            if (present) {
                result.earnedWeight += header.weight;
                result.presentCount++;
            } else {
                result.missingCount++;
            }

            result.checks.push(check);
        }

        // Calculate score
        result.score = Math.round((result.earnedWeight / result.totalWeight) * 100);

        // Assign grade
        if (result.score >= 90) result.grade = 'A+';
        else if (result.score >= 80) result.grade = 'A';
        else if (result.score >= 70) result.grade = 'B';
        else if (result.score >= 55) result.grade = 'C';
        else if (result.score >= 40) result.grade = 'D';
        else result.grade = 'F';

        // Bonus: check for info disclosure
        if (response.headers['server']) {
            result.checks.push({
                name: 'Server Version Hidden',
                present: false,
                value: response.headers['server'],
                weight: 0,
                description: 'Server version disclosure aids attackers in finding known exploits',
                remediation: 'Remove or obfuscate the Server header',
                info: true,
            });
        }

    } catch (err) {
        result.error = err.message;
    }

    return result;
}

/**
 * Fetch headers from a domain (follow redirects)
 */
function fetchHeaders(domain, redirects = 0) {
    return new Promise((resolve, reject) => {
        if (redirects > 5) return reject(new Error('Too many redirects'));

        const url = redirects === 0 ? `https://${domain}` : domain;
        const client = url.startsWith('https') ? https : http;

        const req = client.get(url, { timeout: 10000, headers: { 'User-Agent': 'ARGUS-OSINT/2.0' } }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                return fetchHeaders(res.headers.location, redirects + 1).then(resolve).catch(reject);
            }
            resolve({ headers: res.headers, statusCode: res.statusCode });
            res.resume(); // discard body
        });

        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    });
}

module.exports = { auditHeaders };
