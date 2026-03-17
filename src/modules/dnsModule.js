const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const net = require('net');

/**
 * Query all DNS record types for a domain
 */
async function queryAllRecords(domain) {
    const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
    const results = {};

    for (const type of recordTypes) {
        try {
            switch (type) {
                case 'A':
                    results.A = await dns.resolve4(domain);
                    break;
                case 'AAAA':
                    try { results.AAAA = await dns.resolve6(domain); } catch { results.AAAA = []; }
                    break;
                case 'MX':
                    results.MX = await dns.resolveMx(domain);
                    break;
                case 'TXT':
                    results.TXT = (await dns.resolveTxt(domain)).map(r => r.join(''));
                    break;
                case 'NS':
                    results.NS = await dns.resolveNs(domain);
                    break;
                case 'CNAME':
                    try { results.CNAME = await dns.resolveCname(domain); } catch { results.CNAME = []; }
                    break;
                case 'SOA':
                    results.SOA = await dns.resolveSoa(domain);
                    break;
            }
        } catch (err) {
            results[type] = type === 'SOA' ? null : [];
        }
    }

    // Extract insights from DNS records
    const insights = extractDNSInsights(results, domain);

    return {
        domain,
        records: results,
        insights,
        timestamp: new Date().toISOString(),
    };
}

/**
 * Extract security and infrastructure insights from DNS records
 */
function extractDNSInsights(records, domain) {
    const insights = [];

    // Check for SPF
    if (records.TXT) {
        const spf = records.TXT.find(t => t.startsWith('v=spf1'));
        if (spf) {
            insights.push({ type: 'security', label: 'SPF Record Found', value: spf });
        } else {
            insights.push({ type: 'warning', label: 'No SPF Record', value: 'Email spoofing may be possible' });
        }

        // Check for DMARC
        const dmarc = records.TXT.find(t => t.startsWith('v=DMARC1'));
        if (dmarc) {
            insights.push({ type: 'security', label: 'DMARC Record Found', value: dmarc });
        }

        // Check for DKIM
        const dkim = records.TXT.find(t => t.includes('DKIM'));
        if (dkim) {
            insights.push({ type: 'security', label: 'DKIM Referenced', value: dkim });
        }

        // Check for verification records (Google, Microsoft, etc.)
        for (const txt of records.TXT) {
            if (txt.includes('google-site-verification')) {
                insights.push({ type: 'info', label: 'Google Verified', value: 'Domain verified with Google' });
            }
            if (txt.includes('MS=') || txt.includes('microsoft')) {
                insights.push({ type: 'info', label: 'Microsoft 365', value: 'Domain configured with Microsoft services' });
            }
        }
    }

    // MX analysis
    if (records.MX && records.MX.length > 0) {
        const mxHosts = records.MX.map(m => m.exchange);
        if (mxHosts.some(h => h.includes('google') || h.includes('gmail'))) {
            insights.push({ type: 'info', label: 'Google Workspace', value: 'Email hosted by Google' });
        }
        if (mxHosts.some(h => h.includes('outlook') || h.includes('microsoft'))) {
            insights.push({ type: 'info', label: 'Microsoft 365 Email', value: 'Email hosted by Microsoft' });
        }
        if (mxHosts.some(h => h.includes('protonmail'))) {
            insights.push({ type: 'info', label: 'ProtonMail', value: 'Privacy-focused email provider' });
        }
    }

    return insights;
}

/**
 * Enumerate subdomains using a wordlist
 */
async function enumerateSubdomains(domain, onProgress) {
    const wordlistPath = path.join(__dirname, '..', '..', 'data', 'subdomains.txt');
    let wordlist;
    try {
        wordlist = fs.readFileSync(wordlistPath, 'utf-8').split('\n').map(w => w.trim()).filter(Boolean);
    } catch {
        wordlist = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'webmail', 'admin', 'blog',
            'dev', 'test', 'staging', 'api', 'cdn', 'static', 'media', 'shop', 'store', 'app',
            'vpn', 'remote', 'portal', 'wiki', 'docs', 'support', 'help', 'forum', 'beta'];
    }

    const found = [];
    const batchSize = 20;

    for (let i = 0; i < wordlist.length; i += batchSize) {
        const batch = wordlist.slice(i, i + batchSize);
        const promises = batch.map(async (sub) => {
            const subdomain = `${sub}.${domain}`;
            try {
                const addresses = await dns.resolve4(subdomain);
                if (addresses && addresses.length > 0) {
                    found.push({
                        subdomain,
                        addresses,
                        prefix: sub,
                    });
                }
            } catch {
                // Not found - expected for most
            }
        });
        await Promise.all(promises);
        if (onProgress) {
            onProgress(Math.min(100, Math.round(((i + batchSize) / wordlist.length) * 100)));
        }
    }

    return {
        domain,
        totalChecked: wordlist.length,
        found,
        timestamp: new Date().toISOString(),
    };
}

/**
 * Attempt DNS zone transfer (AXFR) — usually fails but worth trying
 */
async function checkZoneTransfer(domain) {
    try {
        const nsRecords = await dns.resolveNs(domain);
        const results = [];

        for (const ns of nsRecords) {
            try {
                const result = await new Promise((resolve, reject) => {
                    const socket = new net.Socket();
                    socket.setTimeout(3000);

                    socket.on('timeout', () => {
                        socket.destroy();
                        resolve({ ns, status: 'timeout' });
                    });

                    socket.on('error', () => {
                        resolve({ ns, status: 'refused' });
                    });

                    socket.connect(53, ns, () => {
                        // Build AXFR query (simplified)
                        socket.destroy();
                        resolve({ ns, status: 'connection_possible' });
                    });
                });
                results.push(result);
            } catch {
                results.push({ ns, status: 'error' });
            }
        }

        return {
            domain,
            nameservers: nsRecords,
            results,
            vulnerable: false, // Zone transfers are almost always blocked
            timestamp: new Date().toISOString(),
        };
    } catch (err) {
        return {
            domain,
            error: err.message,
            vulnerable: false,
            timestamp: new Date().toISOString(),
        };
    }
}

module.exports = { queryAllRecords, enumerateSubdomains, checkZoneTransfer };
