const axios = require('axios');

/**
 * Search using Google Custom Search API
 */
async function googleSearch(query) {
    const apiKey = process.env.GOOGLE_CSE_API_KEY;
    const cx = process.env.GOOGLE_CSE_CX;

    if (!apiKey || !cx) {
        return {
            query,
            results: [],
            available: false,
            message: 'Google CSE not configured. Add GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX to .env',
            manualUrl: `https://www.google.com/search?q=${encodeURIComponent(query)}`,
            timestamp: new Date().toISOString(),
        };
    }

    try {
        const res = await axios.get('https://www.googleapis.com/customsearch/v1', {
            params: { key: apiKey, cx, q: query, num: 10 },
            timeout: 10000,
        });

        return {
            query,
            results: (res.data.items || []).map(item => ({
                title: item.title,
                link: item.link,
                snippet: item.snippet,
                displayLink: item.displayLink,
            })),
            available: true,
            totalResults: res.data.searchInformation?.totalResults,
            timestamp: new Date().toISOString(),
        };
    } catch (err) {
        return { query, results: [], available: false, error: err.message };
    }
}

/**
 * Shodan host lookup
 */
async function shodanLookup(ip) {
    const apiKey = process.env.SHODAN_API_KEY;

    if (!apiKey) {
        return {
            ip,
            available: false,
            message: 'Shodan API not configured. Add SHODAN_API_KEY to .env',
            manualUrl: `https://www.shodan.io/host/${ip}`,
            timestamp: new Date().toISOString(),
        };
    }

    try {
        const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
            params: { key: apiKey },
            timeout: 15000,
        });

        return {
            ip,
            available: true,
            hostnames: res.data.hostnames || [],
            os: res.data.os,
            ports: res.data.ports || [],
            org: res.data.org,
            isp: res.data.isp,
            country: res.data.country_name,
            city: res.data.city,
            vulns: res.data.vulns || [],
            services: (res.data.data || []).map(svc => ({
                port: svc.port,
                transport: svc.transport,
                product: svc.product,
                version: svc.version,
                banner: (svc.data || '').substring(0, 200),
            })),
            timestamp: new Date().toISOString(),
        };
    } catch (err) {
        return { ip, available: false, error: err.message };
    }
}

/**
 * Discover email patterns for a domain using free tools
 */
async function searchEmails(domain) {
    const results = {
        domain,
        patterns: [],
        found: [],
        timestamp: new Date().toISOString(),
    };

    // Common email patterns
    const commonPatterns = [
        'info', 'admin', 'support', 'contact', 'hello', 'sales',
        'help', 'webmaster', 'postmaster', 'abuse', 'security',
        'hr', 'careers', 'press', 'media', 'marketing',
    ];

    results.patterns = commonPatterns.map(p => `${p}@${domain}`);

    // Provide manual search links
    results.manualSearchLinks = [
        { name: 'Hunter.io', url: `https://hunter.io/search/${domain}` },
        { name: 'Google Email Search', url: `https://www.google.com/search?q=${encodeURIComponent('"@' + domain + '"')}` },
        { name: 'Phonebook.cz', url: `https://phonebook.cz/search?query=${domain}` },
    ];

    return results;
}

/**
 * Shodan search for a domain (DNS lookup + host info)
 */
async function shodanDomainLookup(domain) {
    const dns = require('dns').promises;

    try {
        const ips = await dns.resolve4(domain);
        if (ips.length > 0) {
            const shodanResults = [];
            for (const ip of ips.slice(0, 3)) {
                const result = await shodanLookup(ip);
                shodanResults.push(result);
            }
            return { domain, ips, shodanResults, timestamp: new Date().toISOString() };
        }
    } catch {
        // DNS resolution failed
    }

    return {
        domain,
        ips: [],
        shodanResults: [],
        manualUrl: `https://www.shodan.io/search?query=${encodeURIComponent(domain)}`,
        timestamp: new Date().toISOString(),
    };
}

module.exports = { googleSearch, shodanLookup, shodanDomainLookup, searchEmails };
