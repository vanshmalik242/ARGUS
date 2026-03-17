const axios = require('axios');

/**
 * Check breaches for an email using free alternatives and redirecting to HIBP
 */
async function checkBreaches(email) {
    const results = {
        email,
        breaches: [],
        redirectUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
        sources: [],
        timestamp: new Date().toISOString(),
    };

    // 1. Try BreachDirectory API (free)
    try {
        const bdRes = await axios.get(`https://breachdirectory.p.rapidapi.com/`, {
            params: { func: 'auto', term: email },
            headers: {
                'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com',
                'X-RapidAPI-Key': process.env.RAPIDAPI_KEY || '',
            },
            timeout: 10000,
        });
        if (bdRes.data && bdRes.data.result) {
            results.sources.push('BreachDirectory');
            results.breaches.push(...(bdRes.data.result || []).map(b => ({
                source: 'BreachDirectory',
                hasPassword: b.has_password || false,
                sources: b.sources || [],
            })));
        }
    } catch {
        // Service unavailable without key
    }

    // 2. Try Mozilla Monitor / Firefox Monitor (free, unofficial)
    try {
        const hash = await sha1Hash(email.toLowerCase());
        const prefix = hash.substring(0, 6);
        const mRes = await axios.get(`https://monitor.firefox.com/api/v1/breaches`, {
            timeout: 10000,
        });
        if (mRes.data && Array.isArray(mRes.data)) {
            results.sources.push('MozillaMonitor');
            // Return known breaches database (doesn't check per-email without auth)
            results.knownBreaches = mRes.data.slice(0, 20).map(b => ({
                name: b.Name,
                title: b.Title,
                domain: b.Domain,
                breachDate: b.BreachDate,
                addedDate: b.AddedDate,
                pwnCount: b.PwnCount,
                dataClasses: b.DataClasses,
                description: b.Description,
            }));
        }
    } catch {
        // Firefox Monitor API may not be available
    }

    // 3. EmailRep.io (free, 200 req/day)
    try {
        const repRes = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`, {
            headers: {
                'User-Agent': 'OSINT-Recon-Framework',
                Accept: 'application/json',
            },
            timeout: 10000,
        });
        if (repRes.data) {
            results.emailRep = {
                reputation: repRes.data.reputation,
                suspicious: repRes.data.suspicious,
                references: repRes.data.references,
                details: repRes.data.details,
            };
            results.sources.push('EmailRep.io');
        }
    } catch {
        // Rate limited or unavailable
    }

    // Always provide redirect link to HIBP for manual verification
    results.manualCheckLinks = [
        { name: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}` },
        { name: 'DeHashed', url: `https://dehashed.com/search?query=${encodeURIComponent(email)}` },
        { name: 'IntelligenceX', url: `https://intelx.io/?s=${encodeURIComponent(email)}` },
        { name: 'LeakCheck', url: `https://leakcheck.io/` },
    ];

    return results;
}

/**
 * Check pastes for email mentions
 */
async function checkPastes(email) {
    const results = {
        email,
        pastes: [],
        timestamp: new Date().toISOString(),
    };

    // Provide links for manual checking
    results.manualCheckLinks = [
        { name: 'PasteBin Search', url: `https://psbdmp.ws/api/search/${encodeURIComponent(email)}` },
        { name: 'Google Paste Search', url: `https://www.google.com/search?q=${encodeURIComponent('"' + email + '" site:pastebin.com')}` },
    ];

    // Try psbdmp.ws API (Pastebin dump search)
    try {
        const res = await axios.get(`https://psbdmp.ws/api/search/${encodeURIComponent(email)}`, {
            timeout: 10000,
        });
        if (res.data && Array.isArray(res.data.data)) {
            results.pastes = res.data.data.map(p => ({
                id: p.id,
                tags: p.tags,
                time: p.time,
                url: `https://pastebin.com/${p.id}`,
            }));
        }
    } catch {
        // API may be unavailable
    }

    return results;
}

/**
 * Simple SHA-1 hash (for k-anonymity API calls)
 */
async function sha1Hash(str) {
    const crypto = require('crypto');
    return crypto.createHash('sha1').update(str).digest('hex').toUpperCase();
}

module.exports = { checkBreaches, checkPastes };
