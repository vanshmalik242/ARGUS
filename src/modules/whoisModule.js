const whois = require('node-whois');

/**
 * Parse raw WHOIS text into structured data
 */
function parseWhoisData(raw) {
    const lines = raw.split('\n');
    const data = {};
    for (const line of lines) {
        const colonIdx = line.indexOf(':');
        if (colonIdx === -1) continue;
        const key = line.substring(0, colonIdx).trim();
        const value = line.substring(colonIdx + 1).trim();
        if (key && value && !key.startsWith('%') && !key.startsWith('#')) {
            if (data[key]) {
                if (Array.isArray(data[key])) {
                    data[key].push(value);
                } else {
                    data[key] = [data[key], value];
                }
            } else {
                data[key] = value;
            }
        }
    }
    return data;
}

/**
 * Extract key fields from parsed WHOIS data
 */
function extractKeyFields(parsed) {
    const fieldMap = {
        domainName: ['Domain Name', 'domain name', 'domain'],
        registrar: ['Registrar', 'registrar', 'Sponsoring Registrar'],
        registrantName: ['Registrant Name', 'Registrant Organization', 'registrant-name', 'org-name'],
        registrantOrg: ['Registrant Organization', 'Registrant Org', 'org-name', 'OrgName'],
        registrantEmail: ['Registrant Email', 'Registrant Contact Email', 'e-mail'],
        registrantPhone: ['Registrant Phone', 'Registrant Phone Number', 'phone'],
        registrantCountry: ['Registrant Country', 'Registrant Country/Economy', 'country'],
        registrantState: ['Registrant State/Province', 'Registrant State'],
        registrantCity: ['Registrant City'],
        creationDate: ['Creation Date', 'Created Date', 'created', 'Registration Date'],
        expirationDate: ['Registry Expiry Date', 'Expiration Date', 'Registrar Registration Expiration Date', 'expires'],
        updatedDate: ['Updated Date', 'Last Updated', 'last-updated'],
        nameServers: ['Name Server', 'nserver', 'Nameservers'],
        status: ['Domain Status', 'Status', 'status'],
        dnssec: ['DNSSEC', 'dnssec'],
        whoisServer: ['Registrar WHOIS Server', 'WHOIS Server'],
    };

    const result = {};
    for (const [key, possibleNames] of Object.entries(fieldMap)) {
        for (const name of possibleNames) {
            if (parsed[name]) {
                result[key] = parsed[name];
                break;
            }
        }
    }
    return result;
}

/**
 * Lookup domain WHOIS information
 */
async function lookupDomain(domain) {
    return new Promise((resolve, reject) => {
        whois.lookup(domain, (err, data) => {
            if (err) {
                reject(err);
                return;
            }
            const parsed = parseWhoisData(data);
            const extracted = extractKeyFields(parsed);
            resolve({
                domain,
                raw: data,
                parsed,
                extracted,
                timestamp: new Date().toISOString(),
            });
        });
    });
}

/**
 * Lookup IP WHOIS information
 */
async function lookupIP(ip) {
    return new Promise((resolve, reject) => {
        whois.lookup(ip, (err, data) => {
            if (err) {
                reject(err);
                return;
            }
            const parsed = parseWhoisData(data);

            const ipInfo = {
                ip,
                netRange: parsed['NetRange'] || parsed['inetnum'] || null,
                netName: parsed['NetName'] || parsed['netname'] || null,
                organization: parsed['OrgName'] || parsed['org-name'] || parsed['Organization'] || null,
                orgId: parsed['OrgId'] || parsed['org'] || null,
                country: parsed['Country'] || parsed['country'] || null,
                city: parsed['City'] || parsed['city'] || null,
                stateProv: parsed['StateProv'] || parsed['state'] || null,
                address: parsed['Address'] || parsed['address'] || null,
                cidr: parsed['CIDR'] || null,
                abuseEmail: parsed['OrgAbuseEmail'] || parsed['abuse-mailbox'] || null,
                techEmail: parsed['OrgTechEmail'] || null,
                description: parsed['descr'] || parsed['Description'] || null,
            };

            resolve({
                ip,
                raw: data,
                parsed,
                info: ipInfo,
                timestamp: new Date().toISOString(),
            });
        });
    });
}

module.exports = { lookupDomain, lookupIP };
