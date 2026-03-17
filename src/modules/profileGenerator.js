/**
 * Profile Generator - Aggregates all OSINT results into a unified profile
 */

/**
 * Generate a unified target profile from scan results
 */
function generateProfile(target, targetType, moduleResults) {
    const profile = {
        target,
        targetType,
        generatedAt: new Date().toISOString(),
        summary: {},
        entities: [],
        relationships: [],
        timeline: [],
        riskScore: 0,
        riskFactors: [],
    };

    // Process WHOIS data
    if (moduleResults.whois) {
        processWhoisForProfile(profile, moduleResults.whois);
    }

    // Process DNS data
    if (moduleResults.dns) {
        processDNSForProfile(profile, moduleResults.dns);
    }

    // Process Subdomain data
    if (moduleResults.subdomains) {
        processSubdomainsForProfile(profile, moduleResults.subdomains);
    }

    // Process Social Media data
    if (moduleResults.social) {
        processSocialForProfile(profile, moduleResults.social);
    }

    // Process Breach data
    if (moduleResults.breach) {
        processBreachForProfile(profile, moduleResults.breach);
    }

    // Process Search data
    if (moduleResults.search) {
        processSearchForProfile(profile, moduleResults.search);
    }

    // Process Wayback data
    if (moduleResults.wayback) {
        processWaybackForProfile(profile, moduleResults.wayback);
    }

    // Calculate risk score
    profile.riskScore = calculateRiskScore(profile.riskFactors);

    // Sort timeline
    profile.timeline.sort((a, b) => new Date(a.date) - new Date(b.date));

    // Generate summary
    profile.summary = generateSummary(profile);

    return profile;
}

function processWhoisForProfile(profile, whoisData) {
    if (whoisData.extracted) {
        const ext = whoisData.extracted;

        if (ext.registrantName) {
            profile.entities.push({ type: 'person', name: ext.registrantName, source: 'WHOIS', role: 'registrant' });
        }
        if (ext.registrantOrg) {
            profile.entities.push({ type: 'organization', name: ext.registrantOrg, source: 'WHOIS' });
        }
        if (ext.registrantEmail) {
            profile.entities.push({ type: 'email', value: ext.registrantEmail, source: 'WHOIS' });
        }
        if (ext.creationDate) {
            profile.timeline.push({ date: ext.creationDate, event: 'Domain Registered', source: 'WHOIS', category: 'infrastructure' });
        }
        if (ext.expirationDate) {
            profile.timeline.push({ date: ext.expirationDate, event: 'Domain Expires', source: 'WHOIS', category: 'infrastructure' });
        }
        if (ext.nameServers) {
            const ns = Array.isArray(ext.nameServers) ? ext.nameServers : [ext.nameServers];
            ns.forEach(n => {
                profile.entities.push({ type: 'nameserver', value: n, source: 'WHOIS' });
            });
        }

        // Relationships
        if (ext.registrantOrg && ext.registrantName) {
            profile.relationships.push({ from: ext.registrantName, to: ext.registrantOrg, type: 'works-at', source: 'WHOIS' });
        }
        if (ext.registrantOrg) {
            profile.relationships.push({ from: ext.registrantOrg, to: profile.target, type: 'owns', source: 'WHOIS' });
        }
    }

    // Risk: WHOIS privacy not enabled
    if (whoisData.raw && !whoisData.raw.toLowerCase().includes('privacy') && !whoisData.raw.toLowerCase().includes('redacted')) {
        profile.riskFactors.push({ factor: 'WHOIS Privacy Not Enabled', severity: 'medium', description: 'Registration details are publicly visible' });
    }
}

function processDNSForProfile(profile, dnsData) {
    if (dnsData.records) {
        const rec = dnsData.records;

        if (rec.A) {
            rec.A.forEach(ip => {
                profile.entities.push({ type: 'ip', value: ip, source: 'DNS' });
                profile.relationships.push({ from: profile.target, to: ip, type: 'resolves-to', source: 'DNS' });
            });
        }

        if (rec.MX) {
            rec.MX.forEach(mx => {
                profile.entities.push({ type: 'mailserver', value: mx.exchange, priority: mx.priority, source: 'DNS' });
                profile.relationships.push({ from: profile.target, to: mx.exchange, type: 'mail-handled-by', source: 'DNS' });
            });
        }

        if (rec.NS) {
            rec.NS.forEach(ns => {
                profile.entities.push({ type: 'nameserver', value: ns, source: 'DNS' });
            });
        }
    }

    if (dnsData.insights) {
        for (const insight of dnsData.insights) {
            if (insight.type === 'warning') {
                profile.riskFactors.push({ factor: insight.label, severity: 'medium', description: insight.value });
            }
        }
    }
}

function processSubdomainsForProfile(profile, subData) {
    if (subData.found) {
        for (const sub of subData.found) {
            profile.entities.push({ type: 'subdomain', value: sub.subdomain, addresses: sub.addresses, source: 'DNS Enum' });
            profile.relationships.push({ from: profile.target, to: sub.subdomain, type: 'has-subdomain', source: 'DNS Enum' });

            sub.addresses.forEach(ip => {
                profile.relationships.push({ from: sub.subdomain, to: ip, type: 'resolves-to', source: 'DNS Enum' });
            });
        }

        if (subData.found.length > 20) {
            profile.riskFactors.push({
                factor: 'Large Attack Surface',
                severity: 'high',
                description: `${subData.found.length} subdomains discovered, increasing potential attack vectors`,
            });
        }
    }
}

function processSocialForProfile(profile, socialData) {
    if (socialData.github) {
        const gh = socialData.github;
        if (gh.results) {
            gh.results.repos?.forEach(repo => {
                profile.entities.push({ type: 'repository', value: repo.name, url: repo.url, source: 'GitHub' });
            });
            gh.results.users?.forEach(user => {
                profile.entities.push({ type: 'person', name: user.login, url: user.url, avatar: user.avatar, source: 'GitHub' });
            });
        }
    }

    if (socialData.profiles) {
        const found = socialData.profiles.found || [];
        found.forEach(p => {
            profile.entities.push({ type: 'social-profile', platform: p.platform, url: p.url, source: 'Social Probe' });
        });

        if (found.length > 5) {
            profile.riskFactors.push({
                factor: 'Extensive Social Presence',
                severity: 'low',
                description: `Found ${found.length} social profiles, potential social engineering vectors`,
            });
        }
    }

    if (socialData.secrets && socialData.secrets.findings && socialData.secrets.findings.length > 0) {
        profile.riskFactors.push({
            factor: 'Exposed Secrets in Code',
            severity: 'critical',
            description: `Found ${socialData.secrets.findings.length} potential secrets in public repositories`,
        });
    }
}

function processBreachForProfile(profile, breachData) {
    if (breachData.breaches && breachData.breaches.length > 0) {
        profile.riskFactors.push({
            factor: 'Breach Exposure',
            severity: 'high',
            description: `Email found in ${breachData.breaches.length} known breaches`,
        });
    }

    if (breachData.emailRep) {
        if (breachData.emailRep.suspicious) {
            profile.riskFactors.push({
                factor: 'Suspicious Email',
                severity: 'high',
                description: 'Email marked as suspicious by EmailRep.io',
            });
        }
    }

    if (breachData.knownBreaches) {
        breachData.knownBreaches.forEach(b => {
            if (b.breachDate) {
                profile.timeline.push({ date: b.breachDate, event: `Breach: ${b.name || b.title}`, source: 'Breach DB', category: 'breach' });
            }
        });
    }
}

function processSearchForProfile(profile, searchData) {
    if (searchData.shodan) {
        for (const s of (searchData.shodan.shodanResults || [])) {
            if (s.available && s.ports) {
                s.ports.forEach(port => {
                    profile.entities.push({ type: 'service', value: `${s.ip}:${port}`, source: 'Shodan' });
                });

                if (s.vulns && s.vulns.length > 0) {
                    profile.riskFactors.push({
                        factor: 'Known Vulnerabilities',
                        severity: 'critical',
                        description: `Shodan reports ${s.vulns.length} CVEs for ${s.ip}`,
                    });
                }
            }
        }
    }
}

function processWaybackForProfile(profile, waybackData) {
    if (waybackData.oldestCapture) {
        profile.timeline.push({
            date: waybackData.oldestCapture,
            event: 'First Archive Capture',
            source: 'Wayback Machine',
            category: 'archive',
        });
    }
    if (waybackData.newestCapture) {
        profile.timeline.push({
            date: waybackData.newestCapture,
            event: 'Most Recent Archive Capture',
            source: 'Wayback Machine',
            category: 'archive',
        });
    }
    if (waybackData.timeline) {
        profile.summary.archiveTimeline = waybackData.timeline;
    }
}

function calculateRiskScore(riskFactors) {
    let score = 0;
    for (const rf of riskFactors) {
        switch (rf.severity) {
            case 'critical': score += 30; break;
            case 'high': score += 20; break;
            case 'medium': score += 10; break;
            case 'low': score += 5; break;
        }
    }
    return Math.min(100, score);
}

function generateSummary(profile) {
    const entityCounts = {};
    for (const e of profile.entities) {
        entityCounts[e.type] = (entityCounts[e.type] || 0) + 1;
    }

    return {
        ...profile.summary,
        target: profile.target,
        targetType: profile.targetType,
        totalEntities: profile.entities.length,
        totalRelationships: profile.relationships.length,
        totalTimelineEvents: profile.timeline.length,
        entityBreakdown: entityCounts,
        riskScore: profile.riskScore,
        riskLevel: profile.riskScore >= 60 ? 'Critical' : profile.riskScore >= 40 ? 'High' : profile.riskScore >= 20 ? 'Medium' : 'Low',
        totalRiskFactors: profile.riskFactors.length,
    };
}

module.exports = { generateProfile };
