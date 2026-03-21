const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

const { lookupDomain, lookupIP } = require('../modules/whoisModule');
const { queryAllRecords, enumerateSubdomains, checkZoneTransfer } = require('../modules/dnsModule');
const { searchGitHub, checkSocialProfiles, extractGitHubSecrets } = require('../modules/socialMediaModule');
const { checkBreaches, checkPastes } = require('../modules/breachModule');
const { googleSearch, shodanDomainLookup, searchEmails } = require('../modules/searchModule');
const { getSnapshots, checkAvailability } = require('../modules/waybackModule');
const { analyzeCertificate } = require('../modules/sslModule');
const { auditHeaders } = require('../modules/headersModule');
const { detectTech } = require('../modules/techDetectModule');
const { analyzeEmailSecurity } = require('../modules/dmarcModule');
const { scanPorts } = require('../modules/portScannerModule');
const { checkTakeoverStatus } = require('../modules/takeoverModule');
const { generateProfile } = require('../modules/profileGenerator');
const NodeCache = require('node-cache');

const { body, validationResult } = require('express-validator');

// Initialize cache (stdTTL: 24 hours in seconds, checkperiod: 1 hour)
const scanCache = new NodeCache({ stdTTL: 86400, checkperiod: 3600 });

// In-memory scan store (Active real-time scans)
const scans = new Map();

/**
 * POST /api/scan — Start a new scan
 */
router.post('/', [
    body('target')
        .trim()
        .notEmpty().withMessage('Target is required')
        .matches(/^[a-zA-Z0-9.-@_]+$/).withMessage('Invalid target format. No special characters allowed.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { target, type, modules } = req.body;

    const targetType = type || detectTargetType(target);
    const enabledModules = modules || getDefaultModules(targetType);
    
    // Check Cache first to prevent API abuse
    const cacheKey = `${target}_${enabledModules.sort().join(',')}`;
    const cachedResult = scanCache.get(cacheKey);
    
    if (cachedResult) {
        // Return a mock 'completed' scan state using the cached profile
        const scanId = uuidv4();
        scans.set(scanId, Object.assign({}, cachedResult, { id: scanId }));
        return res.json({ scanId, status: 'started', target, targetType, modules: enabledModules, cached: true });
    }

    const scanId = uuidv4();
    const scan = {
        id: scanId,
        target,
        targetType,
        enabledModules,
        status: 'running',
        progress: 0,
        results: {},
        errors: {},
        startedAt: new Date().toISOString(),
        completedAt: null,
    };

    scans.set(scanId, scan);

    // Return immediately, run scan in background
    res.json({ scanId, status: 'started', target, targetType, modules: enabledModules });

    // Execute scan
    runScan(scan).catch(err => {
        scan.status = 'error';
        scan.errors.global = err.message;
    });
});

/**
 * GET /api/scan/:id/status — Check scan progress
 */
router.get('/:id/status', (req, res) => {
    const scan = scans.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    res.json({
        id: scan.id,
        target: scan.target,
        targetType: scan.targetType,
        status: scan.status,
        progress: scan.progress,
        completedModules: Object.keys(scan.results),
        errorModules: Object.keys(scan.errors),
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
    });
});

/**
 * GET /api/scan/:id/report — Get full scan results
 */
router.get('/:id/report', (req, res) => {
    const scan = scans.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    res.json({
        id: scan.id,
        target: scan.target,
        targetType: scan.targetType,
        status: scan.status,
        progress: scan.progress,
        results: scan.results,
        errors: scan.errors,
        profile: scan.profile || null,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
    });
});

/**
 * GET /api/scan/:id/stream — SSE endpoint for real-time progress
 */
router.get('/:id/stream', (req, res) => {
    const scan = scans.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
    });

    const interval = setInterval(() => {
        const data = {
            status: scan.status,
            progress: scan.progress,
            completedModules: Object.keys(scan.results),
            errorModules: Object.keys(scan.errors),
        };
        res.write(`data: ${JSON.stringify(data)}\n\n`);

        if (scan.status === 'completed' || scan.status === 'error') {
            res.write(`data: ${JSON.stringify({ ...data, done: true })}\n\n`);
            clearInterval(interval);
            res.end();
        }
    }, 500);

    req.on('close', () => clearInterval(interval));
});

/**
 * GET /api/scan/:id/export — Export report
 */
router.get('/:id/export', (req, res) => {
    const scan = scans.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const format = req.query.format || 'json';

    if (format === 'json') {
        res.setHeader('Content-Disposition', `attachment; filename=osint-report-${scan.target}.json`);
        res.json({
            report: {
                target: scan.target,
                type: scan.targetType,
                generatedAt: new Date().toISOString(),
                results: scan.results,
                profile: scan.profile,
            },
        });
    } else if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=osint-report-${scan.target}.csv`);
        res.send(generateCSV(scan));
    } else {
        res.status(400).json({ error: 'Unsupported format. Use json or csv.' });
    }
});

// ===== Scan Execution =====

async function runScan(scan) {
    const moduleCount = scan.enabledModules.length;
    let completed = 0;

    const updateProgress = () => {
        completed++;
        scan.progress = Math.round((completed / moduleCount) * 100);
    };

    // Run modules based on what's enabled
    const moduleMap = {
        whois: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.whois = await lookupDomain(scan.target);
                } else if (scan.targetType === 'ip') {
                    scan.results.whois = await lookupIP(scan.target);
                }
            } catch (err) {
                scan.errors.whois = err.message;
            }
            updateProgress();
        },
        dns: async () => {
            try {
                const domain = scan.targetType === 'domain' ? scan.target : scan.target;
                scan.results.dns = await queryAllRecords(domain);
            } catch (err) {
                scan.errors.dns = err.message;
            }
            updateProgress();
        },
        subdomains: async () => {
            try {
                const domain = scan.targetType === 'domain' ? scan.target : scan.target;
                scan.results.subdomains = await enumerateSubdomains(domain);
            } catch (err) {
                scan.errors.subdomains = err.message;
            }
            updateProgress();
        },
        social: async () => {
            try {
                const socialResults = {};
                if (scan.targetType === 'domain' || scan.targetType === 'username') {
                    socialResults.github = await searchGitHub(scan.target);
                }
                if (scan.targetType === 'username') {
                    socialResults.profiles = await checkSocialProfiles(scan.target);
                }
                scan.results.social = socialResults;
            } catch (err) {
                scan.errors.social = err.message;
            }
            updateProgress();
        },
        breach: async () => {
            try {
                if (scan.targetType === 'email') {
                    scan.results.breach = await checkBreaches(scan.target);
                    scan.results.pastes = await checkPastes(scan.target);
                } else {
                    scan.results.breach = {
                        message: 'Breach checking requires an email address',
                        manualCheckLinks: [
                            { name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/' },
                            { name: 'DeHashed', url: 'https://dehashed.com/' },
                        ],
                    };
                }
            } catch (err) {
                scan.errors.breach = err.message;
            }
            updateProgress();
        },
        search: async () => {
            try {
                const searchResults = {};
                if (scan.targetType === 'domain') {
                    searchResults.emails = await searchEmails(scan.target);
                    searchResults.shodan = await shodanDomainLookup(scan.target);
                    searchResults.google = await googleSearch(`site:${scan.target}`);
                } else if (scan.targetType === 'ip') {
                    searchResults.shodan = await shodanDomainLookup(scan.target);
                } else {
                    searchResults.google = await googleSearch(scan.target);
                }
                scan.results.search = searchResults;
            } catch (err) {
                scan.errors.search = err.message;
            }
            updateProgress();
        },
        wayback: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.wayback = await getSnapshots(scan.target);
                } else {
                    scan.results.wayback = {
                        message: 'Wayback Machine requires a domain target',
                        manualUrl: `https://web.archive.org/web/*/${scan.target}`,
                    };
                }
            } catch (err) {
                scan.errors.wayback = err.message;
            }
            updateProgress();
        },
        ssl: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.ssl = await analyzeCertificate(scan.target);
                } else {
                    scan.results.ssl = { message: 'SSL analysis requires a domain target' };
                }
            } catch (err) {
                scan.errors.ssl = err.message;
            }
            updateProgress();
        },
        headers: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.headers = await auditHeaders(scan.target);
                } else {
                    scan.results.headers = { message: 'Header audit requires a domain target' };
                }
            } catch (err) {
                scan.errors.headers = err.message;
            }
            updateProgress();
        },
        tech: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.tech = await detectTech(scan.target);
                } else {
                    scan.results.tech = { message: 'Tech detection requires a domain target' };
                }
            } catch (err) {
                scan.errors.tech = err.message;
            }
            updateProgress();
        },
        dmarc: async () => {
            try {
                if (scan.targetType === 'domain') {
                    scan.results.dmarc = await analyzeEmailSecurity(scan.target);
                } else {
                    scan.results.dmarc = { message: 'DMARC analysis requires a domain target' };
                }
            } catch (err) {
                scan.errors.dmarc = err.message;
            }
            updateProgress();
        },
        ports: async () => {
            try {
                if (scan.targetType === 'domain' || scan.targetType === 'ip') {
                    scan.results.ports = await scanPorts(scan.target);
                } else {
                    scan.results.ports = { message: 'Port scanning requires an IP or domain target' };
                }
            } catch (err) {
                scan.errors.ports = err.message;
            }
            updateProgress();
        },
        takeover: async () => {
            // Placeholder: Takeover runs after Promise.all because it requires subdomain results
        }
    };

    // Execute all enabled modules in parallel
    const promises = scan.enabledModules
        .filter(m => moduleMap[m])
        .map(m => moduleMap[m]());

    await Promise.all(promises);

    // Run Takeover sequentially if enabled, since it depends on Subdomains
    if (scan.enabledModules.includes('takeover')) {
        try {
            if (scan.results.subdomains && scan.results.subdomains.found) {
                scan.results.takeover = await checkTakeoverStatus(scan.results.subdomains.found);
            } else {
                scan.results.takeover = { message: 'Takeover analysis requires subdomain enumeration results' };
            }
        } catch (err) {
            scan.errors.takeover = err.message;
        }
        updateProgress();
    }

    // Generate unified profile
    try {
        scan.profile = generateProfile(scan.target, scan.targetType, scan.results);
    } catch (err) {
        scan.errors.profile = err.message;
    }

    scan.status = 'completed';
    scan.completedAt = new Date().toISOString();
    
    // Save to cache for 24 hours
    const cacheKey = `${scan.target}_${scan.enabledModules.sort().join(',')}`;
    scanCache.set(cacheKey, scan);
}

// ===== Helpers =====

function detectTargetType(target) {
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) return 'email';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return 'ip';
    if (/^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$/.test(target)) return 'domain';
    return 'username';
}

function getDefaultModules(targetType) {
    switch (targetType) {
        case 'domain': return ['whois', 'dns', 'subdomains', 'ssl', 'headers', 'tech', 'search', 'wayback', 'social', 'dmarc', 'ports', 'takeover'];
        case 'email': return ['breach', 'social', 'search'];
        case 'ip': return ['whois', 'search'];
        case 'username': return ['social'];
        default: return ['search'];
    }
}

function generateCSV(scan) {
    let csv = 'Category,Key,Value,Source\n';

    if (scan.profile) {
        for (const entity of scan.profile.entities) {
            csv += `Entity,${entity.type},${entity.value || entity.name || ''},${entity.source}\n`;
        }
        for (const rel of scan.profile.relationships) {
            csv += `Relationship,${rel.from} -> ${rel.to},${rel.type},${rel.source}\n`;
        }
        for (const rf of scan.profile.riskFactors) {
            csv += `Risk,${rf.factor},${rf.severity},${rf.description}\n`;
        }
    }

    return csv;
}

module.exports = router;
