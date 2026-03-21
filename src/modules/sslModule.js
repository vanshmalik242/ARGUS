/**
 * SSL/TLS Certificate Analyzer Module
 * Connects to target domain over TLS, extracts certificate chain,
 * and scores the configuration.
 */
const tls = require('tls');
const https = require('https');

/**
 * Analyze SSL/TLS certificate for a domain
 */
async function analyzeCertificate(domain) {
    const result = {
        valid: false,
        grade: 'F',
        score: 0,
        certificate: {},
        chain: [],
        issues: [],
        checks: [],
    };

    try {
        const certData = await getCertificate(domain);
        result.certificate = certData;
        result.valid = true;

        // Run scoring checks
        const checks = [];

        // 1. Certificate validity
        const now = new Date();
        const validFrom = new Date(certData.validFrom);
        const validTo = new Date(certData.validTo);
        const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

        if (now < validFrom || now > validTo) {
            checks.push({ name: 'Certificate Validity', pass: false, detail: 'Certificate is expired or not yet valid' });
            result.issues.push('Certificate is expired or not yet valid');
        } else if (daysUntilExpiry < 30) {
            checks.push({ name: 'Certificate Validity', pass: false, detail: `Expires in ${daysUntilExpiry} days` });
            result.issues.push(`Certificate expires in ${daysUntilExpiry} days`);
        } else {
            checks.push({ name: 'Certificate Validity', pass: true, detail: `Valid for ${daysUntilExpiry} more days` });
        }

        // 2. Self-signed check
        const isSelfSigned = certData.issuer === certData.subject;
        if (isSelfSigned) {
            checks.push({ name: 'Not Self-Signed', pass: false, detail: 'Certificate is self-signed' });
            result.issues.push('Self-signed certificate detected');
        } else {
            checks.push({ name: 'Not Self-Signed', pass: true, detail: `Issued by ${certData.issuerOrg || certData.issuer}` });
        }

        // 3. Subject Alternative Names
        const hasSANs = certData.subjectAltNames && certData.subjectAltNames.length > 0;
        checks.push({ name: 'Subject Alt Names', pass: hasSANs, detail: hasSANs ? `${certData.subjectAltNames.length} SANs found` : 'No SANs — legacy CN-only cert' });

        // 4. Key size
        const keyBits = certData.bits || 0;
        if (keyBits >= 2048) {
            checks.push({ name: 'Key Strength', pass: true, detail: `${keyBits}-bit key` });
        } else {
            checks.push({ name: 'Key Strength', pass: false, detail: `Weak ${keyBits}-bit key (2048+ required)` });
            result.issues.push(`Weak key size: ${keyBits} bits`);
        }

        // 5. TLS version support
        const tlsInfo = await checkTLSVersions(domain);
        checks.push({ name: 'TLS 1.2+ Support', pass: tlsInfo.supports12, detail: tlsInfo.supports12 ? 'TLS 1.2 supported' : 'TLS 1.2 not available' });
        if (tlsInfo.supports13) {
            checks.push({ name: 'TLS 1.3 Support', pass: true, detail: 'TLS 1.3 supported (modern)' });
        }

        // 6. Wildcard check
        const isWildcard = certData.subject?.startsWith('*.') || certData.subjectAltNames?.some(s => s.startsWith('*.'));
        checks.push({ name: 'Wildcard Certificate', pass: true, detail: isWildcard ? 'Wildcard cert detected' : 'Standard certificate' });

        // Calculate score
        const passCount = checks.filter(c => c.pass).length;
        const totalChecks = checks.length;
        const rawScore = Math.round((passCount / totalChecks) * 100);

        result.score = rawScore;
        result.checks = checks;

        // Grade
        if (rawScore >= 90) result.grade = 'A';
        else if (rawScore >= 80) result.grade = 'B';
        else if (rawScore >= 60) result.grade = 'C';
        else if (rawScore >= 40) result.grade = 'D';
        else result.grade = 'F';

        // Downgrade for critical issues
        if (isSelfSigned || (now > validTo)) {
            result.grade = 'F';
        }

    } catch (err) {
        result.issues.push(`Connection failed: ${err.message}`);
        result.error = err.message;
    }

    return result;
}

/**
 * Get certificate details via TLS connection
 */
function getCertificate(domain) {
    return new Promise((resolve, reject) => {
        const options = {
            host: domain,
            port: 443,
            servername: domain,
            rejectUnauthorized: false,
            timeout: 10000,
        };

        const socket = tls.connect(options, () => {
            try {
                const cert = socket.getPeerCertificate(true);
                if (!cert || Object.keys(cert).length === 0) {
                    socket.destroy();
                    return reject(new Error('No certificate returned'));
                }

                const parsed = {
                    subject: cert.subject?.CN || 'Unknown',
                    issuer: cert.issuer?.CN || 'Unknown',
                    issuerOrg: cert.issuer?.O || '',
                    validFrom: cert.valid_from,
                    validTo: cert.valid_to,
                    serialNumber: cert.serialNumber,
                    fingerprint: cert.fingerprint,
                    fingerprint256: cert.fingerprint256,
                    bits: cert.bits,
                    subjectAltNames: [],
                    protocol: socket.getProtocol(),
                    cipher: socket.getCipher(),
                };

                // Parse Subject Alt Names
                if (cert.subjectaltname) {
                    parsed.subjectAltNames = cert.subjectaltname
                        .split(', ')
                        .map(s => s.replace('DNS:', '').trim());
                }

                // Extract chain
                const chain = [];
                let current = cert;
                let depth = 0;
                while (current && depth < 5) {
                    chain.push({
                        subject: current.subject?.CN || 'Unknown',
                        issuer: current.issuer?.CN || 'Unknown',
                        validTo: current.valid_to,
                    });
                    if (current.issuerCertificate && current.issuerCertificate !== current) {
                        current = current.issuerCertificate;
                    } else {
                        break;
                    }
                    depth++;
                }
                parsed.chain = chain;

                socket.destroy();
                resolve(parsed);
            } catch (e) {
                socket.destroy();
                reject(e);
            }
        });

        socket.on('error', (err) => {
            socket.destroy();
            reject(err);
        });

        socket.setTimeout(10000, () => {
            socket.destroy();
            reject(new Error('Connection timed out'));
        });
    });
}

/**
 * Check which TLS versions are supported
 */
async function checkTLSVersions(domain) {
    const result = { supports12: false, supports13: false };

    const testVersion = (minVersion, maxVersion) => {
        return new Promise((resolve) => {
            const socket = tls.connect({
                host: domain, port: 443, servername: domain,
                minVersion, maxVersion,
                rejectUnauthorized: false, timeout: 5000,
            }, () => {
                const proto = socket.getProtocol();
                socket.destroy();
                resolve(proto);
            });
            socket.on('error', () => { socket.destroy(); resolve(null); });
            socket.setTimeout(5000, () => { socket.destroy(); resolve(null); });
        });
    };

    try {
        const [v12, v13] = await Promise.all([
            testVersion('TLSv1.2', 'TLSv1.2'),
            testVersion('TLSv1.3', 'TLSv1.3'),
        ]);
        result.supports12 = !!v12;
        result.supports13 = !!v13;
    } catch { /* ignore */ }

    return result;
}

module.exports = { analyzeCertificate };
