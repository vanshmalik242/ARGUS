/**
 * Email Security Analyzer (DMARC/SPF/DKIM)
 * Checks domain text records for secure email configuration to detect spoofing risks.
 */
const dns = require('dns').promises;

async function analyzeEmailSecurity(domain) {
    const result = {
        domain: domain,
        spf: { present: false, record: null, strict: false },
        dmarc: { present: false, record: null, policy: 'none' },
        spoofable: true, // Default to true unless proven secure
        grade: 'F'
    };

    try {
        // Query root domain TXT records for SPF
        let txtRecords = [];
        try {
            const rootTxt = await dns.resolveTxt(domain);
            txtRecords = rootTxt.map(r => r.join(''));
        } catch (e) {
            if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') throw e;
        }

        const spfRecord = txtRecords.find(t => t.startsWith('v=spf1'));
        if (spfRecord) {
            result.spf.present = true;
            result.spf.record = spfRecord;
            // Check if it's strict (-all) or soft (~all) or none (?all)
            if (spfRecord.includes('-all')) result.spf.strict = true;
        }

        // Query _dmarc.domain for DMARC
        let dmarcRecords = [];
        try {
            const dmarcTxt = await dns.resolveTxt(`_dmarc.${domain}`);
            dmarcRecords = dmarcTxt.map(r => r.join(''));
        } catch (e) {
            if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') throw e;
        }

        const dmarcRecord = dmarcRecords.find(t => t.startsWith('v=DMARC1'));
        if (dmarcRecord) {
            result.dmarc.present = true;
            result.dmarc.record = dmarcRecord;
            
            // Extract policy (p=reject, p=quarantine, p=none)
            const pMatch = dmarcRecord.match(/p=(none|quarantine|reject)/i);
            if (pMatch) {
                result.dmarc.policy = pMatch[1].toLowerCase();
            }
        }

        // Calculate vulnerability
        if (result.spf.strict && (result.dmarc.policy === 'reject' || result.dmarc.policy === 'quarantine')) {
            result.spoofable = false;
            result.grade = 'A';
        } else if (result.spf.present && result.dmarc.present) {
            // Has both but loose configuration
            result.grade = 'B';
        } else if (result.spf.present || result.dmarc.present) {
            result.grade = 'C';
        } else {
            result.grade = 'F';
        }

    } catch (err) {
        result.error = err.message;
    }

    return result;
}

module.exports = { analyzeEmailSecurity };
