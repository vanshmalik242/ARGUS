/**
 * Subdomain Takeover Analyzer
 * Checks CNAME records of subdomains to identify unclaimed third-party services.
 */
const dns = require('dns').promises;

const TAKEOVER_FINGERPRINTS = [
    { service: 'GitHub Pages', cname: 'github.io', vulnerable_cname: true },
    { service: 'Heroku', cname: 'herokudns.com', vulnerable_cname: true },
    { service: 'Heroku', cname: 'herokuapp.com', vulnerable_cname: true },
    { service: 'AWS S3', cname: 's3.amazonaws.com', vulnerable_cname: true },
    { service: 'AWS Elastic Beanstalk', cname: 'elasticbeanstalk.com', vulnerable_cname: true },
    { service: 'Pantheon', cname: 'pantheonsite.io', vulnerable_cname: true },
    { service: 'Zendesk', cname: 'zendesk.com', vulnerable_cname: true },
    { service: 'Tumblr', cname: 'domains.tumblr.com', vulnerable_cname: true },
    { service: 'WordPress', cname: 'wordpress.com', vulnerable_cname: true },
    { service: 'Shopify', cname: 'myshopify.com', vulnerable_cname: true }
];

async function checkTakeoverStatus(subdomains) {
    const result = {
        analyzedCount: subdomains.length,
        vulnerableSubdomains: [],
        grade: 'A'
    };

    if (!subdomains || subdomains.length === 0) return result;

    try {
        // Resolve CNAMEs concurrently (batching to avoid overwhelming DNS)
        const batchSize = 10;
        for (let i = 0; i < subdomains.length; i += batchSize) {
            const batch = subdomains.slice(i, i + batchSize);
            
            await Promise.all(batch.map(async (sub) => {
                try {
                    const cnames = await dns.resolveCname(sub.subdomain);
                    cnames.forEach(cname => {
                        const match = TAKEOVER_FINGERPRINTS.find(fp => cname.includes(fp.cname));
                        if (match) {
                            result.vulnerableSubdomains.push({
                                subdomain: sub.subdomain,
                                cname: cname,
                                service: match.service,
                                risk: 'HIGH'
                            });
                        }
                    });
                } catch (e) {
                    // ENODATA or ENOTFOUND is fine, means no CNAME exists
                }
            }));
        }

        if (result.vulnerableSubdomains.length > 0) {
            result.grade = 'F'; // Subdomain takeover is a critical vulnerability
        }

    } catch (err) {
        result.error = err.message;
    }

    return result;
}

module.exports = { checkTakeoverStatus };
