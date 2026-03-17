const axios = require('axios');

const CDX_API = 'https://web.archive.org/cdx/search/cdx';
const WAYBACK_URL = 'https://web.archive.org/web';

/**
 * Get historical snapshots from Wayback Machine CDX API
 */
async function getSnapshots(domain, options = {}) {
    const { limit = 50, from = null, to = null } = options;

    try {
        const params = {
            url: `*.${domain}/*`,
            output: 'json',
            limit,
            filter: 'statuscode:200',
            fl: 'timestamp,original,mimetype,statuscode,length',
            collapse: 'urlkey',
        };

        if (from) params.from = from;
        if (to) params.to = to;

        const res = await axios.get(CDX_API, {
            params,
            timeout: 20000,
        });

        if (!res.data || res.data.length < 2) {
            return { domain, snapshots: [], totalCount: 0, timestamp: new Date().toISOString() };
        }

        // First row is header
        const headers = res.data[0];
        const snapshots = res.data.slice(1).map(row => {
            const obj = {};
            headers.forEach((h, i) => { obj[h] = row[i]; });
            return {
                timestamp: obj.timestamp,
                date: formatWaybackDate(obj.timestamp),
                url: obj.original,
                type: obj.mimetype,
                statusCode: obj.statuscode,
                size: obj.length,
                archiveUrl: `${WAYBACK_URL}/${obj.timestamp}/${obj.original}`,
            };
        });

        // Group by year for timeline
        const timeline = {};
        for (const snap of snapshots) {
            const year = snap.timestamp.substring(0, 4);
            if (!timeline[year]) timeline[year] = 0;
            timeline[year]++;
        }

        return {
            domain,
            snapshots,
            totalCount: snapshots.length,
            timeline,
            oldestCapture: snapshots.length > 0 ? snapshots[0].date : null,
            newestCapture: snapshots.length > 0 ? snapshots[snapshots.length - 1].date : null,
            archiveUrl: `${WAYBACK_URL}/*/${domain}`,
            timestamp: new Date().toISOString(),
        };
    } catch (err) {
        return {
            domain,
            snapshots: [],
            error: err.message,
            archiveUrl: `${WAYBACK_URL}/*/${domain}`,
            timestamp: new Date().toISOString(),
        };
    }
}

/**
 * Get a specific archived page version
 */
async function getArchivedPage(url, timestamp) {
    const archiveUrl = `${WAYBACK_URL}/${timestamp}id_/${url}`;

    try {
        const res = await axios.get(archiveUrl, {
            timeout: 15000,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            },
        });

        return {
            url,
            timestamp,
            archiveUrl,
            content: res.data.substring(0, 5000), // First 5000 chars
            contentLength: res.data.length,
            statusCode: res.status,
            available: true,
        };
    } catch (err) {
        return {
            url,
            timestamp,
            archiveUrl,
            available: false,
            error: err.message,
        };
    }
}

/**
 * Get site availability (first and last capture)
 */
async function checkAvailability(url) {
    try {
        const res = await axios.get('https://archive.org/wayback/available', {
            params: { url },
            timeout: 10000,
        });

        if (res.data && res.data.archived_snapshots && res.data.archived_snapshots.closest) {
            const snap = res.data.archived_snapshots.closest;
            return {
                url,
                available: snap.available,
                archiveUrl: snap.url,
                timestamp: snap.timestamp,
                statusCode: snap.status,
            };
        }

        return { url, available: false };
    } catch {
        return { url, available: false, error: 'Service unavailable' };
    }
}

/**
 * Format Wayback Machine timestamp (YYYYMMDDHHmmss) to readable date
 */
function formatWaybackDate(ts) {
    if (!ts || ts.length < 8) return ts;
    return `${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)}`;
}

module.exports = { getSnapshots, getArchivedPage, checkAvailability };
