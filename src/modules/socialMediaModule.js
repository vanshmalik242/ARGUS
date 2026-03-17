const axios = require('axios');

const GITHUB_API = 'https://api.github.com';

/**
 * Search GitHub for repos, users, and code related to a target
 */
async function searchGitHub(query) {
    const headers = { Accept: 'application/vnd.github.v3+json' };
    if (process.env.GITHUB_TOKEN) {
        headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    const results = { repos: [], users: [], code: [] };

    // Use exact match quotes for better relevance, especially for domains
    const exactQuery = query.includes('@') || query.includes('.') ? `"${query}"` : query;

    try {
        // Search repos
        const repoRes = await axios.get(`${GITHUB_API}/search/repositories`, {
            params: { q: exactQuery, per_page: 10, sort: 'stars' },
            headers,
            timeout: 10000,
        });
        results.repos = repoRes.data.items.map(r => ({
            name: r.full_name,
            description: r.description,
            url: r.html_url,
            stars: r.stargazers_count,
            language: r.language,
            updatedAt: r.updated_at,
            topics: r.topics || [],
        }));
    } catch (err) {
        results.repoError = err.message;
    }

    try {
        // Search users
        const userRes = await axios.get(`${GITHUB_API}/search/users`, {
            params: { q: exactQuery, per_page: 10 },
            headers,
            timeout: 10000,
        });
        results.users = userRes.data.items.map(u => ({
            login: u.login,
            url: u.html_url,
            avatar: u.avatar_url,
            type: u.type,
        }));
    } catch (err) {
        results.userError = err.message;
    }

    try {
        // Search code
        const codeRes = await axios.get(`${GITHUB_API}/search/code`, {
            params: { q: query, per_page: 10 },
            headers,
            timeout: 10000,
        });
        results.code = codeRes.data.items.map(c => ({
            name: c.name,
            path: c.path,
            repo: c.repository.full_name,
            url: c.html_url,
        }));
    } catch (err) {
        results.codeError = err.message;
    }

    return {
        query,
        results,
        timestamp: new Date().toISOString(),
    };
}

/**
 * Check social profile existence across platforms
 */
async function checkSocialProfiles(username) {
    const fs = require('fs');
    const path = require('path');

    let platforms;
    try {
        const data = fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'social-platforms.json'), 'utf-8');
        platforms = JSON.parse(data);
    } catch {
        platforms = getDefaultPlatforms();
    }

    const results = [];
    const batchSize = 5;

    for (let i = 0; i < platforms.length; i += batchSize) {
        const batch = platforms.slice(i, i + batchSize);
        const promises = batch.map(async (platform) => {
            const url = platform.url.replace('{username}', username);
            try {
                const response = await axios.get(url, {
                    timeout: 5000,
                    maxRedirects: 3,
                    validateStatus: (status) => status < 500,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    },
                });

                const exists = response.status === 200 &&
                    (!platform.errorIndicator || !response.data.toString().includes(platform.errorIndicator));

                results.push({
                    platform: platform.name,
                    url,
                    exists,
                    category: platform.category,
                    statusCode: response.status,
                });
            } catch {
                results.push({
                    platform: platform.name,
                    url,
                    exists: false,
                    category: platform.category,
                    statusCode: null,
                    error: 'timeout_or_blocked',
                });
            }
        });
        await Promise.all(promises);
    }

    return {
        username,
        profiles: results,
        found: results.filter(r => r.exists),
        timestamp: new Date().toISOString(),
    };
}

/**
 * Scan GitHub repos for potential secrets
 */
async function extractGitHubSecrets(repoFullName) {
    const headers = { Accept: 'application/vnd.github.v3+json' };
    if (process.env.GITHUB_TOKEN) {
        headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    const secretPatterns = [
        { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
        { name: 'API Key', pattern: /[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*['"][^'"]{10,}/g },
        { name: 'Secret Key', pattern: /[sS][eE][cC][rR][eE][tT][_-]?[kK][eE][yY]\s*[:=]\s*['"][^'"]{10,}/g },
        { name: 'Password', pattern: /[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['"][^'"]{4,}/g },
        { name: 'Private Key', pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g },
        { name: 'Database URL', pattern: /(mongodb|postgres|mysql):\/\/[^\s"']+/g },
        { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
    ];

    const findings = [];

    try {
        // Get recent commits
        const commitsRes = await axios.get(`${GITHUB_API}/repos/${repoFullName}/commits`, {
            params: { per_page: 5 },
            headers,
            timeout: 10000,
        });

        for (const commit of commitsRes.data) {
            try {
                const diffRes = await axios.get(commit.url, {
                    headers: { ...headers, Accept: 'application/vnd.github.v3.diff' },
                    timeout: 10000,
                });

                for (const sp of secretPatterns) {
                    const matches = diffRes.data.match(sp.pattern);
                    if (matches) {
                        findings.push({
                            type: sp.name,
                            commitSha: commit.sha.substring(0, 8),
                            commitMessage: commit.commit.message.substring(0, 80),
                            date: commit.commit.author.date,
                            matchCount: matches.length,
                        });
                    }
                }
            } catch {
                continue;
            }
        }
    } catch (err) {
        return { repo: repoFullName, error: err.message, findings: [] };
    }

    return {
        repo: repoFullName,
        findings,
        timestamp: new Date().toISOString(),
    };
}

function getDefaultPlatforms() {
    return [
        { name: 'GitHub', url: 'https://github.com/{username}', category: 'development', errorIndicator: 'Not Found' },
        { name: 'GitLab', url: 'https://gitlab.com/{username}', category: 'development', errorIndicator: 'Sign in' },
        { name: 'Reddit', url: 'https://www.reddit.com/user/{username}', category: 'social', errorIndicator: 'Nobody on Reddit goes by that name' },
        { name: 'Medium', url: 'https://medium.com/@{username}', category: 'blog', errorIndicator: 'Out of nothing' },
        { name: 'Dev.to', url: 'https://dev.to/{username}', category: 'development', errorIndicator: '404' },
        { name: 'Pinterest', url: 'https://www.pinterest.com/{username}', category: 'social', errorIndicator: 'Not Found' },
        { name: 'Replit', url: 'https://replit.com/@{username}', category: 'development', errorIndicator: 'Not Found' },
        { name: 'NPM', url: 'https://www.npmjs.com/~{username}', category: 'development', errorIndicator: 'not found' },
        { name: 'PyPI', url: 'https://pypi.org/user/{username}', category: 'development', errorIndicator: 'Not Found' },
    ];
}

module.exports = { searchGitHub, checkSocialProfiles, extractGitHubSecrets };
