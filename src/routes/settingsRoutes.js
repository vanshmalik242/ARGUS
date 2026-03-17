const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const ENV_PATH = path.join(__dirname, '..', '..', '.env');

/**
 * GET /api/settings — Get current settings (masked keys)
 */
router.get('/', (req, res) => {
    const settings = {
        SHODAN_API_KEY: maskKey(process.env.SHODAN_API_KEY),
        GOOGLE_CSE_API_KEY: maskKey(process.env.GOOGLE_CSE_API_KEY),
        GOOGLE_CSE_CX: maskKey(process.env.GOOGLE_CSE_CX),
        GITHUB_TOKEN: maskKey(process.env.GITHUB_TOKEN),
    };

    res.json({ settings });
});

/**
 * POST /api/settings — Update API keys
 */
router.post('/', (req, res) => {
    const { keys } = req.body;
    if (!keys || typeof keys !== 'object') {
        return res.status(400).json({ error: 'Invalid payload' });
    }

    const allowedKeys = ['SHODAN_API_KEY', 'GOOGLE_CSE_API_KEY', 'GOOGLE_CSE_CX', 'GITHUB_TOKEN'];

    try {
        let envContent = '';
        try {
            envContent = fs.readFileSync(ENV_PATH, 'utf-8');
        } catch {
            envContent = '';
        }

        for (const [key, value] of Object.entries(keys)) {
            if (!allowedKeys.includes(key)) continue;

            // Update environment variable in memory
            process.env[key] = value;

            // Update .env file
            const regex = new RegExp(`^${key}=.*$`, 'm');
            if (regex.test(envContent)) {
                envContent = envContent.replace(regex, `${key}=${value}`);
            } else {
                envContent += `\n${key}=${value}`;
            }
        }

        fs.writeFileSync(ENV_PATH, envContent.trim() + '\n');

        res.json({ message: 'Settings updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

function maskKey(key) {
    if (!key) return '';
    if (key.length <= 8) return '****';
    return key.substring(0, 4) + '****' + key.substring(key.length - 4);
}

module.exports = router;
