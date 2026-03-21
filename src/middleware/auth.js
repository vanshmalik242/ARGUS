const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production';

function requireAuth(req, res, next) {
    // Check for token in cookie or Authorization header
    const token = req.cookies?.argus_token || req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required. Missing token.', code: 'AUTH_REQUIRED' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // attaching user info to request
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token.', code: 'INVALID_TOKEN' });
    }
}

module.exports = { requireAuth };
