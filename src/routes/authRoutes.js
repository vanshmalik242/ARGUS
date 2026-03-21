const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production';
const ACCESS_PHRASE = process.env.ACCESS_PHRASE || 'argus-admin';

// Login route
router.post('/login', (req, res) => {
    const { phrase } = req.body;
    
    if (phrase === ACCESS_PHRASE) {
        // Generate token valid for 24 hours
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        
        // Set HTTP-only cookie
        res.cookie('argus_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({ success: true, message: 'Authentication successful', token });
    } else {
        res.status(401).json({ success: false, message: 'Invalid access phrase' });
    }
});

// Logout route
router.post('/logout', (req, res) => {
    res.clearCookie('argus_token');
    res.json({ success: true, message: 'Logged out successfully' });
});

// Verify session route
router.get('/verify', (req, res) => {
    const token = req.cookies.argus_token || req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ valid: false });
    }

    try {
        jwt.verify(token, JWT_SECRET);
        res.json({ valid: true });
    } catch (err) {
        res.status(401).json({ valid: false });
    }
});

module.exports = router;
