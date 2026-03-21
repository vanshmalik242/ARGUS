require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const scanRoutes = require('./src/routes/scanRoutes');
const settingsRoutes = require('./src/routes/settingsRoutes');
const authRoutes = require('./src/routes/authRoutes');
const { requireAuth } = require('./src/middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for local development / dynamic frontend
}));
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Rate Limiting (100 requests per 15 minutes)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api', limiter);

app.use(express.static(path.join(__dirname, 'public')));

// Public Auth Routes
app.use('/api/auth', authRoutes);

// Protected API Routes
app.use('/api/scan', requireAuth, scanRoutes);
app.use('/api/settings', requireAuth, settingsRoutes);

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
