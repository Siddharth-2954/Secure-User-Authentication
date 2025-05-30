const express = require('express');
const router = express.Router();
const { register, login, refreshToken, getProfile } = require('../controllers/authController');
const { auth, checkRole } = require('../middlewares/auth');

// Public routes
router.post('/register', register);
router.post('/login', login);
router.post('/refresh-token', refreshToken);

// Protected routes
router.get('/profile', auth, getProfile);

// Example of a protected route with RBAC
router.get('/admin', auth, checkRole(['admin']), (req, res) => {
    res.json({ message: 'Welcome, admin!' });
});

module.exports = router;