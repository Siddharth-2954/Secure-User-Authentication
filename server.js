require('dotenv').config();
const express = require('express');
const helmet = require('helmet'); // For secure headers
const connectDB = require('./config/database');
const authRoutes = require('./routes/auth');

const app = express();

// Middleware for security
app.use(helmet()); // Adds security headers
app.use(express.json());

// Rate limiting middleware
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Connect to MongoDB
connectDB();

// Routes
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});