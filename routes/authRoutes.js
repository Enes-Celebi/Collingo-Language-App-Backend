const express = require('express');
const router = express.Router();
const {
    registerUser,
    loginUser,
    verifyEmail,
    resendVerificationLink,
    requestPasswordReset,
    verifyResetCode, 
    resetPasswordWithCode,
    changeUsername,
    validateToken
} = require('../controllers/authController');
const passport = require('passport');

// Register user
router.post('/register', registerUser);

// Login user
router.post('/login', loginUser);

// Validate token
router.post('/validate-token', validateToken);

// Email verification
router.get('/verify-email', verifyEmail);

// Resend user verification link
router.post('/resend-verification', resendVerificationLink);

// Google OAuth login (currently out of service)
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth callback (currently out of service)
router.get('/google/callback', passport.authenticate('google'), (req, res) => {
    res.redirect('/'); 
});

// Request password reset
router.post('/request-reset-password', requestPasswordReset); 

// Verify code before allowing password reset
router.post('/verify-reset-code', verifyResetCode);  

// Reset password
router.post('/reset-password-with-code', resetPasswordWithCode);

// Change username
router.post('/change-username', changeUsername); 

module.exports = router;