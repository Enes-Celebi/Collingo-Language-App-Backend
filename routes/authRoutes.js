const express = require('express');
const router = express.Router();
const { registerUser, loginUser, verifyEmail, resendVerificationLink } = require('../controllers/authController'); 
const passport = require('passport');

router.post('/register', registerUser);

router.post('/login', loginUser);

router.get('/verify-email', verifyEmail);

router.post('/resend-verification', resendVerificationLink); 

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google'), (req, res) => {
    res.redirect('/'); 
});

module.exports = router;