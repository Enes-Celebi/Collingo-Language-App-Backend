// Inside authController.js
const authService = require('../services/authService');

const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

exports.registerUser = async (req, res) => {
    try {
        const { email, name, password } = req.body;

        if (!email || !name || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        const newUser = await authService.registerUser(email, name, password);

        return res.status(201).json({
            message: 'User registered successfully. Please check your email to verify your account.',
            user: newUser,
        });
    } catch (error) {
        console.error("Error during user registration:", error);

        if (error.message === 'User already exists' || error.code === 'USER_EXISTS') {
            return res.status(409).json({ error: 'User already exists!' });
        } else if (error.message === 'Invalid email format') {
            return res.status(400).json({ error: 'Invalid email format!' });
        }

        return res.status(500).json({ error: 'An unexpected error occurred during registration.' });
    }
};

exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Both email and password are required.' });
        }
        
        const { token, user } = await authService.loginUser(email, password);

        return res.status(200).json({
            message: 'Login successful',
            token,
            user,
        });

    } catch (error) {
        console.error("Error during user login:", error); 

        if (error.message === 'Invalid password') {
            return res.status(403).json({ error: 'Invalid password!' });
        } else if (error.message === 'User not found') {
            return res.status(404).json({ error: 'User not found!' });
        } else if (error.message === 'Email not verified') {
            return res.status(401).json({ error: 'Email not verified!' });
        } else {
            return res.status(500).json({ error: 'An unexpected error occurred during login.' });
        }
    }
};

exports.verifyEmail = async (req, res) => {
    const { token } = req.query;

    try {
        if (!token) {
            return res.status(400).json({ error: 'Verification token is required' });
        }

        const user = await authService.verifyEmail(token);

        res.status(200).json({
            message: 'Email verified successfully!',
            user,
        });
    } catch (error) {
        console.error("Error during email verification:", error); 
        res.status(400).json({ error: error.message });
    }
};

exports.resendVerificationLink = async (req, res) => {
    const { email } = req.body;

    try {
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        const user = await authService.findUserByEmail(email); 
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        if (user.isverified) {
            return res.status(400).json({ error: 'Email already verified.' });
        }

        await authService.resendVerificationEmail(email); 
        return res.status(200).json({ message: 'Verification email resent successfully.' });
    } catch (error) {
        console.error("Error during resending verification email:", error);
        return res.status(500).json({ error: error.message || 'Failed to resend verification email.' });
    }
};