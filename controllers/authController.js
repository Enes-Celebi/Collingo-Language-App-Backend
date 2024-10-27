const jwt = require('jsonwebtoken');
const authService = require('../services/authService');

const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

exports.requestPasswordReset = async (req, res) => {
    const { email } = req.body;

    try {
        if (!email) {
            return res.status(400).json({ error: 'email required' });
        }

        if (!validateEmail(email)) {
            return res.status(401).json({ error: 'invalid email format' });
        }

        await authService.requestPasswordReset(email);

        return res.status(200).json({ message: 'code sent successfully to your email' });
    } catch (error) {
        console.error("error during password reset request:", error);
        return res.status(500).json({ error: error.message || 'an unexpected error occurred' });
    }
};

exports.verifyResetCode = async (req, res) => {
    const { email, code } = req.body;

    try {
        const user = await authService.findUserByEmail(email);
        if (!user) {
            return res.status(404).json({ error: 'user not found' });
        }

        if (user.reset_code === code && user.reset_code_expires > Date.now()) {
            return res.status(200).json({ message: 'code verified successfully. you can now reset your password.' });
        }

        return res.status(400).json({ error: 'invalid or expired code' });
    } catch (error) {
        console.error("error during code verification:", error);
        return res.status(500).json({ error: 'an unexpected error occurred' });
    }
};

exports.resetPasswordWithCode = async (req, res) => {
    const { email, code, newPassword } = req.body; 

    try {
        if (!email || !code || !newPassword) {
            return res.status(400).json({ error: 'email, code, and newPassword are required' });
        }

        await authService.resetPasswordWithCode(email, code, newPassword); 

        return res.status(200).json({ message: 'password reset successfully.' });
    } catch (error) {
        console.error("error during password reset:", error);
        return res.status(400).json({ error: error.message || 'Password reset failed.' });
    }
};

exports.registerUser = async (req, res) => {
    try {
        const { email, name, password } = req.body;

        if (!email || !name || !password) {
            return res.status(400).json({ error: 'email, name, and password are required' });
        }

        if (!validateEmail(email)) {
            return res.status(401).json({ error: 'invalid email format' });
        }

        if (password.length < 8) {
            return res.status(402).json({ error: 'password must be at least 8 characters'})
        }

        const newUser = await authService.registerUser(email, name, password);

        return res.status(201).json({
            message: 'user registered successfully. verify your account from your email.',
            user: newUser,
        });
    } catch (error) {
        console.error("error during user registration:", error);

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

exports.validateToken = async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ error: 'Token is required.' });
        }

        const user = await authService.validateToken(token);

        return res.status(200).json({
            message: 'Login successful',
            user,
        });

    } catch (error) {
        console.error("Error during token-based login:", error);

        if (error.message === 'User not found') {
            return res.status(404).json({ error: 'User not found!' });
        } else if (error.message === 'Email not verified') {
            return res.status(401).json({ error: 'Email not verified!' });
        } else if (error.message === 'Invalid or expired token') {
            return res.status(403).json({ error: 'Invalid or expired token!' });
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

exports.changeUsername = async (req, res) => {
    const { email, newUsername } = req.body;

    try {
        if (!email || !newUsername) {
            return res.status(400).json({ error: 'Email and new username are required.' });
        }

        const user = await authService.findUserByEmail(email);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const updatedUser = await authService.changeUsername(user.id, newUsername);

        return res.status(200).json({
            message: 'Username changed successfully.',
            user: updatedUser
        });
    } catch (error) {
        console.error("Error during username change:", error);
        return res.status(500).json({ error: error.message || 'Failed to change username.' });
    }
};