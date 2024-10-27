const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const pool = require('../config/db');

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'dev.collingo@gmail.com',
        pass: 'udup wpwv yuxv ntxo',
    },
});

const findUserByEmail = async (email) => {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return userResult.rows[0];
};

const findUserById = async(id) => {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return userResult.rows[0];
}

exports.findUserByEmail = findUserByEmail;
exports.findUserById = findUserById;

exports.requestPasswordReset = async (email) => {
    const user = await findUserByEmail(email);
    if (!user) {
        throw new Error('User not found');
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString(); 

    const expirationTimeInSeconds = Math.floor(Date.now() / 1000) + 3600; 
    
    await pool.query('UPDATE users SET reset_code = $1, reset_code_expires = to_timestamp($2) WHERE id = $3', [
        resetCode,
        expirationTimeInSeconds, 
        user.id
    ]);

    await sendPasswordResetEmail(email, resetCode);
};

const sendPasswordResetEmail = async (email, resetCode) => {
    await transporter.sendMail({
        to: email,
        subject: 'Your password reset code',
        html: `
            <p>Hi there!</p>
            <p>You have requested to reset your password. Use the code below to reset your password:</p>
            <h2>${resetCode}</h2>
            <p>This code is valid for 1 hour. If you did not request this, please ignore this email.</p>
        `,
    });
};

exports.verifyResetCode = async (req, res) => {
    const { email, code } = req.body;

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userResult.rows[0];

        if (user.reset_code !== code || user.reset_code_expires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired reset code' });
        }

        return res.status(200).json({ message: 'Code verified. You can now reset your password.' });

    } catch (error) {
        console.error("Error verifying reset code: ", error);
        return res.status(500).json({ message: 'Code verification failed. Please try again.' });
    }
};

exports.resetPasswordWithCode = async (email, code, newPassword) => {
    const userResult = await pool.query(
        'SELECT * FROM users WHERE email = $1 AND reset_code = $2 AND reset_code_expires > NOW()', 
        [email, code]
    );

    if (userResult.rows.length === 0) {
        throw new Error('Invalid or expired reset code');
    }

    const user = userResult.rows[0];

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
        'UPDATE users SET password = $1, reset_code = NULL, reset_code_expires = NULL WHERE id = $2', 
        [hashedPassword, user.id]
    );
};

exports.loginUser = async (email, password) => {
    try {
        const user = await findUserByEmail(email);

        if (!user) {
            throw new Error('User not found');
        }

        if (!user.isverified) {
            throw new Error('Email not verified');
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            throw new Error('Invalid password');
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return { token, user };
    } catch (error) {
        console.error("Error logging in:", error);
        throw error;
    }
};

exports.validateToken = async (token) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await findUserById(decoded.id);

        if (!user) {
            throw new Error('User not found');
        }

        if (!user.isverified) {
            throw new Error('Email not verified');
        }

        return user;
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            console.error("Token has expired.");
            throw new Error('Invalid or expired token');
        } else if (error.name === 'JsonWebTokenError') {
            console.error("JWT is malformed or invalid.");
            throw new Error('Invalid or expired token');
        } else {
            console.error("Error validating token:", error);
            throw new Error('An error occurred during token validation');
        }
    }
};

exports.registerUser = async (email, name, password) => {
    try {
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            const error = new Error('User already exists');
            error.code = 'USER_EXISTS';
            throw error;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex');

        const result = await pool.query(
            'INSERT INTO users (email, name, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, name, hashedPassword, verificationToken]
        );

        const newUser = result.rows[0];

        await exports.sendVerificationEmail(newUser.email, verificationToken);

        return newUser;
    } catch (error) {
        console.error("Error registering user: ", error);

        if (error.code === '23505') {
            error.message = 'User with this email already exists';
        }

        throw new Error(error.message || 'Registration failed. Please try again.');
    }
};

exports.sendVerificationEmail = async (email, token) => {
    const verificationUrl = `http://localhost:5000/api/auth/verify-email?token=${token}`;

    await transporter.sendMail({
        to: email, 
        subject: 'Verify your email address',
        html: `
            <p>Hi there!</p>
            <p>Thanks for registering on Collingo. Please verify your email address by clicking the link below:</p>
            <a href="${verificationUrl}">Verify your email</a>
            <p>If you did not create this account, please ignore this email.</p>
        `,
    });
};

exports.verifyEmail = async (token) => {
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);

        if (userResult.rows.length === 0) {
            throw { message: 'Invalid or expired verification token', statusCode: 400};
        }

        await pool.query('UPDATE users SET isverified = TRUE, verification_token = NULL WHERE id = $1', [userResult.rows[0].id]);

        const updatedUser = await pool.query('SELECT * FROM users WHERE id = $1', [userResult.rows[0].id]);

        return updatedUser.rows[0];
    } catch (error) {
        console.error("Error verifying email: ", error);
        throw new Error("Email verification failed. Please try again.");
    }
};

exports.resendVerificationEmail = async (email) => {
    try {
        const user = await findUserByEmail(email);

        if (!user) {
            throw new Error('User not found');
        }

        if (user.isverified) {
            throw new Error('Email already verified');
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');

        await pool.query('UPDATE users SET verification_token = $1 WHERE id = $2', [verificationToken, user.id]);

        await exports.sendVerificationEmail(user.email, verificationToken);

        return { message: 'Verification email resent successfully.' };
    } catch (error) {
        console.error("Error resending verification email: ", error);
        throw new Error(error.message || 'Failed to resend verification email. Please try again.');
    }
};

exports.changeUsername = async (userId, newUsername) => {
    const existingUser = await pool.query('SELECT * FROM users WHERE name = $1', [newUsername]);
    if (existingUser.rows.length > 0) {
        throw new Error('Username already exists');
    }

    const result = await pool.query('UPDATE users SET name = $1 WHERE id = $2 RETURNING *', [newUsername, userId]);
    
    if (result.rows.length === 0) {
        throw new Error('User not found');
    }

    return result.rows[0];  
};