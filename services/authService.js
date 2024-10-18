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

exports.findUserByEmail = findUserByEmail;

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