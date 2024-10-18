const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('./db');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    const user = await pool.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);
    if (user.rows.length) {
        done(null, user.rows[0]);
    } else {
        const newUser = await pool.query('INSERT INTO users (google_id, email, name) VALUES ($1, $2, $3) RETURNING *',
            [profile.id, profile.emails[0].value, profile.displayName]);
        done(null, newUser.rows[0]);
    }
}));
