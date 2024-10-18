const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];
    if(!token) {
        return res.status(403).send("A token is required for authentication");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;

        const user = await User.findByPk(decoded.id);
        if(!user || !user.isVerified) {
            return res.status(403).send("User is not verified");
        }
    } catch (error) {
        return res.status(401).send("Invalid Token");
    }
    return next();
};