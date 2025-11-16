"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAuth = requireAuth;
const auth_1 = require("../auth");
function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer '))
        return res.status(401).json({ error: 'unauthorized' });
    const token = header.slice(7);
    try {
        const decoded = (0, auth_1.verifyAccess)(token);
        req.authUserId = decoded.userId;
        next();
    }
    catch {
        return res.status(401).json({ error: 'invalid_token' });
    }
}
