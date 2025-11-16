"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashPassword = hashPassword;
exports.comparePassword = comparePassword;
exports.signAccessToken = signAccessToken;
exports.signRefreshToken = signRefreshToken;
exports.storeRefreshToken = storeRefreshToken;
exports.verifyRefresh = verifyRefresh;
exports.generateCode = generateCode;
exports.verifyAccess = verifyAccess;
exports.requireAuth = requireAuth;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const client_1 = require("@prisma/client");
const prisma = new client_1.PrismaClient();
async function hashPassword(password) {
    return bcryptjs_1.default.hash(password, 10);
}
async function comparePassword(password, hash) {
    return bcryptjs_1.default.compare(password, hash);
}
function signAccessToken(payload) {
    const secret = process.env.JWT_SECRET;
    return jsonwebtoken_1.default.sign(payload, secret, { expiresIn: '15m' });
}
function signRefreshToken(payload) {
    const secret = process.env.JWT_SECRET;
    return jsonwebtoken_1.default.sign(payload, secret, { expiresIn: '7d' });
}
async function storeRefreshToken(userId, token, expiresAt) {
    return prisma.refreshToken.create({ data: { userId, token, expiresAt } });
}
async function verifyRefresh(token) {
    if (!token)
        return null;
    try {
        const secret = process.env.JWT_SECRET;
        const payload = jsonwebtoken_1.default.verify(token, secret);
        const dbToken = await prisma.refreshToken.findUnique({ where: { token } });
        if (!dbToken)
            return null;
        if (dbToken.revokedAt)
            return null;
        if (new Date(dbToken.expiresAt) < new Date())
            return null;
        return payload;
    }
    catch {
        return null;
    }
}
function generateCode(len = 6) {
    return Math.random().toString().slice(2, 2 + len);
}
async function verifyAccess(token) {
    if (!token)
        return null;
    try {
        const secret = process.env.JWT_SECRET;
        if (!secret)
            return null;
        const payload = jsonwebtoken_1.default.verify(token.replace(/^Bearer\s+/i, ''), secret);
        // optional: verify user exists
        const user = await prisma.user.findUnique({ where: { id: payload.userId } });
        if (!user)
            return null;
        return payload;
    }
    catch {
        return null;
    }
}
// middleware helper (optional export) for Express
function requireAuth(req, res, next) {
    const authHeader = req.headers?.authorization;
    verifyAccess(authHeader)
        .then((payload) => {
        if (!payload)
            return res.status(401).json({ error: 'unauthorized' });
        req.user = payload;
        next();
    })
        .catch(() => res.status(401).json({ error: 'unauthorized' }));
}
