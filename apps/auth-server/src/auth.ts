import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

export async function hashPassword(password: string) {
  return bcrypt.hash(password, 10);
}

export async function comparePassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export function signAccessToken(payload: object) {
  const secret = process.env.JWT_SECRET as string;
  return jwt.sign(payload, secret, { expiresIn: '15m' });
}

export function signRefreshToken(payload: object) {
  const secret = process.env.JWT_SECRET as string;
  return jwt.sign(payload, secret, { expiresIn: '7d' });
}

export async function storeRefreshToken(userId: string, token: string, expiresAt: Date) {
  return prisma.refreshToken.create({ data: { userId, token, expiresAt } });
}

export async function verifyRefresh(token: string | undefined) {
  if (!token) return null;
  try {
    const secret = process.env.JWT_SECRET as string;
    const payload = jwt.verify(token, secret) as any;
    const dbToken = await prisma.refreshToken.findUnique({ where: { token } });
    if (!dbToken) return null;
    if (dbToken.revokedAt) return null;
    if (new Date(dbToken.expiresAt) < new Date()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function generateCode(len = 6) {
  return Math.random().toString().slice(2, 2 + len);
}

export async function verifyAccess(token: string | undefined) {
  if (!token) return null;
  try {
    const secret = process.env.JWT_SECRET as string;
    if (!secret) return null;
    const payload = jwt.verify(token.replace(/^Bearer\s+/i, ''), secret) as any;
    // optional: verify user exists
    const user = await prisma.user.findUnique({ where: { id: payload.userId } });
    if (!user) return null;
    return payload;
  } catch {
    return null;
  }
}

// middleware helper (optional export) for Express
export function requireAuth(req: any, res: any, next: any) {
  const authHeader = req.headers?.authorization;
  verifyAccess(authHeader)
    .then((payload) => {
      if (!payload) return res.status(401).json({ error: 'unauthorized' });
      req.user = payload;
      next();
    })
    .catch(() => res.status(401).json({ error: 'unauthorized' }));
}