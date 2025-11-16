import { Router } from 'express';
import crypto from 'node:crypto';
import { hashPassword, verifyPassword, signAccess, signRefresh } from '../auth';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// helper used by this file to validate refresh tokens
async function verifyRefresh(token: string) {
  if (!token) return null;
  try {
    const secret = process.env.JWT_SECRET as string;
    if (!secret) return null;

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

export const authRouter = Router();

const OTP_CODE = '123456';

// Start signup: create/update pending; DO NOT create user here
authRouter.post('/register/start', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'missing_fields' });

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) return res.status(409).json({ error: 'email_taken' });

  const passwordHash = await hashPassword(password);

  const pending = await prisma.signupVerification.upsert({
    where: { email },
    create: {
      name,
      email,
      passwordHash,
      code: OTP_CODE,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    },
    update: {
      name,
      passwordHash,
      code: OTP_CODE,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      consumedAt: null,
    },
  });

  const masked = email.includes('@') ? email.replace(/(.{2}).+(@.+)/, '$1***$2') : email;
  return res.status(201).json({ otpId: pending.id, masked });
});

// Alias: some clients may call /auth/register
authRouter.post('/register', async (req, res, next) => {
  req.url = '/register/start';
  next();
});

// Verify: ONLY here user is created; OTP must be 123456
authRouter.post('/register/verify', async (req, res) => {
  const { otpId, code } = req.body || {};
  if (!otpId || !code) return res.status(400).json({ error: 'missing_fields' });

  const pending = await prisma.signupVerification.findUnique({ where: { id: otpId } });
  if (!pending) return res.status(404).json({ error: 'not_found' });
  if (pending.consumedAt) return res.status(409).json({ error: 'already_used' });
  if (pending.expiresAt < new Date()) return res.status(410).json({ error: 'expired' });
  if (String(code) !== OTP_CODE) return res.status(401).json({ error: 'invalid_code' });

  let user = await prisma.user.findUnique({ where: { email: pending.email } });
  if (!user) {
    user = await prisma.user.create({
      data: {
        name: pending.name,
        email: pending.email,
        passwordHash: pending.passwordHash,
        emailVerifiedAt: new Date(),
      },
    });
  } else if (!user.emailVerifiedAt) {
    await prisma.user.update({ where: { id: user.id }, data: { emailVerifiedAt: new Date() } });
  }

  await prisma.signupVerification.update({ where: { id: pending.id }, data: { consumedAt: new Date() } });
  return res.json({ ok: true, verified: true });
});

// Resend (OTP fixed)
authRouter.post('/resend', async (req, res) => {
  const { otpId } = req.body || {};
  if (!otpId) return res.status(400).json({ error: 'missing_otpId' });
  const pending = await prisma.signupVerification.findUnique({ where: { id: otpId } });
  if (!pending) return res.status(404).json({ error: 'not_found' });
  return res.json({ ok: true, info: 'Use 123456' });
});

// Login: block unverified accounts
authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.emailVerifiedAt) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const tokenId = crypto.randomUUID();
  const refreshRow = await prisma.refreshToken.create({
    data: {
      userId: user.id,
      token: tokenId,
      expiresAt: new Date(Date.now() + Number(process.env.JWT_REFRESH_TTL_SECONDS || 2592000) * 1000),
    },
  });

  return res.json({
    user: { id: user.id, name: user.name, email: user.email },
    access: signAccess(user.id),
    refresh: signRefresh(user.id, refreshRow.token),
  });
});

// Refresh
authRouter.post('/refresh', async (req, res) => {
  const { refresh } = req.body || {};
  if (!refresh) return res.status(400).json({ error: 'missing_refresh' });
  try {
    const decoded: any = verifyRefresh(refresh);
    const row = await prisma.refreshToken.findUnique({ where: { token: decoded.tokenId } });
    if (!row || row.userId !== decoded.userId || row.expiresAt < new Date() || row.revokedAt) {
      return res.status(401).json({ error: 'invalid_refresh' });
    }
    res.json({ access: signAccess(decoded.userId) });
  } catch {
    return res.status(401).json({ error: 'invalid_refresh' });
  }
});

// Me
authRouter.get('/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try {
    const decoded: any = require('../auth').verifyAccess(auth.slice(7));
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) return res.status(404).json({ error: 'not_found' });
    res.json({ id: user.id, name: user.name, email: user.email });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// Logout
authRouter.post('/logout', async (req, res) => {
  const { refresh } = req.body || {};
  if (refresh) {
    try {
      const decoded: any = verifyRefresh(refresh);
      await prisma.refreshToken.updateMany({ where: { token: decoded.tokenId }, data: { revokedAt: new Date() } });
    } catch {}
  }
  res.json({ ok: true });
});