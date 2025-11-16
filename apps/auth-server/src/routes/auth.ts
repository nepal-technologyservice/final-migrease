import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { hashPassword, comparePassword, signAccessToken, signRefreshToken, storeRefreshToken, verifyRefresh, generateCode } from '../auth';

const prisma = new PrismaClient();

export const authRouter = Router();

// POST /api/signup
authRouter.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'missing fields' });

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: 'email already registered' });

    const passwordHash = await hashPassword(password);
    const code = generateCode(6);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await prisma.signupVerification.upsert({
      where: { email },
      update: { name, passwordHash, code, expiresAt, consumedAt: null },
      create: { name, email, passwordHash, code, expiresAt }
    });

    // TODO: send `code` to user's email (placeholder)
    console.log(`signup code for ${email}: ${code}`);

    return res.status(201).json({ ok: true, message: 'verification code sent' });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/verify-signup
authRouter.post('/api/verify-signup', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'missing fields' });

    const sv = await prisma.signupVerification.findUnique({ where: { email } });
    if (!sv) return res.status(404).json({ error: 'no verification found' });
    if (sv.consumedAt) return res.status(400).json({ error: 'code already used' });
    if (sv.code !== code) return res.status(400).json({ error: 'invalid code' });
    if (new Date(sv.expiresAt) < new Date()) return res.status(400).json({ error: 'code expired' });

    const user = await prisma.user.create({
      data: { name: sv.name, email: sv.email, passwordHash: sv.passwordHash }
    });

    await prisma.signupVerification.update({ where: { email }, data: { consumedAt: new Date() } });

    return res.status(201).json({ ok: true, userId: user.id });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/login
authRouter.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'missing fields' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const match = await comparePassword(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    const accessToken = signAccessToken({ userId: user.id });
    const refreshToken = signRefreshToken({ userId: user.id });
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await storeRefreshToken(user.id, refreshToken, expiresAt);

    // If you want cookie-based refresh:
    // res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: process.env.NODE_ENV==='production' });

    return res.json({ accessToken, refreshToken });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/refresh
authRouter.post('/api/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = await verifyRefresh(refreshToken);
    if (!payload) return res.status(401).json({ error: 'invalid_refresh' });

    const userId = (payload as any).userId;
    const accessToken = signAccessToken({ userId });

    return res.json({ accessToken });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/logout
authRouter.post('/api/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'missing token' });

    await prisma.refreshToken.updateMany({ where: { token: refreshToken }, data: { revokedAt: new Date() } });
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
});