import { Request, Response, NextFunction } from 'express';
import { verifyAccess } from '../auth';

export interface AuthRequest extends Request {
  authUserId?: string;
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  const token = header.slice(7);
  try {
    const decoded: any = verifyAccess(token);
    req.authUserId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}