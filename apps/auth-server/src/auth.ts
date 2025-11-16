import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const accessTTL = Number(process.env.JWT_ACCESS_TTL_SECONDS || 900);
const refreshTTL = Number(process.env.JWT_REFRESH_TTL_SECONDS || 2592000);

export async function hashPassword(pw: string) {
  return bcrypt.hash(pw, 12);
}
export async function verifyPassword(pw: string, hash: string) {
  return bcrypt.compare(pw, hash);
}

export function signAccess(userId: string) {
  return jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET!, { expiresIn: accessTTL });
}
export function signRefresh(userId: string, tokenId: string) {
  return jwt.sign({ userId, tokenId }, process.env.JWT_REFRESH_SECRET!, { expiresIn: refreshTTL });
}

export function verifyAccess(token: string): any {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
}
export function verifyRefresh(token: string): any {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
}