import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import jwt, { type SignOptions } from 'jsonwebtoken';
import { config } from '../config.js';

export const REFRESH_COOKIE = 'refresh_token';
export const CSRF_COOKIE = 'csrf_token';
export const REFRESH_COOKIE_PATH = '/api/v1/auth';

export interface AccessTokenPayload {
  sub: string;
  sid: string;
}

export function generateOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function signAccessToken(payload: AccessTokenPayload): string {
  const options: SignOptions = {
    algorithm: 'HS256',
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
    issuer: 'erp-backend',
    audience: 'erp-frontend',
    subject: payload.sub,
  };
  return jwt.sign({ sid: payload.sid }, config.ACCESS_TOKEN_SECRET, options);
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  const decoded = jwt.verify(token, config.ACCESS_TOKEN_SECRET, {
    algorithms: ['HS256'],
    issuer: 'erp-backend',
    audience: 'erp-frontend',
  });

  if (typeof decoded === 'string' || typeof decoded.sub !== 'string' || typeof decoded.sid !== 'string') {
    throw new Error('Invalid access token');
  }

  return { sub: decoded.sub, sid: decoded.sid };
}

export function tokensMatch(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}
