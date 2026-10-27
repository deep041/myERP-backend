import type { CookieOptions, Response } from 'express';
import { config } from '../config.js';
import { CSRF_COOKIE, REFRESH_COOKIE, REFRESH_COOKIE_PATH } from '../lib/tokens.js';

function baseCookie(): CookieOptions {
  return {
    secure: config.COOKIE_SECURE,
    sameSite: 'lax',
  };
}

export function setAuthCookies(res: Response, refreshToken: string, csrfToken: string): void {
  res.cookie(REFRESH_COOKIE, refreshToken, {
    ...baseCookie(),
    httpOnly: true,
    path: REFRESH_COOKIE_PATH,
    maxAge: config.REFRESH_TOKEN_TTL_SECONDS * 1000,
  });
  res.cookie(CSRF_COOKIE, csrfToken, {
    ...baseCookie(),
    httpOnly: false,
    path: '/',
    maxAge: config.REFRESH_TOKEN_TTL_SECONDS * 1000,
  });
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie(REFRESH_COOKIE, {
    ...baseCookie(),
    httpOnly: true,
    path: REFRESH_COOKIE_PATH,
  });
  res.clearCookie(CSRF_COOKIE, {
    ...baseCookie(),
    httpOnly: false,
    path: '/',
  });
}
