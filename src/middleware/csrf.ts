import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../lib/errors.js';
import { CSRF_COOKIE, tokensMatch } from '../lib/tokens.js';

export function requireCsrf(req: Request, _res: Response, next: NextFunction): void {
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.get('x-csrf-token');

  if (typeof cookieToken !== 'string' || !cookieToken || typeof headerToken !== 'string' || !headerToken) {
    next(new AppError(403, 'CSRF_FAILED', 'CSRF validation failed'));
    return;
  }

  if (!tokensMatch(cookieToken, headerToken)) {
    next(new AppError(403, 'CSRF_FAILED', 'CSRF validation failed'));
    return;
  }

  next();
}
