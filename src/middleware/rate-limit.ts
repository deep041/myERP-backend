import rateLimit from 'express-rate-limit';
import { config } from '../config.js';

export const authRateLimiter = rateLimit({
  windowMs: config.AUTH_RATE_LIMIT_WINDOW_MS,
  limit: config.AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many authentication attempts. Try again later.',
    },
  },
});
