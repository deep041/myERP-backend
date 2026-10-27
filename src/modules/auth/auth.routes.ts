import { Router } from 'express';
import { asyncHandler } from '../../lib/async-handler.js';
import { clearAuthCookies, setAuthCookies } from '../../middleware/cookies.js';
import { requireCsrf } from '../../middleware/csrf.js';
import { authenticate } from '../../middleware/authenticate.js';
import { authRateLimiter } from '../../middleware/rate-limit.js';
import { validateBody } from '../../middleware/validate.js';
import { CSRF_COOKIE } from '../../lib/tokens.js';
import { loginSchema, registerSchema } from './auth.schemas.js';
import { getCurrentUser, loginUser, logoutSession, refreshSession, registerUser } from './auth.service.js';

export const authRouter = Router();

authRouter.post(
  '/register',
  authRateLimiter,
  validateBody(registerSchema),
  asyncHandler(async (req, res) => {
    const result = await registerUser(req.body, req);
    setAuthCookies(res, result.refreshToken, result.csrfToken);
    res.status(201).json(publicAuth(result));
  }),
);

authRouter.post(
  '/login',
  authRateLimiter,
  validateBody(loginSchema),
  asyncHandler(async (req, res) => {
    const result = await loginUser(req.body, req);
    setAuthCookies(res, result.refreshToken, result.csrfToken);
    res.status(200).json(publicAuth(result));
  }),
);

authRouter.get('/csrf', (req, res) => {
  const csrfToken = req.cookies?.[CSRF_COOKIE];
  res.status(200).json({ csrfToken: typeof csrfToken === 'string' ? csrfToken : null });
});

authRouter.post(
  '/refresh',
  authRateLimiter,
  requireCsrf,
  asyncHandler(async (req, res) => {
    const result = await refreshSession(req);
    setAuthCookies(res, result.refreshToken, result.csrfToken);
    res.status(200).json(publicAuth(result));
  }),
);

authRouter.post(
  '/logout',
  authRateLimiter,
  requireCsrf,
  asyncHandler(async (req, res) => {
    await logoutSession(req);
    clearAuthCookies(res);
    res.status(204).send();
  }),
);

authRouter.get(
  '/me',
  asyncHandler(authenticate),
  asyncHandler(async (req, res) => {
    const user = await getCurrentUser(req.user!.id);
    res.status(200).json({ user });
  }),
);

function publicAuth(result: {
  user: { id: string; name: string; email: string; createdAt: Date };
  accessToken: string;
  expiresIn: number;
  csrfToken: string;
}): object {
  return {
    user: result.user,
    accessToken: result.accessToken,
    expiresIn: result.expiresIn,
    csrfToken: result.csrfToken,
  };
}
