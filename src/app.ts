import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { config } from './config.js';
import { errorHandler, notFoundHandler } from './middleware/error-handler.js';
import { authRouter } from './modules/auth/auth.routes.js';
import { tenantRouter } from './modules/tenants/tenant.routes.js';

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(
    cors({
      origin: config.CORS_ORIGIN,
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    }),
  );
  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use('/api/v1/auth', authRouter);
  app.use('/api/v1/tenants', tenantRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
