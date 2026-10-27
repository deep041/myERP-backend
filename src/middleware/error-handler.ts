import type { NextFunction, Request, Response } from 'express';
import { Prisma } from '@prisma/client';
import { ZodError } from 'zod';
import { AppError } from '../lib/errors.js';
import { config } from '../config.js';

export function notFoundHandler(_req: Request, _res: Response, next: NextFunction): void {
  next(new AppError(404, 'NOT_FOUND', 'Resource not found'));
}

export function errorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction): void {
  if (error instanceof AppError) {
    res.status(error.status).json({
      error: {
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
    });
    return;
  }

  if (error instanceof ZodError) {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      },
    });
    return;
  }

  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
    const rawTarget = error.meta?.['target'];
    const target = Array.isArray(rawTarget) ? rawTarget.join(',') : String(rawTarget ?? '');
    if (target.includes('email')) {
      res.status(409).json({
        error: {
          code: 'EMAIL_TAKEN',
          message: 'An account with this email already exists',
        },
      });
      return;
    }
  }

  if (config.NODE_ENV !== 'production') {
    console.error(error);
  }

  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Something went wrong',
    },
  });
}
