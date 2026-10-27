import type { NextFunction, Request, Response } from 'express';
import { ZodError, type ZodType } from 'zod';
import { AppError } from '../lib/errors.js';

export function validateBody<T>(schema: ZodType<T>) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      next(validationError(parsed.error));
      return;
    }
    req.body = parsed.data;
    next();
  };
}

export function validateParams<T>(schema: ZodType<T>) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.params);
    if (!parsed.success) {
      next(validationError(parsed.error));
      return;
    }
    req.params = parsed.data as Request['params'];
    next();
  };
}

function validationError(error: ZodError): AppError {
  return new AppError(
    400,
    'VALIDATION_ERROR',
    'Request validation failed',
    error.issues.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    })),
  );
}
