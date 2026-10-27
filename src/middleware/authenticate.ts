import type { NextFunction, Request, Response } from 'express';
import { authenticationRequired } from '../lib/errors.js';
import { prisma } from '../lib/prisma.js';
import { verifyAccessToken } from '../lib/tokens.js';

export async function authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const header = req.get('authorization');
    if (!header?.startsWith('Bearer ')) {
      throw authenticationRequired();
    }

    const payload = verifyAccessToken(header.slice('Bearer '.length).trim());
    const session = await prisma.session.findUnique({
      where: { id: payload.sid },
      include: {
        user: {
          select: { id: true, name: true, email: true, createdAt: true },
        },
      },
    });

    if (
      !session ||
      session.userId !== payload.sub ||
      session.revokedAt ||
      session.expiresAt <= new Date()
    ) {
      throw authenticationRequired();
    }

    req.user = session.user;
    req.sessionId = session.id;
    next();
  } catch (error) {
    if (error instanceof Error && error.name === 'AppError') {
      next(error);
      return;
    }
    if (error instanceof Error && (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError' || error.name === 'NotBeforeError')) {
      next(authenticationRequired());
      return;
    }
    next(error);
  }
}
