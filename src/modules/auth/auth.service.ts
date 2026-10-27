import { randomUUID } from 'node:crypto';
import type { Request } from 'express';
import { prisma } from '../../lib/prisma.js';
import { hashPassword, verifyPassword } from '../../lib/password.js';
import { authenticationRequired, invalidCredentials } from '../../lib/errors.js';
import {
  generateOpaqueToken,
  hashToken,
  REFRESH_COOKIE,
  signAccessToken,
} from '../../lib/tokens.js';
import { config } from '../../config.js';
import type { LoginInput, RegisterInput } from './auth.schemas.js';

export interface PublicUser {
  id: string;
  name: string;
  email: string;
  createdAt: Date;
}

export interface AuthResult {
  user: PublicUser;
  accessToken: string;
  expiresIn: number;
  csrfToken: string;
  refreshToken: string;
}

const userSelect = {
  id: true,
  name: true,
  email: true,
  createdAt: true,
} as const;

function clientMeta(req: Request): { userAgent: string | null; ipAddress: string | null } {
  const userAgent = req.get('user-agent')?.slice(0, 255) ?? null;
  const ipAddress = req.ip?.slice(0, 64) ?? null;
  return { userAgent, ipAddress };
}

async function issueSession(
  user: PublicUser,
  req: Request,
  familyId = randomUUID(),
): Promise<AuthResult> {
  const refreshToken = generateOpaqueToken();
  const csrfToken = generateOpaqueToken();
  const expiresAt = new Date(Date.now() + config.REFRESH_TOKEN_TTL_SECONDS * 1000);
  const meta = clientMeta(req);

  const session = await prisma.session.create({
    data: {
      userId: user.id,
      familyId,
      tokenHash: hashToken(refreshToken),
      expiresAt,
      userAgent: meta.userAgent,
      ipAddress: meta.ipAddress,
    },
  });

  return {
    user,
    accessToken: signAccessToken({ sub: user.id, sid: session.id }),
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
    csrfToken,
    refreshToken,
  };
}

export async function registerUser(input: RegisterInput, req: Request): Promise<AuthResult> {
  const passwordHash = await hashPassword(input.password);
  const user = await prisma.user.create({
    data: {
      name: input.name,
      email: input.email,
      passwordHash,
    },
    select: userSelect,
  });

  return issueSession(user, req);
}

export async function loginUser(input: LoginInput, req: Request): Promise<AuthResult> {
  const user = await prisma.user.findUnique({
    where: { email: input.email },
  });

  const matches = await verifyPassword(user?.passwordHash ?? null, input.password);
  if (!user || !matches) {
    throw invalidCredentials();
  }

  return issueSession(
    { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt },
    req,
  );
}

export async function refreshSession(req: Request): Promise<AuthResult> {
  const presented = req.cookies?.[REFRESH_COOKIE];
  if (typeof presented !== 'string' || !presented) {
    throw authenticationRequired();
  }

  const existing = await prisma.session.findUnique({
    where: { tokenHash: hashToken(presented) },
    include: { user: { select: userSelect } },
  });

  if (!existing) {
    throw authenticationRequired();
  }

  if (existing.revokedAt) {
    await prisma.session.updateMany({
      where: { familyId: existing.familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    throw authenticationRequired();
  }

  if (existing.expiresAt <= new Date()) {
    throw authenticationRequired();
  }

  const next = await prisma.$transaction(async (tx) => {
    const claimed = await tx.session.updateMany({
      where: { id: existing.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    if (claimed.count !== 1) {
      await tx.session.updateMany({
        where: { familyId: existing.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      return null;
    }

    const refreshToken = generateOpaqueToken();
    const csrfToken = generateOpaqueToken();
    const meta = clientMeta(req);
    const created = await tx.session.create({
      data: {
        userId: existing.userId,
        familyId: existing.familyId,
        tokenHash: hashToken(refreshToken),
        expiresAt: new Date(Date.now() + config.REFRESH_TOKEN_TTL_SECONDS * 1000),
        userAgent: meta.userAgent,
        ipAddress: meta.ipAddress,
      },
    });

    await tx.session.update({
      where: { id: existing.id },
      data: { replacedById: created.id },
    });

    return { created, refreshToken, csrfToken };
  });

  if (!next) {
    throw authenticationRequired();
  }

  return {
    user: existing.user,
    accessToken: signAccessToken({ sub: existing.userId, sid: next.created.id }),
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
    csrfToken: next.csrfToken,
    refreshToken: next.refreshToken,
  };
}

export async function logoutSession(req: Request): Promise<void> {
  const presented = req.cookies?.[REFRESH_COOKIE];
  const sessionIds = new Set<string>();

  if (req.sessionId) {
    sessionIds.add(req.sessionId);
  }

  if (typeof presented === 'string' && presented) {
    const session = await prisma.session.findUnique({
      where: { tokenHash: hashToken(presented) },
      select: { id: true },
    });
    if (session) {
      sessionIds.add(session.id);
    }
  }

  if (sessionIds.size === 0) {
    return;
  }

  await prisma.session.updateMany({
    where: { id: { in: [...sessionIds] }, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function getCurrentUser(userId: string): Promise<PublicUser> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: userSelect,
  });
  if (!user) {
    throw authenticationRequired();
  }
  return user;
}
