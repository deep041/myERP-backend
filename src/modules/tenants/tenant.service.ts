import type { MembershipRole } from '@prisma/client';
import { AppError } from '../../lib/errors.js';
import { prisma } from '../../lib/prisma.js';
import type { CreateTenantInput } from './tenant.schemas.js';

export interface TenantView {
  id: string;
  name: string;
  ownerId: string;
  role: MembershipRole;
  createdAt: Date;
}

function toView(tenant: { id: string; name: string; ownerId: string; createdAt: Date }, role: MembershipRole): TenantView {
  return {
    id: tenant.id,
    name: tenant.name,
    ownerId: tenant.ownerId,
    role,
    createdAt: tenant.createdAt,
  };
}

export async function createTenant(userId: string, input: CreateTenantInput): Promise<TenantView> {
  const tenant = await prisma.$transaction(async (tx) => {
    return tx.tenant.create({
      data: {
        name: input.name,
        ownerId: userId,
        memberships: {
          create: {
            userId,
            role: 'OWNER',
          },
        },
      },
    });
  });

  return toView(tenant, 'OWNER');
}

export async function listTenants(userId: string): Promise<TenantView[]> {
  const memberships = await prisma.tenantMembership.findMany({
    where: { userId },
    include: { tenant: true },
    orderBy: { tenant: { createdAt: 'asc' } },
  });

  return memberships.map((membership) => toView(membership.tenant, membership.role));
}

export async function getTenant(userId: string, tenantId: string): Promise<TenantView> {
  const membership = await prisma.tenantMembership.findUnique({
    where: { tenantId_userId: { tenantId, userId } },
    include: { tenant: true },
  });

  if (!membership) {
    const exists = await prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true },
    });
    if (!exists) {
      throw new AppError(404, 'NOT_FOUND', 'Company not found');
    }
    throw new AppError(403, 'FORBIDDEN', 'You do not have access to this company');
  }

  return toView(membership.tenant, membership.role);
}
