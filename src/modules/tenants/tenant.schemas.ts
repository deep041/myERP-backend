import { z } from 'zod';

export const createTenantSchema = z.object({
  name: z.string().trim().min(1).max(120),
});

export const tenantParamsSchema = z.object({
  id: z.string().uuid(),
});

export type CreateTenantInput = z.infer<typeof createTenantSchema>;
