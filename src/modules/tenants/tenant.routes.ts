import { Router } from 'express';
import { asyncHandler } from '../../lib/async-handler.js';
import { authenticate } from '../../middleware/authenticate.js';
import { validateBody, validateParams } from '../../middleware/validate.js';
import { createTenantSchema, tenantParamsSchema } from './tenant.schemas.js';
import { createTenant, getTenant, listTenants } from './tenant.service.js';

export const tenantRouter = Router();

tenantRouter.use(asyncHandler(authenticate));

tenantRouter.post(
  '/',
  validateBody(createTenantSchema),
  asyncHandler(async (req, res) => {
    const tenant = await createTenant(req.user!.id, req.body);
    res.status(201).json({ tenant });
  }),
);

tenantRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const tenants = await listTenants(req.user!.id);
    res.status(200).json({ tenants });
  }),
);

tenantRouter.get(
  '/:id',
  validateParams(tenantParamsSchema),
  asyncHandler(async (req, res) => {
    const tenant = await getTenant(req.user!.id, req.params.id);
    res.status(200).json({ tenant });
  }),
);
