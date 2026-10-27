import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { after, before, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Prisma } from '@prisma/client';
import pg from 'pg';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://erp:erp_dev_password@localhost:5433/erp_test';
process.env.ACCESS_TOKEN_SECRET = 'test-access-token-secret-must-be-32';
process.env.ACCESS_TOKEN_TTL_SECONDS = '900';
process.env.REFRESH_TOKEN_TTL_SECONDS = '604800';
process.env.COOKIE_SECURE = 'false';
process.env.CORS_ORIGIN = 'http://localhost:4200';
process.env.AUTH_RATE_LIMIT_WINDOW_MS = '900000';
process.env.AUTH_RATE_LIMIT_MAX = '10000';

const { createApp } = await import('../src/app.ts');
const { prisma } = await import('../src/lib/prisma.ts');
const { hashPassword } = await import('../src/lib/password.ts');

const app = createApp();

function cookieValue(setCookie: string | string[] | undefined, name: string): string {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const row = list.find((cookie) => cookie.startsWith(`${name}=`));
  assert.ok(row, `expected cookie ${name}`);
  return row.split(';')[0]!.slice(name.length + 1);
}

function cookieFlags(setCookie: string | string[] | undefined, name: string): string {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const row = list.find((cookie) => cookie.startsWith(`${name}=`));
  assert.ok(row, `expected cookie ${name}`);
  return row;
}

async function ensureTestDatabase(): Promise<void> {
  const admin = new pg.Client({
    connectionString: 'postgresql://erp:erp_dev_password@localhost:5433/erp',
  });
  await admin.connect();
  const existing = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', ['erp_test']);
  if (existing.rowCount === 0) {
    await admin.query('CREATE DATABASE erp_test');
  }
  await admin.end();
}

async function clearDatabase(): Promise<void> {
  assert.ok(process.env.DATABASE_URL?.includes('/erp_test'), 'refusing to wipe a non-test database');
  await prisma.session.deleteMany();
  await prisma.tenantMembership.deleteMany();
  await prisma.tenant.deleteMany();
  await prisma.user.deleteMany();
}

describe('auth and companies', () => {
  before(async () => {
    await ensureTestDatabase();
    execFileSync('npx', ['prisma', 'migrate', 'deploy'], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
      env: process.env,
      stdio: 'inherit',
      shell: true,
    });
  });

  beforeEach(async () => {
    await clearDatabase();
  });

  after(async () => {
    await prisma.$disconnect();
  });

  it('registers and logs in without exposing secrets', async () => {
    const registered = await request(app).post('/api/v1/auth/register').send({
      name: 'Ada Lovelace',
      email: 'ada@example.com',
      password: 'correct-horse',
    });

    assert.equal(registered.status, 201);
    assert.equal(registered.body.user.email, 'ada@example.com');
    assert.equal(registered.body.user.name, 'Ada Lovelace');
    assert.equal(typeof registered.body.accessToken, 'string');
    assert.equal(registered.body.passwordHash, undefined);
    assert.equal(registered.body.refreshToken, undefined);
    assert.equal(JSON.stringify(registered.body).includes('passwordHash'), false);

    const refreshCookie = cookieFlags(registered.headers['set-cookie'], 'refresh_token');
    assert.match(refreshCookie, /HttpOnly/i);
    assert.match(refreshCookie, /SameSite=Lax/i);
    const csrfCookie = cookieFlags(registered.headers['set-cookie'], 'csrf_token');
    assert.doesNotMatch(csrfCookie, /HttpOnly/i);

    const me = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${registered.body.accessToken}`);
    assert.equal(me.status, 200);
    assert.equal(me.body.user.email, 'ada@example.com');
    assert.equal(me.body.user.passwordHash, undefined);

    const loggedIn = await request(app).post('/api/v1/auth/login').send({
      email: 'ada@example.com',
      password: 'correct-horse',
    });
    assert.equal(loggedIn.status, 200);
    assert.equal(loggedIn.body.user.email, 'ada@example.com');
    assert.equal(typeof loggedIn.body.accessToken, 'string');
  });

  it('rejects duplicate email registration', async () => {
    const payload = { name: 'Grace', email: 'grace@example.com', password: 'correct-horse' };
    const first = await request(app).post('/api/v1/auth/register').send(payload);
    assert.equal(first.status, 201);

    const second = await request(app).post('/api/v1/auth/register').send(payload);
    assert.equal(second.status, 409);
    assert.equal(second.body.error.code, 'EMAIL_TAKEN');
  });

  it('returns a generic error for invalid credentials', async () => {
    await request(app).post('/api/v1/auth/register').send({
      name: 'Grace',
      email: 'grace@example.com',
      password: 'correct-horse',
    });

    const wrongPassword = await request(app).post('/api/v1/auth/login').send({
      email: 'grace@example.com',
      password: 'wrong-password',
    });
    const unknownEmail = await request(app).post('/api/v1/auth/login').send({
      email: 'missing@example.com',
      password: 'correct-horse',
    });

    assert.equal(wrongPassword.status, 401);
    assert.equal(unknownEmail.status, 401);
    assert.equal(wrongPassword.body.error.message, 'Invalid email or password');
    assert.equal(unknownEmail.body.error.message, wrongPassword.body.error.message);
  });

  it('rotates refresh tokens and revokes the family when an old token is reused', async () => {
    const registered = await request(app).post('/api/v1/auth/register').send({
      name: 'Alan',
      email: 'alan@example.com',
      password: 'correct-horse',
    });
    const firstRefresh = cookieValue(registered.headers['set-cookie'], 'refresh_token');
    const firstCsrf = registered.body.csrfToken as string;

    const rotated = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refresh_token=${firstRefresh}`, `csrf_token=${firstCsrf}`])
      .set('X-CSRF-Token', firstCsrf);

    assert.equal(rotated.status, 200);
    const secondRefresh = cookieValue(rotated.headers['set-cookie'], 'refresh_token');
    const secondCsrf = rotated.body.csrfToken as string;
    assert.notEqual(secondRefresh, firstRefresh);
    assert.notEqual(rotated.body.accessToken, registered.body.accessToken);

    const me = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${rotated.body.accessToken}`);
    assert.equal(me.status, 200);

    const reused = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refresh_token=${firstRefresh}`, `csrf_token=${firstCsrf}`])
      .set('X-CSRF-Token', firstCsrf);
    assert.equal(reused.status, 401);

    const afterReuse = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refresh_token=${secondRefresh}`, `csrf_token=${secondCsrf}`])
      .set('X-CSRF-Token', secondCsrf);
    assert.equal(afterReuse.status, 401);

    const oldAccess = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${registered.body.accessToken}`);
    assert.equal(oldAccess.status, 401);
  });

  it('logs out and rejects the revoked session', async () => {
    const registered = await request(app).post('/api/v1/auth/register').send({
      name: 'Katherine',
      email: 'katherine@example.com',
      password: 'correct-horse',
    });
    const refresh = cookieValue(registered.headers['set-cookie'], 'refresh_token');
    const csrf = registered.body.csrfToken as string;

    const logout = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', [`refresh_token=${refresh}`, `csrf_token=${csrf}`])
      .set('X-CSRF-Token', csrf);
    assert.equal(logout.status, 204);

    const me = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${registered.body.accessToken}`);
    assert.equal(me.status, 401);

    const refreshAgain = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refresh_token=${refresh}`, `csrf_token=${csrf}`])
      .set('X-CSRF-Token', csrf);
    assert.equal(refreshAgain.status, 401);
  });

  it('creates a company for the authenticated owner', async () => {
    const registered = await request(app).post('/api/v1/auth/register').send({
      name: 'Owner',
      email: 'owner@example.com',
      password: 'correct-horse',
    });
    const token = registered.body.accessToken as string;

    const unauthenticated = await request(app).post('/api/v1/tenants').send({ name: 'Nope' });
    assert.equal(unauthenticated.status, 401);

    const created = await request(app)
      .post('/api/v1/tenants')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Northwind' });
    assert.equal(created.status, 201);
    assert.equal(created.body.tenant.name, 'Northwind');
    assert.equal(created.body.tenant.role, 'OWNER');
    assert.equal(created.body.tenant.ownerId, registered.body.user.id);

    const fetched = await request(app)
      .get(`/api/v1/tenants/${created.body.tenant.id}`)
      .set('Authorization', `Bearer ${token}`);
    assert.equal(fetched.status, 200);
    assert.equal(fetched.body.tenant.name, 'Northwind');
  });

  it('hides companies from users who are not members and lists every company a user belongs to', async () => {
    const owner = await request(app).post('/api/v1/auth/register').send({
      name: 'Owner',
      email: 'multi-owner@example.com',
      password: 'correct-horse',
    });
    const other = await request(app).post('/api/v1/auth/register').send({
      name: 'Other',
      email: 'other@example.com',
      password: 'correct-horse',
    });

    const first = await request(app)
      .post('/api/v1/tenants')
      .set('Authorization', `Bearer ${owner.body.accessToken}`)
      .send({ name: 'Alpha' });
    const second = await request(app)
      .post('/api/v1/tenants')
      .set('Authorization', `Bearer ${owner.body.accessToken}`)
      .send({ name: 'Beta' });
    assert.equal(first.status, 201);
    assert.equal(second.status, 201);

    const ownList = await request(app)
      .get('/api/v1/tenants')
      .set('Authorization', `Bearer ${owner.body.accessToken}`);
    assert.equal(ownList.status, 200);
    assert.deepEqual(
      ownList.body.tenants.map((tenant: { name: string }) => tenant.name),
      ['Alpha', 'Beta'],
    );

    const otherList = await request(app)
      .get('/api/v1/tenants')
      .set('Authorization', `Bearer ${other.body.accessToken}`);
    assert.equal(otherList.status, 200);
    assert.deepEqual(otherList.body.tenants, []);

    const denied = await request(app)
      .get(`/api/v1/tenants/${first.body.tenant.id}`)
      .set('Authorization', `Bearer ${other.body.accessToken}`);
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error.message, 'You do not have access to this company');

    const missing = await request(app)
      .get('/api/v1/tenants/11111111-1111-4111-8111-111111111111')
      .set('Authorization', `Bearer ${other.body.accessToken}`);
    assert.equal(missing.status, 404);
  });

  it('rejects a duplicate membership at the database', async () => {
    const passwordHash = await hashPassword('correct-horse');
    const user = await prisma.user.create({
      data: { name: 'Member', email: 'member@example.com', passwordHash },
    });
    const tenant = await prisma.tenant.create({
      data: {
        name: 'Shared',
        ownerId: user.id,
        memberships: { create: { userId: user.id, role: 'OWNER' } },
      },
    });

    await assert.rejects(
      () =>
        prisma.tenantMembership.create({
          data: { tenantId: tenant.id, userId: user.id, role: 'ADMIN' },
        }),
      (error: unknown) => error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002',
    );
  });
});
