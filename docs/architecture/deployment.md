# Deployment

## Local

1. Install Node.js 20+ and PostgreSQL.
2. Copy `.env.example` to an ignored environment file and set `WAKEEL_DATABASE_URL` and `WAKEEL_SESSION_SECRET`.
3. Run `npm install`, `npm run db:migrate`, and `npm run db:seed`.
4. Start with `npm run dev`; the landing page remains at `/` and API health is `/health`.

For deterministic tests, no database is required: `npm test` uses the explicit memory repository. That adapter must not be enabled in production.

## Deployment controls

Use a managed PostgreSQL service, TLS, a secret manager, health checks, structured logs, and a reverse proxy that supplies the canonical HTTPS origin. Set `NODE_ENV=production`; startup then requires the database URL and strong session secret. Run migrations as a controlled release step, not on every web process boot. Backups, restore drills, retention, CSP/security headers, rate limits, and alerting remain required before production.
