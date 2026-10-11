# Wakeel system overview

## Current milestone

The Phase 3 foundation keeps `index.html` and the Phase 2 `app.html` preview intact, and adds a Node.js/Express application boundary. Protected JSON routes use Passport Local for password verification and `express-session` for server-side sessions. The repository is deliberately split into an HTTP layer, a repository adapter, and a PostgreSQL migration so later providers can be changed without changing authorization rules.

The local test adapter is deterministic and memory-backed. It is test/development infrastructure only and is never selected in production. Production requires `WAKEEL_DATABASE_URL`, a strong `WAKEEL_SESSION_SECRET`, and a PostgreSQL-backed session store.

## Official documentation reviewed

- [Express session middleware](https://expressjs.com/en/resources/middleware/session.html): session IDs are cookies while session data stays server-side; the default memory store is not production-ready.
- [Passport authentication concepts](https://www.passportjs.org/concepts/authentication/downloads/html/): strategies, middleware, and sessions are separate concerns.
- [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html): enabled policies default-deny and table owners can bypass them unless forced.
- [node-postgres parameterized queries](https://node-postgres.com/features/queries): request values are parameters, never interpolated SQL.
- [Node.js test runner](https://nodejs.org/api/test.html): the built-in runner supports synchronous and asynchronous tests without an additional framework.

## Major choices

| Concern | Selected | Alternative considered | Reason |
| --- | --- | --- | --- |
| Web runtime | Node.js + Express 5 | Next.js App Router | The existing static site can be served unchanged and the first slice needs a small explicit API boundary. |
| Auth | Passport Local + bcryptjs + server sessions | Auth.js / hosted OIDC only | Passport separates authentication strategy from application authorization; OIDC remains a later provider adapter. |
| Database | PostgreSQL + parameterized `pg` queries | Prisma or Drizzle | Fewer moving parts for the first slice; SQL migrations remain inspectable and portable. |
| Session store | `connect-pg-simple` | Redis-backed sessions | Reuses the required PostgreSQL infrastructure and keeps session state server-side. |
| Tests | Node built-in test runner + Supertest | Vitest + Playwright | Fast HTTP authorization coverage now; browser tests are a later milestone. |

## Boundaries

The public landing page is static and has no authenticated state. `/api/*` is server-owned. Organization membership is checked on every organization route; role checks are performed after membership checks. No route accepts provider secrets, card details, or claims to execute AI, billing, uploads, or webhooks yet.

## Next milestones

Add transaction-scoped PostgreSQL RLS policies, migrations table, organization invites, CSRF protection for browser mutations, knowledge uploads and jobs, conversations, and provider adapters only behind explicit integration contracts.
