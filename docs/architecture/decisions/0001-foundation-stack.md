# ADR 0001: smallest functional foundation

- **Status:** accepted
- **Date:** 2026-10-11

## Decision

Use Node.js 20+, Express 5, Passport Local, bcryptjs, express-session, connect-pg-simple, PostgreSQL, and parameterized `pg` queries for the first functional slice. Keep the existing static landing page and expose a separate JSON API boundary.

## Alternatives

Next.js with Auth.js would provide a more integrated full-stack convention but would require moving the static entry point and add framework-specific routing before the domain boundaries are proven. A hosted identity provider would reduce password responsibility but requires an external tenant, callback URLs, and credentials; it is a later adapter, not a deterministic local test dependency.

## Consequences

The stack is intentionally explicit and low-complexity. We must add CSRF, email/OIDC, rate limiting, RLS transaction context, and operational observability before production.
