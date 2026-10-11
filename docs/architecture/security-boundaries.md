# Security boundaries

## Implemented now

- Password verification is delegated to Passport Local and bcryptjs; no password or session cryptography is custom.
- Session data is server-side; the browser receives only an HttpOnly, SameSite cookie.
- Production startup fails without a database URL or a session secret of at least 32 characters.
- Organization routes require an authenticated user and a membership in the path organization.
- Role mutation requires `admin` or `owner` privilege and writes an audit event through the repository adapter.
- PostgreSQL calls use parameterized queries.
- Development login is opt-in via `WAKEEL_ALLOW_DEV_LOGIN=true`, marked `developmentOnly`, and unavailable in production.

## Not yet production-ready

The first slice does not yet include CSRF tokens, email verification, password reset, OIDC, rate limiting, RLS policies, upload malware scanning, webhook signature verification, or security headers/CSP. These are release blockers, not hidden assumptions. PostgreSQL RLS will be enabled only when every request transaction sets `app.current_user_id` with `SET LOCAL` and policies are tested.

## Threat model

Tenant identifiers are untrusted input. A route must never use an organization identifier without loading membership for the authenticated user. A repository method must not construct SQL with identifiers from a request. Audit records are append-only from application code; administrative deletion and retention are future operational controls.
