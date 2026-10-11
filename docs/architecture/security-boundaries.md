# Security boundaries

## Implemented now

- Password verification is delegated to Passport Local and bcryptjs; no password or session cryptography is custom.
- Session data is server-side; the browser receives only an HttpOnly, SameSite cookie.
- Login rotates the session identifier after successful authentication to reduce session fixation risk.
- Browser mutations require a session-bound CSRF token in `X-CSRF-Token`; login attempts are bounded per IP/email window.
- Baseline CSP, clickjacking, MIME-sniffing, referrer, and permissions headers are emitted by the API/static server.
- PostgreSQL repository organization queries run inside transactions that set `app.current_user_id` with transaction-local `set_config`; migration policies deny rows without that context.
- Knowledge content is bounded and is never treated as trusted instructions: simple prompt-injection indicators quarantine a source before any future indexing step.
- Conversation content is bounded plain text and is returned only from the create response; list and lifecycle responses expose metadata without customer message bodies.
- API key secrets are returned only at creation and stored hashed. Webhook secrets are returned only at registration, encrypted at rest for future HMAC verification, and protected by timestamp tolerance plus persistent event-id replay checks.
- Production startup fails without a database URL or a session secret of at least 32 characters.
- Organization routes require an authenticated user and a membership in the path organization.
- Role mutation requires `admin` or `owner` privilege and writes an audit event through the repository adapter.
- PostgreSQL calls use parameterized queries.
- Development login is opt-in via `WAKEEL_ALLOW_DEV_LOGIN=true`, marked `developmentOnly`, and unavailable in production.

## Not yet production-ready

The first slice does not yet include email verification, password reset, OIDC, distributed rate-limit storage, upload malware scanning, webhook signature verification, or full production CSP asset review. RLS policy execution still requires a live PostgreSQL integration test and a separately privileged application database role; migration owners can bypass RLS by PostgreSQL design.

## Threat model

Tenant identifiers are untrusted input. A route must never use an organization identifier without loading membership for the authenticated user. A repository method must not construct SQL with identifiers from a request. Audit records are append-only from application code; administrative deletion and retention are future operational controls.
