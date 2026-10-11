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
- API-key metadata listing is tenant-scoped and never returns hashes; revocation is admin-only, persisted, and audited. The current slice does not yet authenticate inbound API requests with these keys.
- Error responses expose only a request ID and stable error code; server-side error events persist bounded metadata without stack traces or secrets. Tenant-associated events are RLS-scoped.
- Knowledge ingestion requests may provide a bounded idempotency key. Jobs are unique per tenant/key and only queued; no fetch, parsing, embedding, or provider execution is claimed.
- Subscription state has no local checkout or payment success path. It changes only after webhook signature and replay validation, with tenant-scoped state and billing-event records.
- Audit retrieval is restricted to tenant admins, bounded to 100 records per request, and removes metadata keys that resemble secrets, tokens, hashes, passwords, or ciphertext.
- Password recovery tokens are random, stored only as hashes, expire after one hour, and are single-use. Requests return a generic accepted response; email delivery and account verification remain external integration boundaries.
- Production startup fails without a database URL or a session secret of at least 32 characters.
- Organization routes require an authenticated user and a membership in the path organization.
- Role mutation requires `admin` or `owner` privilege and writes an audit event through the repository adapter.
- PostgreSQL calls use parameterized queries.
- Development login is opt-in via `WAKEEL_ALLOW_DEV_LOGIN=true`, marked `developmentOnly`, and unavailable in production.

## Not yet production-ready

The first slice does not yet include email verification, password reset, OIDC, distributed rate-limit storage, upload malware scanning, webhook signature verification, or full production CSP asset review. RLS policy execution still requires a live PostgreSQL integration test and a separately privileged application database role; migration owners can bypass RLS by PostgreSQL design.

## Threat model

Tenant identifiers are untrusted input. A route must never use an organization identifier without loading membership for the authenticated user. A repository method must not construct SQL with identifiers from a request. Audit records are append-only from application code; administrative deletion and retention are future operational controls.
