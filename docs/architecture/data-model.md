# Data model

The first migration creates:

- `users`: login identity and bcrypt password hash.
- `organizations`: tenant boundary.
- `memberships`: user-to-organization relationship with `owner`, `admin`, `member`, or `viewer`.
- `audit_events`: organization-scoped security and administration trail.
- `agent_configs`: one tenant-scoped agent draft with validated language, instructions, and guardrails; it configures behavior but does not execute an AI provider.
- `knowledge_sources`: tenant-scoped manual/URL source metadata and bounded text. New content is `pending` or `quarantined`; no URL fetch, file parser, embedding, or AI execution is implied.
- `conversations`: tenant-scoped support records with bounded plain text, channel, status, and optional member assignment. List responses omit customer message content; no outbound messaging is performed.
- `user_sessions`: server-side `express-session` records for `connect-pg-simple`.

All identifiers are UUIDs except the human-readable organization key. Membership has a composite primary key. Future domain tables must carry `organization_id` and be protected by membership checks plus transaction-scoped PostgreSQL RLS.

The migration enables RLS on organizations, memberships, and audit events. Repository organization reads and writes use a transaction-local `app.current_user_id`; missing context yields no rows under the policies. Deployments must use a non-owner application role so owner bypass cannot defeat these policies.

## Migration and seed

Run `npm run db:migrate` and then `WAKEEL_SEED_PASSWORD=... npm run db:seed` with `WAKEEL_DATABASE_URL` set. The seed account is local bootstrap data, not a production credential. Do not commit the password or database URL.
