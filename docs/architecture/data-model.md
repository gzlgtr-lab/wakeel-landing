# Data model

The first migration creates:

- `users`: login identity and bcrypt password hash.
- `organizations`: tenant boundary.
- `memberships`: user-to-organization relationship with `owner`, `admin`, `member`, or `viewer`.
- `audit_events`: organization-scoped security and administration trail.
- `user_sessions`: server-side `express-session` records for `connect-pg-simple`.

All identifiers are UUIDs except the human-readable organization key. Membership has a composite primary key. Future domain tables must carry `organization_id` and be protected by membership checks plus transaction-scoped PostgreSQL RLS.

## Migration and seed

Run `npm run db:migrate` and then `WAKEEL_SEED_PASSWORD=... npm run db:seed` with `WAKEEL_DATABASE_URL` set. The seed account is local bootstrap data, not a production credential. Do not commit the password or database URL.
