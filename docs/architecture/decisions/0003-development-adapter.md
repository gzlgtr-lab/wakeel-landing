# ADR 0003: explicit development adapter

- **Status:** accepted
- **Date:** 2026-10-11

## Decision

Use an in-memory repository only in tests and opt-in local development. It is deterministic, contains no external credentials, and returns `developmentOnly` for the dev login route. Production startup requires PostgreSQL and disables the route.

## Alternatives

SQLite would improve local persistence but diverges from the required PostgreSQL behavior. A hosted preview database would introduce secrets and non-deterministic test state.
