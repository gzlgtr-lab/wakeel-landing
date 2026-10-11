# ADR 0002: membership-first authorization

- **Status:** accepted
- **Date:** 2026-10-11

## Decision

Every protected organization route authenticates first, loads membership for the authenticated user and requested organization, then applies a minimum role. Repository methods receive the authenticated identity rather than trusting a client-supplied role.

## Alternatives

JWT claims alone were rejected because revocation and membership changes would lag token expiry. Client-only RBAC was rejected because it cannot protect data access.

## Consequences

The first slice is safe against cross-tenant route access and unauthorized role mutation. PostgreSQL RLS will be added when request transactions consistently set a tenant context.
