# Capability matrix

| Capability | Local foundation | Integration-ready | Production status |
| --- | --- | --- | --- |
| Public landing page | Yes, preserved | N/A | Static only |
| Sign-in and server session | Yes, Passport + session | PostgreSQL store | Needs email/OIDC, CSRF, rate limits |
| Organizations and memberships | Yes | PostgreSQL migration | Needs invites and RLS |
| Tenant isolation and RBAC | Yes, route-enforced and tested | Repository boundary | Needs transaction-scoped RLS |
| Knowledge, uploads, jobs | No | No | Not implemented |
| Agent configuration | Yes, tenant-scoped draft API | Provider-neutral config boundary | Execution/provider safety still pending |
| Knowledge sources | Yes, bounded text + injection quarantine | Storage contract | Fetching, uploads, scanning, indexing/jobs pending |
| Conversations/inbox | Yes, create/list/status/assignment lifecycle | Provider-neutral records | Outbound channels, realtime, notifications, SLA automation pending |
| Conversation analytics | Yes, counts derived from stored records | Query contract | Production dashboards, retention, export, and event pipeline pending |
| API keys/webhooks | Yes, tenant-scoped hashed API keys with metadata listing/revocation, encrypted webhook secret, HMAC/timestamp/replay checks | Provider-neutral boundary | Key-authenticated API middleware, delivery workers, external provider verification pending |
| Observability/health | Yes, request IDs, durable error-event contract, liveness/readiness endpoints | Adapter boundary | External metrics, tracing, alerting, and live PostgreSQL verification pending |
| Background jobs | Yes, tenant-scoped queued knowledge-ingestion job contract with idempotency | Queue adapter boundary | Worker, fetching, parsing, embedding, retries, and provider execution pending |
| Billing/subscription state | Yes, tenant-scoped state read model updated only by verified, replay-safe webhook events | Provider-neutral contract | Checkout, payment collection, provider synchronization, tax, and invoicing pending |
| Security/audit | Yes, tenant-scoped admin audit retrieval with bounded limits and metadata redaction | Existing audit/RLS contract | Retention, export, alerting, and compliance review workflow pending |
| Password recovery | Yes, hashed expiring single-use token lifecycle and generic request/reset contract | Provider-neutral auth boundary | Email delivery, verified email ownership, OIDC, and abuse controls pending |
| Email verification | Yes, hashed expiring single-use token lifecycle and confirmation contract | Provider-neutral auth boundary | Email delivery, resend throttles, ownership proof operations, and OIDC pending |
| Privacy/retention | Yes, tenant-scoped bounded retention policy with admin audit | Policy/configuration boundary | Deletion worker, legal holds, export, and compliance operations pending |
| Conversations, AI/RAG | No | No | Not implemented |
| Billing, API keys, webhooks | No fake flows | Contracts only | Not implemented |
| Arabic/English | Existing landing/workspace | N/A | Browser matrix still required |
| Deployment | Local documented | PostgreSQL path | Operational controls pending |
