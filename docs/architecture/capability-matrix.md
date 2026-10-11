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
| Conversations, AI/RAG | No | No | Not implemented |
| Billing, API keys, webhooks | No fake flows | Contracts only | Not implemented |
| Arabic/English | Existing landing/workspace | N/A | Browser matrix still required |
| Deployment | Local documented | PostgreSQL path | Operational controls pending |
