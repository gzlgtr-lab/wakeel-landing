# Wakeel

Wakeel contains a public multilingual landing page, the preserved Phase 2 workspace preview, and a Phase 3 local-first server foundation. The foundation includes real Passport authentication, server-side sessions, PostgreSQL migrations/seeds, organization membership, tenant checks, and server-side RBAC. It does not claim to implement provider integrations, billing, uploads, or live AI orchestration yet.

## Run locally

The public landing page still works as a static site. To run the functional server:

```bash
npm install
WAKEEL_DATABASE_URL=postgres://... npm run db:migrate
WAKEEL_DATABASE_URL=postgres://... WAKEEL_SEED_PASSWORD='local-only' npm run db:seed
npm run dev
```

Then open `http://localhost:3000/`. `npm test` runs deterministic HTTP authorization tests without a database.

The public page is `index.html`; the workspace preview is `app.html`. Choose a visitor, demo member, or demo owner on the workspace sign-in screen. The workspace uses hash routes and local browser state only.

## Included

- Responsive dark enterprise design system with Arabic RTL and English LTR switching.
- Accessible navigation, skip link, keyboard-friendly dialog, focus restoration, reduced-motion support, and semantic status announcements.
- Local-only dialect/scenario simulator with safe `textContent` rendering.
- Progressive text-to-speech controls; no microphone recording or voice storage.
- Transparent ROI calculator using locale-aware currency formatting and disclosed assumptions.
- Reference pricing with no fake checkout.
- Demo-booking dialog submitted to `https://formspree.io/f/xqkvqgpe` using JSON acceptance, honeypot, timeout, duplicate-submission lock, field validation, success, and recoverable failure states.
- Phase 2 workspace shell with Arabic RTL and English LTR, onboarding-ready navigation, overview, inbox, knowledge, agent builder, analytics, integrations, team/RBAC, markets/locales/currencies, billing, API/webhooks, security/audit, and settings surfaces.
- Phase 3 foundation API with Passport Local authentication, server-side sessions, PostgreSQL migration/seed scripts, memberships, tenant checks, and role-enforced mutations.
- Provider-independent UI boundaries: integration and billing actions disclose their server/credential requirements instead of collecting secrets or simulating successful payments.

## Production boundary

The landing and workspace preview remain frontend surfaces, while the Phase 3 server is intentionally incomplete. A real launch still needs OIDC/email verification, CSRF protection, PostgreSQL RLS transaction context, background knowledge ingestion, provider adapters, rate limiting, webhook verification, billing synchronization, observability, legal approval, and deployment security headers. Do not add secrets to this repository or treat local seed data as production credentials.

The Formspree endpoint is the only external submission configured in the public page. The workspace preview makes no external API calls. Confirm the endpoint, retention policy, notification recipients, and privacy notice with the owner before launch.

## Phase 2 boundary

**Functional in this repository:** public landing page, local language switching, accessible demo dialog, local workspace routing, responsive app shell, server-side login/session endpoints, organization membership checks, server-side role enforcement, PostgreSQL migration/seed scripts, and deterministic authorization tests.

**Demo-only:** workspace preview metrics and all product operations not represented by the API. The opt-in memory repository and dev-login endpoint are development-only. No customer content, secrets, cards, or provider requests are accepted by `app.html`.

**Required before production:** server-side sessions and authorization, database and migrations, tenant isolation, background ingestion, provider adapters, webhook verification, rate limiting, observability, legal/privacy review, secure secret management, a real billing synchronization flow, security headers/CSP, and deployment-specific credentials. The names are listed in `.env.example`; values must be supplied by the deployment environment.

## Validation

The page can be checked with:

```bash
curl --fail --silent --show-error http://localhost:8080/ > /dev/null
```

For production, add HTML validation, accessibility automation, end-to-end browser coverage, CSP/security-header configuration, and complete the documented security blockers before enabling customer traffic.
