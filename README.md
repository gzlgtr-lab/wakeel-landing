# Wakeel

Wakeel contains a public multilingual landing page and a static Phase 2 workspace preview for an enterprise customer-support platform. The repository intentionally does **not** claim to implement authentication, a database, provider integrations, billing, or live AI orchestration.

## Run locally

No build step or package installation is required. Serve the repository with any static server, for example:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080/`.

The public page is `index.html`; the workspace preview is `app.html`. Choose a visitor, demo member, or demo owner on the workspace sign-in screen. The workspace uses hash routes and local browser state only.

## Included

- Responsive dark enterprise design system with Arabic RTL and English LTR switching.
- Accessible navigation, skip link, keyboard-friendly dialog, focus restoration, reduced-motion support, and semantic status announcements.
- Local-only dialect/scenario simulator with safe `textContent` rendering.
- Progressive text-to-speech controls; no microphone recording or voice storage.
- Transparent ROI calculator using locale-aware currency formatting and disclosed assumptions.
- Reference pricing with no fake checkout.
- Demo-booking dialog submitted to `https://formspree.io/f/xqkvqgpe` using JSON acceptance, honeypot, timeout, duplicate-submission lock, field validation, success, and recoverable failure states.
- Phase 2 workspace shell with Arabic RTL and English LTR, demo auth states, onboarding-ready navigation, overview, inbox, knowledge, agent builder, analytics, integrations, team/RBAC, markets/locales/currencies, billing, API/webhooks, security/audit, and settings surfaces.
- Provider-independent UI boundaries: integration and billing actions disclose their server/credential requirements instead of collecting secrets or simulating successful payments.

## Production boundary

This is a frontend-only repository. A real launch still needs a server-side authentication/session layer, organization authorization, database, background knowledge ingestion, provider adapters, rate limiting, webhook verification, billing synchronization, observability, legal approval, and deployment security headers. Do not add secrets to this repository or treat the demo values as production metrics.

The Formspree endpoint is the only external submission configured in the public page. The workspace preview makes no external API calls. Confirm the endpoint, retention policy, notification recipients, and privacy notice with the owner before launch.

## Phase 2 boundary

**Functional in this repository:** public landing page, local language switching, accessible demo dialog, local workspace routing, responsive app shell, demo role selection, local UI state, safe empty/loading/error-style states, Intl-ready locale/currency presentation, and explicit architecture surfaces for the requested product areas.

**Demo-only:** authentication, onboarding persistence, inbox records, knowledge ingestion, agent execution, analytics, escalation, Copilot responses, integrations, RBAC enforcement, audit events, API keys, webhooks, billing, and payment actions. No customer content, secrets, cards, or provider requests are accepted by `app.html`.

**Required before production:** server-side sessions and authorization, database and migrations, tenant isolation, background ingestion, provider adapters, webhook verification, rate limiting, observability, legal/privacy review, secure secret management, a real billing synchronization flow, security headers/CSP, and deployment-specific credentials. The names are listed in `.env.example`; values must be supplied by the deployment environment.

## Validation

The page can be checked with:

```bash
curl --fail --silent --show-error http://localhost:8080/ > /dev/null
```

For production, add HTML validation, accessibility automation, end-to-end browser coverage, CSP/security-header configuration, and a real backend before enabling authenticated product routes.
