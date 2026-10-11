# Wakeel landing

Wakeel is a static, multilingual marketing and product-demonstration page for an enterprise customer-support platform. The current repository intentionally does **not** claim to implement authentication, a database, provider integrations, billing, or live AI orchestration.

## Run locally

No build step or package installation is required. Serve the repository with any static server, for example:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080/`.

## Included

- Responsive dark enterprise design system with Arabic RTL and English LTR switching.
- Accessible navigation, skip link, keyboard-friendly dialog, focus restoration, reduced-motion support, and semantic status announcements.
- Local-only dialect/scenario simulator with safe `textContent` rendering.
- Progressive text-to-speech controls; no microphone recording or voice storage.
- Transparent ROI calculator using locale-aware currency formatting and disclosed assumptions.
- Reference pricing with no fake checkout.
- Demo-booking dialog submitted to `https://formspree.io/f/xqkvqgpe` using JSON acceptance, honeypot, timeout, duplicate-submission lock, field validation, success, and recoverable failure states.

## Production boundary

This is a frontend-only repository. A real launch still needs a server-side authentication/session layer, organization authorization, database, background knowledge ingestion, provider adapters, rate limiting, webhook verification, billing synchronization, observability, legal approval, and deployment security headers. Do not add secrets to this repository or treat the demo values as production metrics.

The Formspree endpoint is the only external submission configured in the page. Confirm the endpoint, retention policy, notification recipients, and privacy notice with the owner before launch.

## Validation

The page can be checked with:

```bash
curl --fail --silent --show-error http://localhost:8080/ > /dev/null
```

For production, add HTML validation, accessibility automation, end-to-end browser coverage, CSP/security-header configuration, and a real backend before enabling authenticated product routes.
