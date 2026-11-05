# Kagi Identity Documentation Site

A responsive Japanese documentation site for Kagi Identity, implemented as a self-contained static HTML page.

## Sections
- Overview and local quickstart
- First passkey login and the account console
- Account management, sessions, consent and recovery codes
- OIDC / OAuth authorization flow and advanced FAPI features (PAR/DPoP/JAR/JARM)
- Client registration and browser SDK integration
- Environment configuration and production baseline
- Runtime architecture, deployment, persistence and Supabase
- Security checklist, implemented defences, testing, troubleshooting and known limitations
- MIT license and open-source information
- Client-side section search and active navigation

## Deploy as a separate Vercel project
- Project name: `kagi-docs`
- Framework preset: Other
- Root Directory: `examples/identity-docs`
- Build Command: empty
- Output Directory: empty / project root
- Install Command: empty

The docs site is static and does not host the Identity server. Content is a practical guide, not a certification claim. Check the source repository's `docs/` directory and the deployed commit for exact configuration and endpoint behavior.
