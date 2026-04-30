# Deployment

Human-oriented deployment guidance for the current production setup.

## Current Production Path

Phase 1 deploys only `apps/web`.

- Hosting: `Cloudflare Pages`
- Delivery: `GitHub Actions`
- Domain registrar: `Hostinger`
- Domain: `btcnetwork.info`
- Reserved future API hostname: `api.btcnetwork.info`

This setup keeps the deploy path automated while leaving any future API DNS cutover manual and low-risk.

## CI/CD Flow

The production workflow is [ci.yml](/home/chseki/projects/personal/btc-network/.github/workflows/ci.yml).

It:

- runs the normal build/test and dependency-security jobs
- runs `deploy-web` only after those jobs succeed
- deploys only on pushes to `main`
- deploys only when the push changes files under `apps/web/**`
- builds `apps/web`
- deploys the built `dist/` artifact to Cloudflare Pages

This keeps the deploy visible in the same GitHub commit checks as the rest of the pipeline while still gating production on the existing repository test and dependency-security checks.

## GitHub Repository Setup

Add these repository values before the first deploy:

- secret `CLOUDFLARE_API_TOKEN`
- secret `CLOUDFLARE_ACCOUNT_ID`
- variable `CLOUDFLARE_PAGES_PROJECT_NAME`
- variable `VITE_DEMO_MODE` if you want the hosted site to use deterministic demo analytics instead of calling the API
- variable `VITE_SUPPORT_URL` if you want the support link shown in the web UI

Use a Cloudflare API token with:

- `Account` -> `Cloudflare Pages` -> `Edit`

Scope it to the target Cloudflare account only.

For frontend environment values such as `VITE_SUPPORT_URL` and `VITE_DEMO_MODE`, remember:

- Vite injects `VITE_*` values at build time
- this repository builds the frontend in GitHub Actions before deploying to Cloudflare Pages
- because of that, `VITE_SUPPORT_URL` should be set in GitHub repository variables, not only in Cloudflare Pages
- set `VITE_DEMO_MODE=true` in GitHub repository variables for browser-only demo deploys that are not ready to expose the public API yet

## Cloudflare Pages Setup

Create the Pages project in `Workers & Pages`.

Recommended setup:

- product: `Pages`
- mode: `Direct Upload`
- project name: the same value used in `CLOUDFLARE_PAGES_PROJECT_NAME`

This repository does not use Cloudflare's built-in Git provider integration. GitHub Actions builds and uploads the static artifact directly.

## Manual Domain and DNS Setup

Use Cloudflare Pages as the source of truth for the required DNS records. Do not hardcode record targets in repository docs.

### In Cloudflare

1. Open the Pages project.
2. Open `Custom domains`.
3. Add `btcnetwork.info` as the production custom domain.
4. If you want `www.btcnetwork.info`, add it as a second custom domain.
5. Copy the exact DNS target values Cloudflare Pages shows for the apex domain and any extra hostname.

### In Hostinger

1. Open hPanel for `btcnetwork.info`.
2. Open the DNS zone editor.
3. Remove or update any conflicting `@` or `www` records, including default parking-page records.
4. Create the exact DNS records Cloudflare Pages requested.
5. Save the DNS changes.

### Validation

1. Wait for DNS propagation.
2. Return to Cloudflare Pages.
3. Confirm the custom domain becomes active.
4. Confirm HTTPS is issued successfully.

## Practical Defaults

- Keep the registrar at Hostinger.
- Do not move nameservers to Cloudflare during the current web-only phase.
- Keep `api.btcnetwork.info` unused for now so it remains available for the future API.
- Treat Cloudflare Pages as the production host for the static frontend only.

## Future Direction

The current Phase 1 setup is only for the web app.

The planned later path is:

- keep the frontend on Cloudflare Pages
- move authoritative DNS to Cloudflare when the API goes live
- add a Rust API on AWS self-managed infrastructure
- provision infrastructure with Terraform-compatible HCL and review plan diffs in CI
- keep PostgreSQL self-managed and non-public by default, initially on a separate private EC2 host from the API
- run the crawler on the API/crawler host as a sporadic batch workload through a scheduler or operator trigger, while preventing overlapping runs

See [BNDD-0003](/home/chseki/projects/personal/btc-network/docs/design_docs/BNDD-0003/BNDD-0003.md) for the staged web deployment decision, [BNDD-0011](/home/chseki/projects/personal/btc-network/docs/design_docs/BNDD-0011/BNDD-0011.md) for the accepted API hosting direction, and [BNDD-0007](/home/chseki/projects/personal/btc-network/docs/design_docs/BNDD-0007/BNDD-0007.md) for the current default storage backend.
