# apps/web

Primary web-first frontend for the project.

This app owns:

- page composition
- feature components
- frontend state
- API client boundary used by both web and desktop modes

This app does not own:

- Bitcoin P2P protocol logic
- socket/session logic
- direct Tauri API usage inside page components
- CLI process invocation

## UI composition rule

- Start with a relevant shadcn block when building a new app shell, sidebar, header, or other common page frame
- Adapt blocks down to the repo's cleaner retro style instead of rebuilding those patterns from scratch
- Drop to lower-level shadcn primitives only when no suitable block exists or the block would be heavier than the interface needs

## Risk article content workflow

Risk articles are human-owned source content, not runtime prompts.

- Keep article copy in Markdown files under `src/content/risk/articles/`
- Keep article registration and frontmatter parsing in `src/content/risk/article-registry.ts`
- Keep approved widgets in `src/pages/risk-article-widgets.tsx`
- Keep React page code in `src/pages/risk-page.tsx` focused on rendering, navigation, state, and layout
- Treat AI as an editor or drafting assistant; the reviewed article file remains the source of truth
- Write article prose as plain Markdown headings, paragraphs, and bullet lists
- Use approved widget directives for dynamic UI or API-backed areas, for example `::widget{type="sybil-dashboard"}`
- Markdown may request a widget, but it must not define widget behavior, API calls, or layout code
- Unknown widget types render as visible placeholders so articles can be drafted before a widget exists
- The `On this page` rail is generated from Markdown headings, so section labels should be short and human-readable
- Include references as explicit links with human-readable titles and short details
- Avoid claims the crawler cannot support; describe crawler-visible evidence, limitations, and review prompts
- Do not add protocol parsing, crawler data shaping, or API calls inside article Markdown files

Suggested contributor flow:

1. Add or edit article Markdown under `src/content/risk/articles/`
2. If a new widget is needed, add a directive such as `::widget{type="address-churn"}` in Markdown
3. Implement the matching typed widget in `src/pages/risk-article-widgets.tsx`
4. Add API client methods or backend work only in the existing API boundaries, never in Markdown
5. Update `src/pages/risk-page.test.tsx` when adding sections, references, widgets, or navigation behavior
6. Run `npm run test --prefix apps/web -- src/pages/risk-page.test.tsx src/App.test.tsx`
7. Run `npm run build --prefix apps/web`

## Current Status

Current state:

- app shell and page navigation are implemented
- the sidebar shell is covered by render tests in `src/App.test.tsx`
- runtime selection between `web-client` and `tauri-client` is in place
- `Crawler Runs` and `Network Analytics` are now real analytics pages backed by the HTTP API
- desktop-backed handshake, ping, peer address lookup, chain height, block summary, and block download are wired through Tauri
- both web and desktop analytics reads now use the browser-safe HTTP helper
- plain web mode still uses placeholder/mock responses only for the single-peer flows that do not yet have a browser-safe backend
- optional demo mode can mock analytics pages too for hosted demo deploys that do not need live analytics reads

## Local commands

- `npm install --prefix apps/web`
- `npm run dev --prefix apps/web`
- `VITE_DEMO_MODE=true npm run dev --prefix apps/web`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`
- `VITE_DEMO_MODE=true npm run build --prefix apps/web`

Makefile shortcuts:

- `make web-dev` runs the local web app against the default analytics mode
- `make web-dev-demo` runs the local web app with mocked analytics pages enabled
- `make web-build-demo` builds the static site with mocked analytics pages enabled

Optional environment:

- `VITE_API_BASE_URL` — base URL for network analytics reads; defaults to `http://127.0.0.1:8080` in local development and `https://api.btcnetwork.info` in production
- `VITE_DEMO_MODE` — when set to `true`, `1`, `yes`, or `on`, the hosted web app serves deterministic mock data for `Crawler Runs` and `Network Analytics`
- `VITE_SUPPORT_URL` — override the default Buy Me a Coffee link shown in the sidebar footer

Important:

- Vite reads `VITE_*` values at build time, not after the page has already loaded
- local development: set `VITE_SUPPORT_URL` in your shell or a local Vite env file if you want to override the default support link before `npm run dev`
- local mocked analytics: `make web-dev-demo` is the quickest path when you want `Crawler Runs` and `Network Analytics` to use deterministic browser-side demo data
- the API docs page still fetches `/api/docs/config.json` and `/api/openapi.json` from the API service in both normal and demo web modes
- the embedded Scalar reference uses `VITE_API_BASE_URL` as the default OpenAPI server when the API service does not publish `BTC_NETWORK_API_PUBLIC_BASE_URL`; set `VITE_API_BASE_URL` to target localhost, staging, or production from the web build
- the home page opens an in-app `Agent Guide` page; normal builds load API-hosted `/agents.md`, while demo mode renders the bundled `src` Markdown symlink to the API guide without calling the API
- `src/lib/api/api-agents.md` is intentionally a symlink to `apps/api/src/docs/agents.md`; update the API-owned file, not a web copy
- demo deploys: set `VITE_DEMO_MODE=true` in the build environment when you want analytics pages mocked while still pointing API docs at a live API
- production deploys: set `VITE_SUPPORT_URL` as a GitHub repository variable so the GitHub Actions build injects it into the static site

## Production deploy

Phase 1 production deploys target `Cloudflare Pages` through the repository GitHub Actions workflow at [ci.yml](/home/chseki/projects/personal/btc-network/.github/workflows/ci.yml).

Deployment gating:

- the `deploy-web` job runs only on pushes to `main`
- it depends on both the build/test and dependency-security jobs succeeding first
- it runs only when the push includes changes under `apps/web/**`
- the workflow injects `vars.VITE_SUPPORT_URL` into the build so the support link is present in production when configured

Repository setup and manual Hostinger DNS steps live in [docs/deployment.md](/home/chseki/projects/personal/btc-network/docs/deployment.md).

Important:

- this setup does **not** require moving the domain registrar
- this setup does **not** require changing nameservers to Cloudflare
- this repo’s workflow uses automated direct upload from GitHub Actions, not manual `dist/` uploads in the UI

Next implementation priorities:

- extend the browser-safe backend beyond crawler analytics if more single-peer flows need real web support
- improve progress and streaming feedback for longer-running protocol actions
- decide whether one-shot `getheaders` belongs in the product surface beyond the current chain-height view
- keep the web runtime behind a browser-safe adapter boundary
