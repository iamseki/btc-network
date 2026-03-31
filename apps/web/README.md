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

## Current Status

Current state:

- app shell and page navigation are implemented
- the sidebar shell is covered by render tests in `src/App.test.tsx`
- runtime selection between `web-client` and `tauri-client` is in place
- `Crawler Runs` and `Network Analytics` are now real analytics pages backed by the HTTP API
- desktop-backed handshake, ping, peer address lookup, chain height, block summary, and block download are wired through Tauri
- both web and desktop analytics reads now use the browser-safe HTTP helper
- plain web mode still uses placeholder/mock responses only for the single-peer flows that do not yet have a browser-safe backend

## Local commands

- `npm install --prefix apps/web`
- `npm run dev --prefix apps/web`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`

Optional environment:

- `VITE_API_BASE_URL` — base URL for crawler analytics reads; defaults to `http://127.0.0.1:8080` in local development and `https://api.btcnetwork.info` in production
- `VITE_SUPPORT_URL` — Buy Me a Coffee or other support link shown in the sidebar footer

Important:

- Vite reads `VITE_*` values at build time, not after the page has already loaded
- local development: set `VITE_SUPPORT_URL` in your shell or a local Vite env file before `npm run dev`
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
