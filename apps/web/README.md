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
- desktop-backed handshake, ping, peer address lookup, chain height, block summary, and block download are wired through Tauri
- plain web mode still uses placeholder/mock responses where a browser-safe backend does not yet exist

## Local commands

- `npm install --prefix apps/web`
- `npm run dev --prefix apps/web`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`

Optional environment:

- `VITE_SUPPORT_URL` — Buy Me a Coffee or other support link shown in the sidebar footer

Important:

- Vite reads `VITE_*` values at build time, not after the page has already loaded
- local development: set `VITE_SUPPORT_URL` in your shell or a local Vite env file before `npm run dev`
- production deploys: set `VITE_SUPPORT_URL` as a GitHub repository variable so the GitHub Actions build injects it into the static site

## Production deploy

Phase 1 production deploys target `Cloudflare Pages` through the repository GitHub Actions workflow at [deploy-web-pages.yml](/home/chseki/projects/personal/btc-network/.github/workflows/deploy-web-pages.yml).

Deployment gating:

- the deploy workflow runs only after the repository `CI` workflow succeeds on `main`
- this means deploys wait for both test and dependency-security checks in `CI`
- the workflow injects `vars.VITE_SUPPORT_URL` into the build so the support link is present in production when configured

Repository setup and manual Hostinger DNS steps live in [docs/deployment.md](/home/chseki/projects/personal/btc-network/docs/deployment.md).

Important:

- this setup does **not** require moving the domain registrar
- this setup does **not** require changing nameservers to Cloudflare
- this repo’s workflow uses automated direct upload from GitHub Actions, not manual `dist/` uploads in the UI

Next implementation priorities:

- keep the browser-safe adapter boundary ready for a future HTTP/backend implementation
- improve progress and streaming feedback for longer-running protocol actions
- decide whether one-shot `getheaders` belongs in the product surface beyond the current chain-height view
- keep the web runtime behind a browser-safe adapter boundary
