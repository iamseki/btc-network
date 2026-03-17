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

## Production deploy

Phase 1 production deploys target `Cloudflare Pages` through the repository GitHub Actions workflow at [deploy-web-pages.yml](/home/chseki/projects/personal/btc-network/.github/workflows/deploy-web-pages.yml).

We set the action and the following secrets:
- secret `CLOUDFLARE_API_TOKEN`
- secret `CLOUDFLARE_ACCOUNT_ID`

Current pragmatic DNS/domain default setup:

1. keep `btcnetwork.info` registered at Hostinger
2. point the web app domain to Cloudflare Pages with a manual DNS update in Hostinger (Copy the Cloudflare nameservers to where you bought your domain, put these nameserver on there)
3. Create Cloud Flare Page, maybe you will need to upload the dist manually.
4. Add a custom domain in cloud flare page console
Manual DNS cutover checklist:
5. Wait for propagation and confirm the domain becomes active in Cloudflare Pages.


Next implementation priorities:

- keep the browser-safe adapter boundary ready for a future HTTP/backend implementation
- improve progress and streaming feedback for longer-running protocol actions
- decide whether one-shot `getheaders` belongs in the product surface beyond the current chain-height view
- keep the web runtime behind a browser-safe adapter boundary
