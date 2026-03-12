# apps/desktop

Tauri desktop shell for the application.

Responsibilities:

- host the shared frontend
- expose native Rust commands to the UI
- keep desktop-only capabilities behind a narrow adapter boundary

Non-responsibilities:

- implement page logic directly
- duplicate CLI flows
- bypass the shared Rust application layer

The frontend should remain portable enough that the same UI can later run as a normal web application backed by an HTTP or WebSocket API.

## Current Status

The first real desktop-backed flow is implemented:

- `handshake`
- `ping`

These commands are exposed from `src-tauri/src/commands.rs` and call the shared Rust application layer in `crates/btc-network/src/app/peer.rs`.

The desktop icon set is generated from:

- `src-tauri/icons/icon.svg`

Generated bundle assets now live alongside it in `src-tauri/icons/`.

## Linux Prerequisites

On Ubuntu/Debian systems, the desktop crate needs the native Tauri/WebKit build packages available through `pkg-config`.

The current Ubuntu 22.04-compatible package set is:

- `libwebkit2gtk-4.1-dev`
- `build-essential`
- `curl`
- `wget`
- `file`
- `libxdo-dev`
- `libssl-dev`
- `libayatana-appindicator3-dev`
- `librsvg2-dev`

## Local Commands

- `make desktop-install`
- `make desktop-dev`
- `make desktop-test`

## Editor Support

The repository root `Cargo.toml` includes `apps/desktop/src-tauri` as a workspace member so `rust-analyzer` can index the desktop crate from the repo root.

The workspace also includes a VS Code fallback in `.vscode/settings.json` via `rust-analyzer.linkedProjects` for cases where the editor does not automatically pick up the nested manifest.

The workspace default members include the desktop crate, so running `cargo test` at the repository root also exercises the Tauri Rust code.

Project-wide verification lives at the repo root: `make test` runs those Rust workspace tests plus the frontend test suite.

The workspace root `Cargo.lock` is the single lockfile that should be kept in version control for Rust dependencies. The desktop crate should not maintain an independent lockfile once it is part of the root workspace.

## Dev Permissions

During `tauri dev`, the frontend is loaded from the Vite dev server (`http://localhost:5173`). The default capability therefore allows the local dev origins explicitly, so desktop commands like `handshake` and `ping` work in development as well as in the bundled local app context.

Application command permissions follow the Tauri v2 explicit pattern:

- `build.rs` registers the app commands in the Tauri app manifest
- Tauri autogenerates `allow-handshake` and `allow-ping`
- the desktop capability grants those exact permission identifiers
