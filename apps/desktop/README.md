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

These commands are exposed from `src-tauri/src/commands.rs` and call the shared Rust application layer in `src/app/peer.rs`.

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
