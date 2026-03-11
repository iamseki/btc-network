# apps/desktop

Planned Tauri shell for the desktop application.

Responsibilities:

- host the shared frontend
- expose native Rust commands to the UI
- keep desktop-only capabilities behind a narrow adapter boundary

Non-responsibilities:

- implement page logic directly
- duplicate CLI flows
- bypass the shared Rust application layer

The frontend should remain portable enough that the same UI can later run as a normal web application backed by an HTTP or WebSocket API.
