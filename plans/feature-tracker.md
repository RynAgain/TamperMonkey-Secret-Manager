# TamperMonkey Secret Manager -- Feature Tracker

## Phase 1 -- Foundation

- [x] Scaffold Tauri v2 project with React + TypeScript + Vite
- [x] Configure Tailwind CSS with Art Deco theme tokens
- [x] Set up comprehensive .gitignore
- [x] Implement Rust crypto module: AES-256-GCM encrypt/decrypt
- [x] Implement Rust KDF module: Argon2id key derivation
- [x] Set up SQLite database with rusqlite
- [x] Create DB schema and migrations (secrets, scripts, config tables)
- [x] Build master password unlock flow (Rust backend)
- [x] Build master password unlock screen (React frontend)
- [x] Implement KV secret CRUD -- Tauri IPC commands
- [x] Build SecretList and SecretEditor React components
- [x] Wire up Zustand store for secrets state

## Phase 2 -- Local HTTP API

- [x] Embed Axum HTTP server in Tauri startup
- [x] Bind to 127.0.0.1 with random available port
- [x] Write port number to %APPDATA% file on startup
- [x] Generate cryptographic bearer token on startup
- [x] Write token to %APPDATA% file with restrictive permissions
- [x] Implement bearer token auth middleware
- [x] Implement `GET /api/health` endpoint
- [x] Implement `POST /api/secrets/:name` endpoint
- [x] Implement `POST /api/register` endpoint for script self-registration
- [x] Implement `GET /api/scripts` endpoint (internal/UI use)
- [x] Add no-cache / no-store headers to all secret responses
- [x] Create TamperMonkey helper snippet (JS) for users to copy

## Phase 3 -- All Secret Types

- [x] Implement environment variable allowlist config (UI + backend)
- [x] Implement runtime env var reading (Rust, memory-only, no persistence)
- [x] Serve env var values through HTTP API
- [x] Design .tmvault file format (header + encrypted payload)
- [x] Implement vault export: select secrets, set PIN, generate .tmvault
- [x] Implement vault import: load .tmvault, enter PIN, decrypt
- [x] Implement blind mode flag per secret in vault
- [x] Enforce blind mode: Tauri IPC refuses to send blind values to frontend
- [x] Allow HTTP API to serve blind secret values to approved scripts
- [x] Build VaultExport and VaultImport React components
- [x] Allow User B to add own secrets alongside imported blind ones

## Phase 4 -- Script Approval System

- [x] Store script registrations in SQLite (script_id, domain, requested secrets)
- [x] Show approval notification/modal when new script registers
- [x] Build ScriptApprovalList React component
- [x] Build ScriptDetail view with approve/revoke per-secret controls
- [x] Enforce approval checks on every secret request
- [x] Allow user to revoke script access from the UI

## Phase 5 -- UI Polish and Art Deco Theme

- [x] Implement light/dark mode toggle with CSS custom properties
- [x] Art Deco color palette: gold/black/warm white
- [x] Geometric sans-serif typography (Outfit/DM Sans + Playfair Display headings)
- [x] Gold hairline borders and chamfered card corners
- [x] Sunburst dividers and chevron decorative motifs (CSS pseudo-elements)
- [x] Gold gradient buttons with geometric hover animations
- [x] Integrate Lucide React icons
- [x] Build Dashboard view with secret counts and recent access log
- [x] Build Settings panel (API port, token display/rotation, theme toggle)
- [x] Copy-to-clipboard for TamperMonkey helper snippet in Settings
- [x] Responsive layout with Art Deco symmetry and generous whitespace
- [x] Unlock screen with sunburst logo/branding

## Phase 6 -- Security Hardening

- [x] Configure Tauri CSP (Content Security Policy) in tauri.conf.json
- [x] Set restrictive OS file permissions on token and port files
- [x] Implement token rotation on app restart (configurable)
- [x] Add audit logging: who accessed what secret and when
- [x] Ensure secrets are zeroized in Rust memory after use (zeroize crate)
- [x] PIN complexity enforcement for vault creation
- [x] Rate limiting on HTTP API to prevent brute force
- [x] Integration tests for all crypto paths (encrypt/decrypt round-trip)
- [x] Integration tests for API auth (valid token, invalid token, missing token)
- [x] Integration tests for blind mode enforcement
- [x] Test .tmvault portability (create on machine A, import on machine B)
- [x] Security review of .gitignore coverage

## Phase 7 -- Threat Modeling and Security Review

- [x] Conduct formal STRIDE threat analysis across all components
- [x] Enumerate full attack surface: Tauri IPC commands, HTTP API endpoints, file system artifacts, process memory
- [ ] Adversarial test: simulate bearer token theft and replay
- [ ] Adversarial test: vault PIN brute force attempt against Argon2id parameters
- [ ] Adversarial test: script ID spoofing to access unauthorized secrets
- [x] Data flow review: trace every path a secret value travels, verify no unintended leakage
- [x] Blind mode bypass audit: confirm no IPC command, API endpoint, or log can expose blind values to frontend
- [x] Tauri IPC surface review: verify no over-exposed commands callable from webview JS
- [ ] Run cargo-audit on all Rust crate dependencies for known CVEs
- [ ] Run npm audit on all frontend dependencies for known CVEs
- [ ] Pin all dependency versions and verify lock file integrity
- [x] Document all residual risks with severity ratings and accepted trade-offs
- [x] Create incident response playbook: token compromise, vault file leak, dependency vulnerability
- [x] Prepare documentation for potential third-party security review
