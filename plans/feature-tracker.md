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

## Phase 8 -- Blind Code Modules

- [x] Design .tmcode file format (header + encrypted Rhai code payload)
- [x] DB migration v4: blind_code_modules and script_code_access tables
- [x] Add BlindCodeModule and ScriptCodeAccess models
- [x] Implement .tmcode export: create module, set PIN, generate .tmcode file
- [x] Implement .tmcode import: load file, enter PIN, decrypt and store
- [x] Add Rhai scripting engine dependency (rhai crate)
- [x] Implement sandboxed Rhai execution engine with controlled API surface
- [x] Implement secret() function injection for Rhai scripts (reads from encrypted store)
- [x] Implement HTTP helper functions for Rhai scripts (http_get, http_post)
- [x] Implement parameter validation (only allowed_params accepted from TM scripts)
- [x] Add POST /api/execute/:module_name HTTP endpoint
- [x] Per-script + per-module access control (approval required)
- [x] Toast notifications for new module execution requests
- [x] IPC commands: list, import, export, approve, revoke, delete blind code modules
- [x] IPC commands: list and set script-to-module access
- [x] IPC command: create_blind_code_module (for code authors)
- [x] Frontend: BlindCodeList component (shows module metadata, never code)
- [x] Frontend: BlindCodeDetail component (approval controls, access management)
- [x] Frontend: BlindCodeImport component (file picker + PIN entry)
- [x] Frontend: BlindCodeExport component (code editor + PIN + export)
- [x] Frontend: Zustand store for blind code modules
- [x] Audit logging for all module operations (import, execute, approve, revoke)
- [x] Blind mode enforcement: code never sent to frontend via IPC
- [x] Expiration support for blind code modules
- [x] Integration tests: .tmcode roundtrip, execution, access control
- [x] Security review: verify no code leakage path to frontend
- [x] DB migration v5: language column for multi-language support
- [x] Add language field to BlindCodeModule model and CodeModuleEntry format
- [x] Implement Python subprocess executor (sandboxed, net-allowed, fs-restricted)
- [x] Implement JavaScript/TypeScript Deno subprocess executor (--allow-net only)
- [x] Implement execution dispatcher (routes by language: rhai/python/javascript/typescript)
- [x] Frontend: language selector in create component, language display in list/detail
- [x] Integration tests for .tmcode format, Rhai execution, DB operations (18 tests)
- [x] Security review of blind code modules (all languages)
