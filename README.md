# TamperMonkey Secret Manager

A Tauri v2 desktop application that provides secure, encrypted storage for API keys, passwords, and tokens -- and serves them to TamperMonkey userscripts via a local HTTP API. Secrets never touch your scripts or browser storage in plain text.

---

## Table of Contents

- [Problem](#problem)
- [How It Works](#how-it-works)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Usage](#usage)
  - [Managing Secrets](#managing-secrets)
  - [Connecting TamperMonkey Scripts](#connecting-tampermonkey-scripts)
  - [Blind Vault Sharing](#blind-vault-sharing)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [Development](#development)
- [Testing](#testing)
- [License](#license)

---

## Problem

TamperMonkey has no native secret management. Users hardcode API keys, passwords, and tokens directly in userscripts, where they sit in plain text in browser storage. This is visible to any extension, any page with sufficient access, and anyone who exports or shares a script.

## How It Works

```
TamperMonkey Script                    Tauri Desktop App
+-----------------+                    +--------------------------+
|                 |  GM_xmlhttpRequest |  Axum HTTP API (127.0.0.1)|
|  getSecret()   | -----------------> |  Bearer token auth        |
|                 |    localhost:PORT   |  Script approval check    |
|                 | <----------------- |  Decrypt from SQLite      |
|  use secret     |   plaintext value  |  Zeroize after response   |
+-----------------+                    +--------------------------+
```

1. The app runs a local HTTP server bound exclusively to `127.0.0.1` on a random port.
2. TamperMonkey scripts authenticate with a bearer token and request secrets by name.
3. Secrets are decrypted in Rust memory, served once, then zeroized.
4. The app enforces per-script approval -- scripts must be explicitly granted access to each secret.

---

## Features

- **Encrypted storage** -- AES-256-GCM with keys derived via Argon2id (64 MB memory, 3 iterations)
- **Three secret types**
  - Key-value pairs (encrypted in SQLite)
  - Environment variables (read from OS at runtime, never persisted)
  - Portable vault files (`.tmvault`) for sharing between users
- **Blind vault sharing** -- share secrets so recipients can *use* them without *seeing* them
- **Script approval system** -- per-script, per-secret access control with trust-on-first-use registration
- **Local HTTP API** -- Axum server on `127.0.0.1` with bearer token auth and rate limiting (60 req/min)
- **Auto-lock** -- configurable idle timeout locks the vault
- **Audit log** -- records every secret access with timestamp and script identity
- **Art Deco UI** -- dark/light theme with gold accent palette, geometric motifs, Lucide icons
- **Token rotation** -- bearer token regenerated on each app restart

---

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop framework | Tauri v2 (Rust backend) |
| Frontend | React 19 + TypeScript |
| Styling | Tailwind CSS v4 |
| State management | Zustand |
| Encryption | `aes-gcm` + `argon2` crates |
| Local API | Axum (embedded in Tauri process) |
| Storage | SQLite via `rusqlite` (bundled) |
| Build | Vite 7 |

---

## Prerequisites

- **Node.js** >= 18
- **Rust** >= 1.77 (stable)
- **Tauri v2 CLI** -- installed via `npm` as a dev dependency
- **System dependencies** for Tauri: see the [Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/)

On Windows, you need the Microsoft Visual Studio C++ Build Tools and WebView2 (pre-installed on Windows 11).

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/kryasatt/tampermonkey-secret-manager.git
cd tampermonkey-secret-manager

# Install frontend dependencies
npm install

# Run in development mode (starts both Vite dev server and Tauri)
npm run tauri dev

# Build a production release
npm run tauri build
```

The development server starts on `http://localhost:1420` for the Vite frontend. The Tauri backend compiles and launches automatically.

---

## Project Structure

```
tampermonkey-secret-manager/
|-- src/                          # React frontend
|   |-- components/
|   |   |-- audit/                # AuditLog viewer
|   |   |-- scripts/              # ScriptList, ScriptDetail (approval UI)
|   |   |-- secrets/              # SecretList, SecretEditor, EnvVarConfig
|   |   |-- ui/                   # PasswordStrength indicator
|   |   |-- vault/                # VaultImport, VaultExport
|   |-- hooks/                    # useAutoLock, useTheme
|   |-- lib/                      # Tauri IPC wrappers
|   |-- stores/                   # Zustand stores (auth, secrets, scripts)
|   |-- views/                    # Dashboard, Settings, UnlockScreen
|   |-- App.tsx
|   |-- main.tsx
|   |-- styles.css
|-- src-tauri/                    # Rust backend
|   |-- src/
|   |   |-- api/                  # Axum HTTP server, routes, auth middleware, rate limiting
|   |   |-- crypto/               # AES-256-GCM encryption, Argon2id KDF
|   |   |-- db/                   # SQLite schema, migrations, models
|   |   |-- secrets/              # Vault file format, secret management
|   |   |-- commands.rs           # Tauri IPC command handlers
|   |   |-- error.rs              # Error types
|   |   |-- state.rs              # Application state
|   |   |-- lib.rs                # Tauri plugin setup
|   |   |-- main.rs               # Entry point
|   |-- tests/                    # Integration tests (crypto, API auth, vault)
|   |-- Cargo.toml
|   |-- tauri.conf.json
|-- scripts/                      # TamperMonkey test/helper scripts
|-- plans/                        # Architecture docs, feature tracker, security review
|-- package.json
|-- vite.config.ts
|-- tsconfig.json
```

---

## Usage

### Managing Secrets

1. Launch the app and set a **master password** on first run. This derives the encryption key via Argon2id.
2. Navigate to the **Secrets** view to create, edit, or delete key-value secrets.
3. Use the **Environment Variables** panel to configure an allowlist of OS env vars to serve at runtime.
4. The **Dashboard** shows secret counts by type and recent access history.

### Connecting TamperMonkey Scripts

The app writes its API port and bearer token to files in your app data directory on startup. You can also find these values in the **Settings** view.

Add this helper to any TamperMonkey script:

```javascript
// ==UserScript==
// @name         My Script
// @grant        GM_xmlhttpRequest
// @connect      127.0.0.1
// ==/UserScript==

async function getSecret(name) {
    const PORT = 12345;   // Copy from Settings or api.port file
    const TOKEN = 'xxx';  // Copy from Settings or api.token file

    return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
            method: 'POST',
            url: `http://127.0.0.1:${PORT}/api/secrets/${name}`,
            headers: {
                'Authorization': `Bearer ${TOKEN}`,
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                script_id: GM_info.script.name,
                domain: window.location.hostname
            }),
            onload: (res) => resolve(res.responseText),
            onerror: (err) => reject(err)
        });
    });
}

// Usage:
const apiKey = await getSecret('MY_API_KEY');
```

On first request, the script auto-registers and appears in the **Scripts** panel. You must approve it and grant access to specific secrets before values are served.

A complete test/verification userscript is available at [`scripts/test-tampermonkey-script.user.js`](scripts/test-tampermonkey-script.user.js).

### Blind Vault Sharing

1. Select secrets to share and choose **Export Vault**.
2. Set a PIN (used to derive the vault encryption key via Argon2id).
3. Send the `.tmvault` file and PIN to the recipient through a secure channel.
4. The recipient imports the vault and enters the PIN.
5. Blind secrets are usable by TamperMonkey scripts but **their values are never shown in the UI**.

---

## API Reference

The HTTP API binds to `127.0.0.1` on a random port. All endpoints except `/api/health` require `Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | No | Health check; returns `200` when the app is running |
| `POST` | `/api/secrets/:name` | Yes | Retrieve a decrypted secret by name |
| `POST` | `/api/register` | Yes | Register a script (name, domain, requested secrets) |
| `GET` | `/api/scripts` | Yes | List registered scripts and their approval status |

**Response codes for** `POST /api/secrets/:name`:

| Status | Meaning |
|---|---|
| `200` | Secret value returned in response body |
| `401` | Invalid or missing bearer token |
| `403` | Script not approved for this secret |
| `404` | Secret not found |
| `410` | Secret has expired |
| `423` | App is locked (master password not entered) |
| `429` | Rate limit exceeded (60 requests/minute) |

All secret responses include `Cache-Control: no-store, no-cache` and `X-Content-Type-Options: nosniff` headers.

---

## Security Model

### Encryption

- **At rest**: All secret values encrypted with AES-256-GCM before writing to SQLite.
- **Key derivation**: Master password processed through Argon2id (64 MB memory, 3 iterations, 1 lane, 16-byte random salt).
- **Nonces**: 12-byte random nonce per encryption operation (OsRng).
- **Memory**: Decrypted values zeroized in Rust memory after use (`zeroize` crate).

### Network

- API server binds exclusively to `127.0.0.1` -- no external network exposure.
- Bearer token is 32 bytes of cryptographic randomness (256 bits of entropy).
- Token comparison uses constant-time equality to prevent timing attacks.
- Rate limiting at 60 requests/minute/endpoint prevents brute force.

### Access Control

- **App-level**: Master password required to unlock the vault.
- **Script-level**: Each TamperMonkey script must be explicitly approved.
- **Secret-level**: Approved scripts must be granted access to individual secrets.
- **Blind mode**: Imported vault secrets with `blind: true` are served only through the HTTP API; Tauri IPC refuses to send their values to the frontend.

### Content Security Policy

The Tauri webview enforces a restrictive CSP: scripts limited to `'self'`, connections limited to `'self'`, IPC, and `http://ipc.localhost`.

For the full STRIDE threat analysis, attack surface enumeration, and incident response playbook, see [`plans/security-review.md`](plans/security-review.md).

---

## Configuration

Configuration is managed through the **Settings** view in the app:

| Setting | Description |
|---|---|
| Theme | Toggle between light and dark mode |
| API port | Displayed for reference (random on each start) |
| Bearer token | Displayed for copying into scripts; rotates on restart |
| Auto-lock timeout | Idle duration before the vault locks automatically |
| Env var allowlist | OS environment variable names the app is allowed to serve |

---

## Development

```bash
# Start development mode with hot reload
npm run tauri dev

# Build frontend only
npm run build

# Run Rust tests
cd src-tauri && cargo test

# Type-check the frontend
npx tsc --noEmit
```

The Vite dev server runs on port `1420` with HMR. The Tauri backend recompiles on Rust source changes.

---

## Testing

Integration tests live in [`src-tauri/tests/`](src-tauri/tests/):

| Test file | Coverage |
|---|---|
| [`crypto_integration.rs`](src-tauri/tests/crypto_integration.rs) | AES-256-GCM encrypt/decrypt round-trip, Argon2id key derivation |
| [`api_auth_test.rs`](src-tauri/tests/api_auth_test.rs) | Bearer token validation (valid, invalid, missing) |
| [`vault_integration.rs`](src-tauri/tests/vault_integration.rs) | Vault export/import, blind mode enforcement |

```bash
cd src-tauri && cargo test
```

---

## License

This project is private and not currently published under an open-source license.
