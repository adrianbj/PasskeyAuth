# PasskeyAuth

WebAuthn passkey login for the ProcessWire admin.

Sign in to ProcessWire with a passkey — Touch ID, Face ID, Windows Hello, an iPhone via QR/hybrid, or a hardware security key — instead of (or alongside) a password.

- **Phishing-resistant** by design (origin-bound credentials)
- **Passwordless** — uses discoverable credentials, no username typing
- **Per-user, per-device** — register multiple passkeys per account, label and revoke individually
- **Hardened** — anchored origin checks, CSRF, rate limiting, atomic per-user cap, signature-counter rollback rejection, structured failure logs

## Requirements

- ProcessWire ≥ 3.0.173
- PHP ≥ 8.1
- HTTPS in production (browsers refuse WebAuthn on insecure origins; `localhost` and `127.0.0.1` are exempt for development)
- A modern browser with WebAuthn support (Chrome 67+, Safari 14+, Firefox 60+, Edge 18+)

## Configure

**Modules → Configure → PasskeyAuth**

| Setting | Description |
|---|---|
| **Application name** | Friendly name shown in the OS biometric prompt. Defaults to your host. |
| **Relying Party ID** | Hostname WebAuthn binds credentials to. Must equal the admin host or a registrable suffix (e.g. RP ID `example.com` works for `admin.example.com`). **Do not change after passkeys are registered** — existing keys will stop working. |
| **Allowed roles** | Only users with at least one of these roles can register or use passkeys. Fail-closed: with no roles selected, no one can use passkeys. |
| **Show registration banner** | Auto-prompt logged-in admins (in allowed roles) without a passkey to register one. |

## Use

### Register a passkey

After install, allowed-role admins see a yellow banner across the top of the admin chrome:

> 🔑 Add a passkey for faster, more secure sign-in. **[Set up]** [Don't show again]

Click **Set up**, complete the OS biometric / security-key prompt, and a passkey is registered to your account. You can also register from the user-edit page (`Profile` for self, `Access → Users → [user]` for superusers managing others).

### Sign in with a passkey

The login form gains a **Sign in with passkey** button. Click it, select your passkey from the OS prompt, and you're in — no username, no password.

Username autofill (`autocomplete="username webauthn"`) is also wired up, so browsers that support conditional UI will surface available passkeys when you focus the username field.

### Manage passkeys

The user-edit / profile screen shows a **Passkeys** fieldset listing all registered passkeys for that user, with their label, registration date, and last-used date. Click a name to rename, click **Delete** to remove one. Superusers can manage any user's passkeys; non-superusers can manage only their own.

## Security

This module is designed for production deployment of an admin login surface. Code-level hardening is documented inline (search `SEC-D`, `SEC-E`, `SEC-F` markers).

### Threat model and trust boundaries

The login endpoints are guest-reachable; the management endpoints are admin-gated. Trust boundaries enforced inside the code:

1. **Page gate** (admin URL prefix) — keeps unauthenticated users out of management endpoints.
2. **Role allow-list** — only configured roles can register or use passkeys.
3. **Ownership check** — non-superusers can only manage their own passkeys.
4. **CSRF** — every mutation endpoint validates a per-session token.
5. **WebAuthn binding** — userHandle must match the credential row's user_id; counter rollback is rejected; challenge is bound per-ceremony per-session.

### Defenses

- **Anchored origin validation** — works around the unanchored regex in `lbuchs/webauthn` so `evilexample.com` cannot match an RP ID of `example.com`. 24 unit tests cover the gate.
- **CSRF on every mutation** — register, rename, delete, banner-dismiss
- **Per-session rate limit** — 20 login attempts / 60s, applied to both `login/options` and `login/finish`
- **Per-user passkey cap** — 25, enforced atomically via `SELECT ... FOR UPDATE`
- **Signature-counter rollback rejection** — rejects clones, allows always-zero authenticators (e.g. iCloud Keychain)
- **userHandle binding** — the credential's resident `userHandle` must match the credential row's user_id
- **Cross-origin ceremonies rejected** — `clientDataJSON.crossOrigin === true` is refused
- **Cascading deletes** — passkeys are removed when their owning user is trashed or deleted
- **Trust-boundary enforcement** — even superuser-on-behalf registration binds the *acting* session user separately from the *target* user
- **User verification required** — `userVerification` is hardcoded to `required`; present-but-unverified assertions are refused. This is the W3C / FIDO Alliance posture for passkey deployments.

### Required operator actions

#### 1. Configure roles before enabling

The module fail-closes when no roles are allow-listed (no one can register or use passkeys). Configure at least one role in the module config screen before enabling.

#### 2. Pair the per-session rate limit with a per-IP limit

The module enforces **20 login attempts per 60 seconds per session** (`Endpoints::LOGIN_RATE_LIMIT_COMBINED` / `LOGIN_RATE_WINDOW`). This is sufficient against naive browser-tab brute force, but a determined attacker can rotate sessions to defeat it.

For production, **add a per-IP limit at the web server / WAF** scoped to:

- `POST /passkey-auth/login/options`
- `POST /passkey-auth/login/finish`

Suggested tools:

- **fail2ban** — match `passkey-auth-login-failures` log entries (path: `site/assets/logs/passkey-auth-login-failures.txt`). Each entry has `category=<short_code>` you can filter on (`unknown_credential`, `signature_verification_failed`, `counter_rollback`, etc.).
- **nginx `limit_req`** — rate-limit by `$binary_remote_addr` on the login URLs, e.g. 30 req/min with a small burst.
- **Cloudflare / WAF rule** — same idea at the edge.

#### 3. RP ID configuration

`Relying Party ID` MUST equal the host the admin is served from (or a registrable suffix). If you serve admin at `admin.example.com`, an RP ID of `example.com` works (subdomain match); `evilexample.com` does NOT (anchored origin check rejects it).

**Do not change the RP ID after passkeys are registered** — the WebAuthn credential is bound to the RP ID, and existing passkeys will stop working.

#### 4. HTTPS in production

Origins are accepted only over HTTPS, with a hard-coded carve-out for `localhost` and `127.0.0.1` for development. Browsers also refuse to expose the WebAuthn API on insecure origins (other than localhost).

#### 5. Content-Security-Policy

The module emits inline `<script>` blocks for client config (`window.PasskeyAuth = {...}`). If you deploy a strict CSP without `'unsafe-inline'`, the inline JSON will be blocked and passkey UI will break. See the class-level docblock in `PasskeyAuth.module.php` for workaround paths (nonce / dataset / scoped policy).

#### 6. Database

Schema is created on install. Tables:

- `passkey_auth` — current schema (this module).
- `loginpasskey` — legacy table from a prior name (dropped on uninstall, ignored otherwise).

Per-user passkey cap: 25 (`Endpoints::MAX_CREDENTIALS_PER_USER`). Enforced atomically inside `Storage::addIfUnderCap` via `SELECT ... FOR UPDATE`.

### Logging

Two log channels:

- `passkey-auth.txt` — general module errors (verifyRegistration / verifyLogin throws, encode failures, trash cascade, etc.).
- `passkey-auth-login-failures.txt` — every failed login attempt, with `category=<code>` and integer-only context fields. Safe to ship to SOC pipelines (no user-controlled data).

Login failure categories:

| Category | Meaning |
|---|---|
| `missing_credential` | Body missing `credential` field |
| `no_challenge` | Session has no in-flight login challenge |
| `invalid_response_shape` | `credential.response` is not an object |
| `malformed_b64` | Base64url decode of `rawId` / `clientDataJSON` / `authenticatorData` / `signature` failed |
| `unknown_credential` | `rawId` not in DB (most common probe signal) |
| `missing_user_handle` | `response.userHandle` empty/non-string |
| `user_handle_mismatch` | userHandle decoded but doesn't match credential's user_id |
| `orphaned_credential` | Credential row's user_id doesn't resolve to a user |
| `user_trashed` | User is in trash |
| `role_denied` | User's role is no longer in the allow-list |
| `signature_verification_failed` | lbuchs library threw during processGet |
| `counter_rollback` | Authenticator's signCount went backwards (clone indicator) |
| `already_logged_in` | Session is already authenticated |
| `rate_limited` | Per-session limit exceeded |

## How it works (brief)

- **Login endpoints** — registered as URL hooks at `/passkey-auth/login/options` and `/passkey-auth/login/finish` so they're reachable by guests before page resolution.
- **Protected endpoints** — live under `/admin/passkey-auth/` as a hidden Process module page (`ProcessPasskeyAuth`). The admin URL gate keeps guests out; finer authorization (role allow-list, ownership, CSRF) is enforced inside `Endpoints`.
- **Banner injection** — the registration prompt is injected directly into the rendered HTML by a `Page::render` hook (not via `$this->warning(...)`, which would persist undisplayed across redirects).
- **Server-side WebAuthn** — wraps `lbuchs/webauthn` for attestation/assertion verification. Origin and crossOrigin checks run *before* delegating to the library.

## Development

```bash
git clone https://github.com/adrianbj/PasskeyAuth.git
cd PasskeyAuth
composer install
./vendor/bin/phpunit
```

53 unit tests cover storage CRUD, rate limiting, name sanitisation, WebAuthn server option generation, and the origin-check gate (24 cases including evil-prefix host, FQDN trailing dot, scheme allow-list, userinfo / IPv6 / cross-origin rejections).

End-to-end browser testing is manual — see [`docs/`](./docs/) for the test pass checklist.

## License

MIT — see `composer.json`.

## Author

Adrian Jones — [github.com/adrianbj](https://github.com/adrianbj)
