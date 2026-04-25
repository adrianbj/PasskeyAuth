# PasskeyAuth — Security & Operations Notes

Deployment guidance for operators. Code-level security hardening is documented inline (search `SEC-D`, `SEC-E`, `SEC-F` markers).

## Threat model summary

This module adds WebAuthn passkey login to the ProcessWire admin. The login endpoints are guest-reachable; the management endpoints are admin-gated. Trust boundaries enforced inside the code:

1. **Page gate** (admin URL prefix) — keeps unauthenticated users out of management endpoints.
2. **Role allow-list** — only configured roles can register or use passkeys.
3. **Ownership check** — non-superusers can only manage their own passkeys.
4. **CSRF** — every mutation endpoint validates a per-session token.
5. **WebAuthn binding** — userHandle must match the credential row's user_id; counter rollback is rejected; challenge is bound per-ceremony per-session.

## Required operator actions

### 1. Configure roles before enabling

The module fail-closes when no roles are allow-listed (no one can register or use passkeys). Configure at least one role in the module config screen before enabling.

### 2. Pair the per-session rate limit with a per-IP limit

The module enforces **20 login attempts per 60 seconds per session** (`Endpoints::LOGIN_RATE_LIMIT_COMBINED` / `LOGIN_RATE_WINDOW`). This is sufficient against naive browser-tab brute force, but a determined attacker can rotate sessions to defeat it.

For production, **add a per-IP limit at the web server / WAF** scoped to:

- `POST /passkey-auth/login/options`
- `POST /passkey-auth/login/finish`

Suggested tools:

- **fail2ban** — match `passkey-auth-login-failures` log entries (path: `site/assets/logs/passkey-auth-login-failures.txt`). Each entry has `category=<short_code>` you can filter on (`unknown_credential`, `signature_verification_failed`, `counter_rollback`, etc.).
- **nginx `limit_req`** — rate-limit by `$binary_remote_addr` on the login URLs, e.g. 30 req/min with a small burst.
- **Cloudflare / WAF rule** — same idea at the edge.

### 3. RP ID configuration

`Relying Party ID` MUST equal the host the admin is served from (or a registrable suffix). If you serve admin at `admin.example.com`, an RP ID of `example.com` works (subdomain match); `evilexample.com` does NOT (anchored origin check rejects it).

**Do not change the RP ID after passkeys are registered** — the WebAuthn credential is bound to the RP ID, and existing passkeys will stop working.

### 4. HTTPS in production

Origins are accepted only over HTTPS, with a hard-coded carve-out for `localhost` and `127.0.0.1` for development. Browsers also refuse to expose the WebAuthn API on insecure origins (other than localhost).

### 5. Content-Security-Policy

The module emits inline `<script>` blocks for client config (`window.PasskeyAuth = {...}`). If you deploy a strict CSP without `'unsafe-inline'`, the inline JSON will be blocked and passkey UI will break. See the class-level docblock in `PasskeyAuth.module.php` for workaround paths (nonce / dataset / scoped policy).

### 6. Database

Schema is created on install. Tables:

- `passkey_auth` — current schema (this module).
- `loginpasskey` — legacy table from a prior name (dropped on uninstall, ignored otherwise).

Per-user passkey cap: 25 (`Endpoints::MAX_CREDENTIALS_PER_USER`). Enforced atomically inside `Storage::addIfUnderCap` via `SELECT ... FOR UPDATE`.

## Logging

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

## Testing

```bash
composer install
./vendor/bin/phpunit
```

Includes unit tests for: storage CRUD, rate limiter, name sanitisation, WebAuthn server options, and the origin-check gate (24 cases covering host equality, subdomains, case sensitivity, FQDN trailing dot, scheme allow-list, userinfo / IPv6 / cross-origin rejections).
