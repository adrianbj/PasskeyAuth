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

This module is designed for production deployment of an admin login surface. The threat model and defenses are summarised in [`SECURITY.md`](./SECURITY.md). Highlights:

- **Anchored origin validation** — works around the unanchored regex in `lbuchs/webauthn` so `evilexample.com` cannot match an RP ID of `example.com`. 24 unit tests cover the gate.
- **CSRF on every mutation** — register, rename, delete, banner-dismiss
- **Per-session rate limit** — 20 login attempts / 60s, applied to both `login/options` and `login/finish`
- **Per-user passkey cap** — 25, enforced atomically via `SELECT ... FOR UPDATE`
- **Signature-counter rollback rejection** — rejects clones, allows always-zero authenticators (e.g. iCloud Keychain)
- **userHandle binding** — the credential's resident `userHandle` must match the credential row's user_id
- **Cross-origin ceremonies rejected** — `clientDataJSON.crossOrigin === true` is refused
- **Cascading deletes** — passkeys are removed when their owning user is trashed or deleted
- **Trust-boundary enforcement** — even superuser-on-behalf registration binds the *acting* session user separately from the *target* user

For production deployment, **pair the per-session rate limit with a per-IP limit** at your web server / WAF — see `SECURITY.md` for fail2ban + nginx recipes and the structured `passkey-auth-login-failures` log channel reference.

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
