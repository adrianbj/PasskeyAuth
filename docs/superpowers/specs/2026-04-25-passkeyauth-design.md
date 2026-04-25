# PasskeyAuth — Design Spec

**Date:** 2026-04-25
**Author:** Adrian Jones (with Claude Code)
**Status:** Approved for implementation

## Goal

Replace the broken `LoginPassKey` module with a clean, native-WebAuthn passkey
authentication module for the **ProcessWire admin login** at `paddle.grief.coach`
and similar deployments. The module must install with no manual template-file
juggling, support multiple passkeys per user with a management UI, and follow
the GitHub-style passkey UX (autofill + button on login, dismissable banner for
registration prompt).

## Non-goals

- **Frontend (public-site) passkey login.** Handled separately by `LoginGoogle`
  (Google OAuth). This module is admin-only.
- **TOTP fallback.** Handled by ProcessWire core's `TfaTotp` module, configured
  per-user. The two paths (passkey OR username+password+TOTP) are independent
  and either is sufficient to log in.
- **Migration from `LoginPassKey`.** Production has never had a successful
  registration; clean-slate. The old `loginpasskey` table will be dropped on
  uninstall as a courtesy but not migrated.
- **Custom attestation policies.** We accept `none` and `packed` attestation —
  whatever `lbuchs/WebAuthn` accepts by default. No FIDO MDS / metadata
  validation.

## High-level architecture

**Module:** `PasskeyAuth`, installed at `/site/modules/PasskeyAuth/`. Single
autoload module; no companion `Process` module.

**Underlying WebAuthn library:** `lbuchs/WebAuthn` (zero-dependency). Pulled in
via the module's own `composer.json`.

**File layout:**

```
/site/modules/PasskeyAuth/
├── PasskeyAuth.module.php       # autoload module class
├── PasskeyAuth.info.php
├── composer.json                 # requires lbuchs/WebAuthn ^2.x
├── src/
│   ├── Storage.php               # DB read/write for passkey rows
│   ├── Server.php                # wraps lbuchs/WebAuthn (registration, verification)
│   └── Endpoints.php             # URL-hook handlers (orchestrates Storage + Server + session)
├── PasskeyAuth.js                # single client file; entry points by mode
└── PasskeyAuth.css               # banner + management UI styling
```

**Separation of concerns:** Storage knows nothing about WebAuthn. Server knows
nothing about the database. Endpoints orchestrates both plus the ProcessWire
session/user. Each file is small and unit-testable in isolation. Replacing the
underlying WebAuthn library later only touches `Server.php`.

## Data model

Single MySQL table `passkey_auth`, created in `___install()`:

```sql
CREATE TABLE passkey_auth (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED NOT NULL,
    credential_id   VARBINARY(255) NOT NULL,
    public_key      BLOB NOT NULL,
    sign_count      INT UNSIGNED NOT NULL DEFAULT 0,
    name            VARCHAR(120) NOT NULL,
    aaguid          CHAR(36) DEFAULT NULL,
    transports      VARCHAR(80) DEFAULT NULL,
    created         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used       TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY credential_id_unique (credential_id),
    KEY user_id_idx (user_id),
    CONSTRAINT passkey_auth_user_fk FOREIGN KEY (user_id)
        REFERENCES pages(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Column rationale:**

- `credential_id` `VARBINARY(255)`: raw bytes from the authenticator. WebAuthn
  IDs can theoretically be up to 1023 bytes but real-world IDs are ≤128 bytes.
- `public_key` `BLOB`: COSE-encoded public key bytes from `lbuchs/WebAuthn`.
  Stored verbatim so we hand the same bytes back during verification — no
  round-trip transformation.
- `sign_count`: replay-protection counter. Many platform authenticators (notably
  iCloud Keychain) report 0 every time; we tolerate this rather than rejecting,
  but log a warning when a counter regresses.
- `name`: user-supplied label. Defaults to `<OS>/<browser>` heuristic at
  registration time.
- `aaguid`: authenticator's AAGUID. Used to render a friendly icon/name in the
  management UI ("iCloud Keychain", "YubiKey 5", etc.). Often all-zero.
- `transports`: JSON-encoded list (`["internal","hybrid"]`). Currently advisory.
- `pages(id)` FK with `ON DELETE CASCADE`: deleting a PW user deletes their
  passkeys.

## API endpoints

All endpoints register via `$wire->addHook($path, ...)` in `init()`. Path prefix
configurable; default `/passkey-auth/`. All responses JSON, content-type set
explicitly. Uniform error shape: `{ error: 'human message', code: 'short_slug' }`
with appropriate HTTP status.

**Registration (requires logged-in user):**

| Method | Path | Body | Returns |
|--------|------|------|---------|
| POST | `/passkey-auth/register/options` | `{ name }` | `PublicKeyCredentialCreationOptions` |
| POST | `/passkey-auth/register/finish`  | `{ name, credential }` | `{ ok: true, passkey: { id, name, ... } }` |

`/options` stashes the challenge in `$session`; `/finish` reads it back and
clears it. `excludeCredentials` is populated from the user's existing passkeys
to prevent duplicate registration on the same authenticator.

**Login (no auth required):**

| Method | Path | Body | Returns |
|--------|------|------|---------|
| POST | `/passkey-auth/login/options` | (empty) | `PublicKeyCredentialRequestOptions` with `allowCredentials: []` |
| POST | `/passkey-auth/login/finish`  | `{ credential }` | `{ ok: true, redirect: '/htgc-admin/' }` |

`allowCredentials: []` enables discoverable credentials (autofill flow).
`/finish` looks up the credential by ID, verifies the assertion, checks the
user is in the configured allowed-roles set, then `$session->forceLogin($user)`.

**Management (requires logged-in user):**

| Method | Path | Body | Returns |
|--------|------|------|---------|
| POST | `/passkey-auth/list`             | `{ userId? }` | `[ { id, name, created, lastUsed, aaguid }, ... ]` |
| POST | `/passkey-auth/rename`           | `{ id, name }` | `{ ok: true }` |
| POST | `/passkey-auth/delete`           | `{ id }` | `{ ok: true }` |
| POST | `/passkey-auth/banner/dismiss`   | (empty) | `{ ok: true }` |

**Authorization rules:**

- `list/rename/delete` accept an optional `userId`. Without it, they operate on
  `$user->id`. With it, the requesting user must be either acting on themselves
  OR a superuser. Otherwise 403.
- All write endpoints validate `$session->CSRF->validate($token)` against a
  token sent in `X-CSRF-Token` header.
- Login endpoints don't require CSRF — the WebAuthn challenge is a stronger
  anti-replay mechanism.

**Login error messages are deliberately generic** ("Authentication failed —
try password instead") to prevent username enumeration via timing or message
differences.

## Server-side components

### `Storage.php`

Plain DB access. No ProcessWire session/user knowledge, no WebAuthn knowledge.
Uses `wire('database')` (PDO).

```php
class Storage {
    public function add(int $userId, array $row): int  // returns inserted id
    public function findByCredentialId(string $credentialId): ?array
    public function listForUser(int $userId): array
    public function findById(int $id): ?array
    public function rename(int $id, string $name): bool
    public function delete(int $id): bool
    public function touchLastUsed(int $id, int $signCount): void
    public function countForUser(int $userId): int
}
```

### `Server.php`

Thin wrapper over `lbuchs\WebAuthn\WebAuthn`. Holds the WebAuthn instance
configured with the relying-party config. Methods return arrays/objects ready
to JSON-encode or hand to Storage.

```php
class Server {
    public function __construct(string $rpName, string $rpId, array $allowedFormats = ['none','packed'])
    public function registrationOptions(int $userId, string $userName, string $userDisplayName, array $excludeCredentialIds): array
    public function verifyRegistration(string $clientDataJson, string $attestationObject, string $challenge): array  // returns ['credentialId', 'publicKey', 'signCount', 'aaguid', 'transports']
    public function loginOptions(): array
    public function verifyLogin(string $clientDataJson, string $authenticatorData, string $signature, string $userHandle, string $publicKey, string $challenge, int $storedSignCount): array  // returns ['signCount']
}
```

### `Endpoints.php`

URL-hook handlers. Each method maps 1:1 to an endpoint. Calls into Storage and
Server, manages session state (challenge, dismissed flag, login redirect).

```php
class Endpoints {
    public function registerOptions(HookEvent $event): string
    public function registerFinish(HookEvent $event): string
    public function loginOptions(HookEvent $event): string
    public function loginFinish(HookEvent $event): string
    public function list(HookEvent $event): string
    public function rename(HookEvent $event): string
    public function delete(HookEvent $event): string
    public function bannerDismiss(HookEvent $event): string
}
```

A small helper `respond($data, int $status = 200): string` sets the JSON
content-type header and HTTP status, json-encodes the body, and returns the
string for `$event->return`.

### `PasskeyAuth.module.php`

The autoload module. Wires everything together.

- `__construct()`: instantiate Storage, Server, Endpoints with config from PW.
- `init()`:
  - Register the URL hook for the API endpoints.
  - Hook `ProcessLogin::buildLoginForm` (after) to add the autofill + button.
  - Hook `ProcessUser::buildEditForm` (after) to add the management fieldset.
  - Hook `ProcessProfile::buildForm` (after) to add the management fieldset.
  - Hook `Page::render` (after) on admin pages to inject the banner.
- `___install()`: create `passkey_auth` table.
- `___uninstall()`: drop `passkey_auth` table; drop legacy `loginpasskey` table
  if present (defensive cleanup).
- `getModuleConfigInputfields($data)`: see "Module configuration" below.

## Client-side components

Single file `PasskeyAuth.js`, dispatches based on `window.PasskeyAuth.mode`
which is set by an inline `<script>` blob the server injects:

- `mode: 'login'` — admin login page integration
- `mode: 'banner'` — auto-registration banner
- `mode: 'manage'` — management UI on user-edit and profile pages

### `mode: 'login'`

1. On `DOMContentLoaded`, feature-detect:
   `window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable && await PublicKeyCredential.isConditionalMediationAvailable()`.
2. If supported, fetch `/passkey-auth/login/options`, then start a *conditional*
   `navigator.credentials.get({ mediation: 'conditional', publicKey: options, signal: abortCtl.signal })`.
   This promise hangs until the user picks a passkey from the autofill dropdown.
3. The "Sign in with passkey" button click handler:
   - `abortCtl.abort()` to cancel the pending conditional call.
   - Fetch fresh `/passkey-auth/login/options`.
   - Call `navigator.credentials.get({ publicKey: options })` (modal flow).
4. Both paths converge on `handleAssertion(credential)`: serialise credential to
   base64url, POST to `/passkey-auth/login/finish`, on `{ ok, redirect }` set
   `window.location.href = redirect`.
5. On error: write a generic message into `.passkey-auth-status`, don't disclose
   specifics. Don't break the password form — user can fall through to typing
   their password normally.

**Failure modes handled:**

- No passkey on device → conditional call never resolves; user types password.
- No conditional UI support → autofill skipped, button still works.
- No WebAuthn support at all → button is hidden via JS feature-check.
- User cancels biometric → status message, button re-enabled.

### `mode: 'banner'`

DOM is injected by the server (see "Hook integration" below). JS:

- Dismiss button: POST `/passkey-auth/banner/dismiss`, remove banner from DOM.
- Set up button: prompt for a name (default = `<OS>/<browser>` heuristic), run
  `registrationFlow(name)`, swap banner content to "✓ Passkey added" with a
  3-second auto-fade on success. On error, show inline error and allow retry.

### `mode: 'manage'`

- On load: POST `/passkey-auth/list` (with `userId` if editing another user),
  render rows.
- Inline rename: click name → input → blur or Enter posts to
  `/passkey-auth/rename`. Escape cancels.
- Delete: native `confirm()` then POST `/passkey-auth/delete`. Optimistic UI,
  rollback on error.
- "Add a passkey" button: prompt for name, run `registrationFlow(name)`, prepend
  the new row.

### Shared `registrationFlow(name)`

```js
async function registrationFlow(name, userId = null) {
  const opts = await postJSON('/passkey-auth/register/options', { name, userId });
  const credential = await navigator.credentials.create({ publicKey: opts });
  const result = await postJSON('/passkey-auth/register/finish', {
    name, userId, credential: serializeCredential(credential)
  });
  return result;
}
```

## Hook integration

### `ProcessLogin::buildLoginForm` (after)

Modifies the form returned by ProcessLogin. Steps:

1. Find the username `Inputfield` and add `attr('autocomplete', 'username webauthn')`.
2. Append an `InputfieldMarkup` after the password field with the button +
   status `<div>` markup.
3. Append a second `InputfieldMarkup` containing the inline config blob and
   `<script src>` for `PasskeyAuth.js`.

Inline config blob:
```html
<script>window.PasskeyAuth = { apiUrl: '/passkey-auth/', mode: 'login' };</script>
```

### `ProcessUser::buildEditForm` and `ProcessProfile::buildForm` (after)

Both hooks: append a "Passkeys" `InputfieldFieldset` (collapsed if no passkeys,
expanded otherwise) containing one `InputfieldMarkup` with the management UI
markup and the inline config blob:

```html
<script>window.PasskeyAuth = { apiUrl: '/passkey-auth/', mode: 'manage', userId: <id>, csrf: '<token>' };</script>
```

Permission check: if the editing user is not a superuser AND not editing their
own record, the fieldset is omitted.

### `Page::render` (after) on admin pages

Conditions for injecting the banner:

1. `$user->isLoggedin()` AND user has at least one role from the configured
   allowed-roles set. (This implicitly excludes the login form page, which is
   only reached by guest users.)
2. `Storage::countForUser($user) === 0`.
3. `$session->getFor($module, 'banner_dismissed')` is not set.
4. Current page template is `admin`.
5. Module config `bannerEnabled` is on.

Banner HTML (injected before `</body>`):

```html
<div class="passkey-auth-banner" data-passkey-auth-banner>
  <span class="passkey-auth-banner__icon">🔑</span>
  <span class="passkey-auth-banner__text">
    Add a passkey for faster, more secure sign-in.
  </span>
  <button type="button" data-passkey-auth-action="register">Set up</button>
  <button type="button" data-passkey-auth-action="dismiss" aria-label="Dismiss">×</button>
</div>
<script>window.PasskeyAuth = { apiUrl: '/passkey-auth/', mode: 'banner', csrf: '<token>' };</script>
<script src="/site/modules/PasskeyAuth/PasskeyAuth.js" defer></script>
```

## Module configuration

Fields presented by `getModuleConfigInputfields`:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `apiUrlPrefix` | text | `/passkey-auth/` | Must start and end with `/`. Where URL hooks register. |
| `appName` | text | `$config->httpHost` | Shown in OS biometric prompt. |
| `rpId` | text | `$config->httpHost` | Relying-party ID. **Don't change after registrations exist** — invalidates all existing passkeys. |
| `allowedRoles` | checkbox-list | `[superuser]` | Only users with at least one of these roles can register or use passkeys. |
| `userVerification` | radio | `preferred` | `discouraged | preferred | required` |
| `residentKeyRequirement` | radio | `required` | `discouraged | preferred | required`. Default `required` for the autofill flow. |
| `bannerEnabled` | checkbox | on | Toggle the auto-prompt banner. |

## Installation and deployment

**Install:**

1. Drop the module folder into `/site/modules/PasskeyAuth/`.
2. Run `composer install` inside the module folder (or `composer require` from
   site root if `lbuchs/WebAuthn` is added to the site's root composer.json).
3. Admin → Modules → Refresh → Install `PasskeyAuth`.
4. Module config: confirm `rpId` matches the production hostname; confirm
   `allowedRoles` includes the right roles.
5. Enable core `TfaTotp` module separately and configure on each admin user
   account (independent fallback path).

**Uninstall:** drops `passkey_auth` and (defensively) `loginpasskey` tables.
Removes its hooks. No leftover pages or templates.

**Deployment to `paddle.grief.coach`:** plain file copy + composer install +
Modules → Refresh. No template files to ship, no admin page tree entries to
create.

## Security considerations

- **Origin/RP-ID binding** — handled by browser + lbuchs/WebAuthn. Cannot be
  bypassed without a separate XSS or browser bug.
- **Replay protection** — the WebAuthn challenge (one-time, session-scoped)
  plus `sign_count` regression check.
- **CSRF** — write endpoints (registration, rename, delete, dismiss) check the
  PW session CSRF token. Login endpoints don't (challenge takes its place).
- **Username enumeration** — login endpoints return generic errors. The
  registration `excludeCredentials` list could leak existing passkey IDs to a
  logged-in user, but those users already have access to their own data.
- **Authorization on management endpoints** — list/rename/delete require either
  `userId === $user->id` or `$user->isSuperuser()`. Without this, any
  authenticated admin could enumerate or destroy another admin's passkeys.
- **Role-gated login** — the login endpoint refuses to log in users who don't
  have a role in the configured allowed-roles set, even if their credential
  verifies. Prevents passkey-bypass for users who registered then later had
  their role revoked.
- **Counter regression** — logged but not enforced as a hard reject, because
  iCloud Keychain reliably reports 0. Treated as advisory.
- **Cross-user passkey reuse** — credential IDs are unique across the table
  (`UNIQUE KEY`). A single physical authenticator can hold a credential for
  exactly one PW user.

## Out of scope / future work

- Frontend (public-site) passkey registration/login.
- Recovery codes (replaced by `TfaTotp` fallback).
- Conditional-UI feature on registration (only relevant on login).
- Authenticator metadata service / FIDO MDS.
- Passkey export / import.
- Per-passkey scoping (e.g. "this passkey only valid from this IP range").
