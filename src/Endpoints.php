<?php declare(strict_types=1);

namespace PasskeyAuth;

use ProcessWire\User;
use ProcessWire\WireException;

final class Endpoints
{
    public const SESSION_NAMESPACE = 'PasskeyAuth';
    // L5: distinct keys for register vs login challenges so a register
    // ceremony in another tab doesn't clobber an in-flight login (and vice
    // versa).
    //
    // SEC-E L-A6: NOT mitigated here — two concurrent register tabs (or two
    // concurrent login tabs) DO clobber each other's challenge, because both
    // tabs share the same session key. The first tab to call /finish after
    // the second tab has called /options will fail challenge verification
    // and have to retry. This is acceptable: it's a UX papercut, never a
    // security issue (the verification fails closed), and the mitigation
    // (per-ceremony challenge IDs round-tripped through the client) adds
    // significant complexity for a niche workflow.
    private const REGISTER_CHALLENGE_KEY = 'register_challenge';
    private const LOGIN_CHALLENGE_KEY    = 'login_challenge';
    private const BANNER_DISMISSED_KEY = 'banner_dismissed';
    private const CSRF_ID = 'passkey-auth';
    private const LOGIN_RATE_KEY = 'login_rate';
    // H2: per-session rate limit. Per-session is enough to defeat naive browser-tab
    // spamming without infrastructure dependencies. A determined attacker can rotate
    // sessions to defeat this; the proper defense for that case is a per-IP limit
    // at the web server (fail2ban, nginx limit_req).
    private const LOGIN_RATE_WINDOW = 60;
    // SEC-D H4: per-user passkey cap. 25 covers any plausible legitimate
    // multi-device user (laptop+phone+tablet+yubikey * a few replacements)
    // while bounding storage cost and the size of excludeCredentials lists.
    public const MAX_CREDENTIALS_PER_USER = 25;

    // SEC-E M-A5: rate limit applies to BOTH login/options and login/finish so
    // a timing oracle on finish (existence-of-credential probe) is bounded by
    // the same per-session budget. Both endpoints increment the counter; one
    // legitimate login attempt = 2 increments. Doubled the limit (10 → 20) so
    // a real user with a few retries doesn't get locked out, while keeping the
    // window tight enough to deter brute force.
    private const LOGIN_RATE_LIMIT_COMBINED = 20;

    // L6: bound base64url input size before decoding. Real WebAuthn fields fit
    // well below this — credential IDs are typically 16-128 bytes, signatures
    // ~64-512 bytes, attestation/clientData under 4KB. 8192 base64 chars =
    // ~6KB decoded, generous headroom for any conformant authenticator while
    // keeping a single bad request from chewing memory.
    private const MAX_B64_INPUT_LEN = 8192;

    // SEC-E M-A1: cap the entire request body. The largest legitimate WebAuthn
    // payload (a register-finish containing attestationObject + clientDataJSON
    // base64-encoded) is well under 16 KB. 64 KB is a safety margin that still
    // costs <0.1% of typical PHP memory_limit per request and prevents an
    // unauthenticated flood of multi-MB bodies from saturating workers via
    // file_get_contents allocations and json_decode work.
    private const MAX_BODY_SIZE = 65536;

    /**
     * SEC-F #4: dedicated log channel for login failures. Each branch in
     * loginFinish that returns auth_failed records the category here so
     * operators / SOC can tune fail2ban rules and detect probing patterns
     * without sifting the general module log. Categories are short,
     * deliberately opaque codes (no user input echoed back) so the log
     * itself is safe to expose to monitoring pipelines.
     */
    private const LOGIN_FAILURE_LOG = 'passkey-auth-login-failures';

    public function __construct(
        private readonly Storage $storage,
        private readonly Server $server,
        private readonly \ProcessWire\Wire $wire,
        private readonly array $allowedRoleIds,
        private readonly bool $requireResidentKey,
    ) {}

    /**
     * Set JSON content type, status code, and return the encoded body.
     *
     * L3: json_encode can fail (e.g. if a non-UTF-8 binary string slips into a
     * response payload). JSON_THROW_ON_ERROR would surface that as an uncaught
     * exception AFTER headers were already sent — leaving the client with an
     * empty body and the server-side log message hidden from view. Catch it
     * and emit a static, always-encodeable fallback so the client always gets
     * a parseable JSON error and the original failure is logged.
     */
    private function respond(array $data, int $status = 200): string
    {
        http_response_code($status);
        header('Content-Type: application/json');
        // M1: belt-and-braces against MIME sniffing and shared-cache leakage.
        // These responses are per-session (CSRF tokens, ownership-bound) and
        // must never be cached or content-type-coerced into HTML.
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        header('Pragma: no-cache');
        // SEC-F #1: defense-in-depth headers on JSON responses.
        //   - Referrer-Policy: no-referrer prevents the next navigation from
        //     leaking the endpoint URL (and any query params, though we don't
        //     use them) via the Referer header to a third-party origin.
        //   - X-Frame-Options: DENY blocks the JSON response itself from being
        //     embedded in a frame. The JSON has no UI and isn't a clickjacking
        //     target on its own, but a misconfigured upstream (a permissive
        //     Content-Security-Policy frame-ancestors, an admin-overridden
        //     X-Frame-Options) shouldn't be able to weaken this endpoint's
        //     framing posture; setting it explicitly here is fail-closed.
        header('Referrer-Policy: no-referrer');
        header('X-Frame-Options: DENY');
        try {
            return json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (\JsonException $e) {
            $this->wire->wire('log')->save('passkey-auth', 'respond: json_encode failed: ' . self::sanitizeForLog($e->getMessage()));
            http_response_code(500);
            return '{"error":"Server error","code":"encode_failed"}';
        }
    }

    /**
     * L1: sanitize a string before logging. Strips control characters (newlines,
     * tabs) to prevent log injection from third-party exception messages or any
     * code path where attacker-influenced bytes could reach the message text.
     * Clamp length so a hostile input can't bloat the log file.
     */
    private static function sanitizeForLog(string $msg): string
    {
        $clean = preg_replace('/[^\x20-\x7E]/', '?', $msg) ?? '';
        return substr($clean, 0, 500);
    }

    /**
     * H2: enforce HTTP POST on every endpoint. PW URL hooks fire for any
     * method; without this, GET requests can churn challenges, consume
     * rate-limit budget, and spawn sessions without preflight. Returns a
     * pre-encoded 405 response if the method is wrong, null otherwise.
     */
    private function requirePost(): ?string
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            header('Allow: POST');
            return $this->error('Method not allowed', 'method_not_allowed', 405);
        }
        return null;
    }

    private function error(string $message, string $code, int $status = 400): string
    {
        return $this->respond(['error' => $message, 'code' => $code], $status);
    }

    /**
     * Read & decode the JSON request body, capped at MAX_BODY_SIZE.
     *
     * SEC-E M-A1: read at most MAX_BODY_SIZE+1 bytes so we can detect oversize
     * (length > MAX_BODY_SIZE) without allocating an arbitrary-size string.
     * Oversize bodies short-circuit to an empty array, which downstream gates
     * (CSRF / required fields) translate into a 4xx — strictly more aggressive
     * would be a 413, but the empty-array path is uniform with malformed JSON
     * and avoids leaking "yes I have a size limit" to an attacker probing.
     * Also reduce json_decode max depth from 64 → 8: the deepest legitimate
     * WebAuthn payload nests ~3 levels (cred.response.{...}); 8 is generous.
     */
    private function readJsonBody(): array
    {
        $raw = (string) @file_get_contents('php://input', false, null, 0, self::MAX_BODY_SIZE + 1);
        if (strlen($raw) > self::MAX_BODY_SIZE) return [];
        $raw = trim($raw);
        if ($raw === '') return [];
        try {
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : [];
        } catch (\JsonException) {
            return [];
        }
    }

    private function session(): \ProcessWire\Session { return $this->wire->wire('session'); }
    private function user(): User { return $this->wire->wire('user'); }

    private function requireLoggedIn(): ?string
    {
        if (!$this->user()->isLoggedin()) {
            return $this->error('Authentication required', 'auth_required', 401);
        }
        return null;
    }

    private function requireCsrf(array $body): ?string
    {
        $submitted = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($body['csrf'] ?? '');
        $submitted = is_string($submitted) ? trim($submitted) : '';
        if ($submitted === '') {
            return $this->error('Invalid session', 'invalid_csrf', 403);
        }
        $expected = $this->wire->wire('session')->CSRF->getTokenValue(self::CSRF_ID);
        if (!is_string($expected) || $expected === '' || !hash_equals($expected, $submitted)) {
            return $this->error('Invalid session', 'invalid_csrf', 403);
        }
        return null;
    }

    /** Targeted user for management endpoints; superuser-gated for cross-user. */
    private function targetUser(?int $userId): ?User
    {
        $current = $this->user();
        if ($userId === null || $userId === $current->id) return $current;
        if (!$current->isSuperuser()) return null;
        $target = $this->wire->wire('users')->get($userId);
        return ($target && $target->id) ? $target : null;
    }

    private function isAllowedByRole(User $user): bool
    {
        if (empty($this->allowedRoleIds)) return false;
        foreach ($user->roles as $role) {
            if (in_array($role->id, $this->allowedRoleIds, true)) return true;
        }
        return false;
    }

    /**
     * Strict base64url decoder. WebAuthn `cred.toJSON()` produces base64url
     * (uses `-_` instead of `+/`, no padding). Returns null for malformed
     * input or input larger than MAX_B64_INPUT_LEN (L6 hardening).
     */
    private function base64UrlDecode(string $s): ?string
    {
        if ($s === '' || strlen($s) > self::MAX_B64_INPUT_LEN) return null;
        $b64 = strtr($s, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) $b64 .= str_repeat('=', 4 - $pad);
        $decoded = base64_decode($b64, true);
        return $decoded === false ? null : $decoded;
    }

    private function clearRegistrationSession(): void
    {
        $this->session()->removeFor(self::SESSION_NAMESPACE, self::REGISTER_CHALLENGE_KEY);
        $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_user_id');
        $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_name');
    }

    private function clearLoginSession(): void
    {
        $this->session()->removeFor(self::SESSION_NAMESPACE, self::LOGIN_CHALLENGE_KEY);
    }

    /**
     * M3: invoked from the Session::logoutSuccess hook to clear any in-flight
     * registration / banner-dismissal state that could otherwise survive across
     * a logout-then-different-user-login on the same session id, and bind to
     * the next user's identity in unexpected ways.
     */
    public function clearAllSessionState(): void
    {
        $this->clearRegistrationSession();
        $this->clearLoginSession();
        $this->session()->removeFor(self::SESSION_NAMESPACE, self::BANNER_DISMISSED_KEY);
        $this->session()->removeFor(self::SESSION_NAMESPACE, self::LOGIN_RATE_KEY);
    }

    /**
     * SEC-F #4: emit a structured login-failure record on its own channel.
     * Category is a short fixed code from a closed set ({@see loginFinish}
     * call sites). No user-controlled fields are passed in; only ints
     * (credential id, user id, counters) which are safe to log directly.
     */
    private function logLoginFailure(string $category, array $context = []): void
    {
        $parts = ['category=' . $category];
        foreach ($context as $k => $v) {
            // Only int-typed context values are accepted; anything else is
            // dropped to keep the log fully attacker-input-free.
            if (is_int($v)) $parts[] = $k . '=' . $v;
        }
        $this->wire->wire('log')->save(self::LOGIN_FAILURE_LOG, implode(' ', $parts));
    }

    public function registerOptions(): string
    {
        if ($err = $this->requirePost()) return $err;
        if ($err = $this->requireLoggedIn()) return $err;
        $body = $this->readJsonBody();
        if ($err = $this->requireCsrf($body)) return $err;

        $current = $this->user();
        $userId = isset($body['userId']) ? (int) $body['userId'] : $current->id;
        $target = $this->targetUser($userId);
        if (!$target) return $this->error('Forbidden', 'forbidden', 403);

        if (!$this->isAllowedByRole($target)) {
            return $this->error('User not permitted to register passkeys', 'role_denied', 403);
        }

        // H4: enforce per-user passkey cap. Checked again at finish time
        // because options-issuance and finish are separate requests; a client
        // could race two finishes against a single options call.
        if ($this->storage->countForUser($target->id) >= self::MAX_CREDENTIALS_PER_USER) {
            return $this->error('Passkey limit reached', 'limit_reached', 409);
        }

        $existing = $this->storage->listForUser($target->id);
        $excludeIds = array_map(fn($r) => (string) $r['credential_id'], $existing);

        $rawName = (string) ($body['name'] ?? '');
        if (trim($rawName) === '') {
            $rawName = 'Passkey added ' . date('Y-m-d');
        }
        $name = Naming::sanitize($rawName);
        if ($name === null) {
            return $this->error('Invalid name', 'bad_request', 400);
        }

        $result = $this->server->registrationOptions(
            $target->id,
            $target->name,
            $target->name,  // displayName — could be made configurable later
            $excludeIds,
            $this->requireResidentKey,
        );

        $this->session()->setFor(self::SESSION_NAMESPACE, self::REGISTER_CHALLENGE_KEY, $result['challenge']);
        $this->session()->setFor(self::SESSION_NAMESPACE, 'register_user_id', $target->id);
        // M3: also bind to the *session* user id at options time so finish can
        // confirm the same browser session is completing the ceremony, even
        // if the target is someone else (superuser-on-behalf flow).
        $this->session()->setFor(self::SESSION_NAMESPACE, 'register_session_user_id', $current->id);
        $this->session()->setFor(self::SESSION_NAMESPACE, 'register_name', $name);

        return $this->respond(['options' => $result['options']]);
    }

    public function registerFinish(): string
    {
        if ($err = $this->requirePost()) return $err;
        if ($err = $this->requireLoggedIn()) return $err;
        $body = $this->readJsonBody();
        if ($err = $this->requireCsrf($body)) return $err;

        $challenge       = $this->session()->getFor(self::SESSION_NAMESPACE, self::REGISTER_CHALLENGE_KEY);
        $userId          = (int) $this->session()->getFor(self::SESSION_NAMESPACE, 'register_user_id');
        $sessionUserId   = (int) $this->session()->getFor(self::SESSION_NAMESPACE, 'register_session_user_id');
        $name            = (string) $this->session()->getFor(self::SESSION_NAMESPACE, 'register_name');

        // JS may override the auto-generated name after navigator.credentials.create()
        // returns — e.g. when authenticatorAttachment === 'cross-platform' indicates
        // the credential was registered via QR/hybrid on a phone, so we relabel it.
        // Sanitization below applies uniformly whether the name came from session or body.
        $bodyName = (string) ($body['name'] ?? '');
        if (trim($bodyName) !== '') {
            $name = $bodyName;
        }

        if (!$challenge || !$userId) {
            $this->clearRegistrationSession();
            return $this->error('No registration in progress', 'no_session', 400);
        }

        // M3: the session user that *started* the ceremony must still be the
        // one finishing it. Without this, a logout-then-different-user-login
        // on the same session id could land someone else's authenticator
        // attestation on the original target. Superuser-on-behalf is preserved
        // because both options and finish must be executed by the same admin.
        if (!$sessionUserId || $sessionUserId !== (int) $this->user()->id) {
            $this->clearRegistrationSession();
            return $this->error('Forbidden', 'forbidden', 403);
        }

        // H1: re-check role allow-list at finish time. Roles may have changed since options.
        $targetUser = $this->wire->wire('users')->get($userId);
        if (!$targetUser || !$targetUser->id || !$this->isAllowedByRole($targetUser)) {
            $this->clearRegistrationSession();
            return $this->error('Forbidden', 'forbidden', 403);
        }

        // H4 / SEC-F #2: per-user cap is enforced atomically inside
        // storage->addIfUnderCap below. We keep this pre-flight count purely
        // as a fast-fail to avoid running crypto verification on a request
        // that's certain to be rejected by the cap; the authoritative check
        // is the transactional one.
        if ($this->storage->countForUser($userId) >= self::MAX_CREDENTIALS_PER_USER) {
            $this->clearRegistrationSession();
            return $this->error('Passkey limit reached', 'limit_reached', 409);
        }

        $cred = $body['credential'] ?? null;
        if (!is_array($cred)) {
            $this->clearRegistrationSession();
            return $this->error('Missing credential', 'missing_credential', 400);
        }

        $response = $cred['response'] ?? null;
        if (!is_array($response)) {
            $this->clearRegistrationSession();
            return $this->error('Invalid credential payload', 'invalid_payload', 400);
        }

        $clientDataJson    = $this->base64UrlDecode((string) ($response['clientDataJSON'] ?? ''));
        $attestationObject = $this->base64UrlDecode((string) ($response['attestationObject'] ?? ''));
        if ($clientDataJson === null || $attestationObject === null) {
            $this->clearRegistrationSession();
            return $this->error('Invalid credential payload', 'invalid_payload', 400);
        }

        try {
            $verified = $this->server->verifyRegistration($clientDataJson, $attestationObject, $challenge);
        } catch (\Throwable $e) {
            $this->wire->wire('log')->save('passkey-auth', 'verifyRegistration failed: ' . self::sanitizeForLog($e->getMessage()));
            $this->clearRegistrationSession();
            return $this->error('Verification failed', 'verify_failed', 400);
        }

        $sanitizedName = Naming::sanitize($name);
        if ($sanitizedName === null) {
            $this->clearRegistrationSession();
            return $this->error('Invalid name', 'bad_request', 400);
        }

        // SEC-E M-A3: a UNIQUE-violation on credential_id (e.g. concurrent
        // double-submit, or an authenticator that returns a deterministic
        // credentialId already registered) would otherwise propagate as
        // PDOException → PW's default error handler → HTML 500 (and PW
        // debug info if debug=true). Catch the SQLSTATE 23000 case
        // explicitly and return a clean JSON 409 conflict.
        try {
            // SEC-F #2: atomic check-and-insert closes the count/add race
            // window. Returns null if the cap was hit between the pre-flight
            // count above and the row-locked check inside the transaction.
            $id = $this->storage->addIfUnderCap($userId, [
                'credential_id' => $verified['credentialId'],
                'public_key'    => $verified['publicKey'],
                'sign_count'    => $verified['signCount'],
                'name'          => $sanitizedName,
                'aaguid'        => $verified['aaguid'],
                'transports'    => $verified['transports'],
            ], self::MAX_CREDENTIALS_PER_USER);
        } catch (\PDOException $e) {
            $this->clearRegistrationSession();
            // SQLSTATE 23000 = integrity constraint violation (covers MySQL
            // 1062 duplicate-entry and similar). Anything else is logged
            // and returns a generic verify_failed (don't leak DB internals).
            if ($e->getCode() === '23000') {
                return $this->error('Passkey already registered', 'duplicate_credential', 409);
            }
            $this->wire->wire('log')->save('passkey-auth', 'storage->add failed: ' . self::sanitizeForLog($e->getMessage()));
            return $this->error('Verification failed', 'verify_failed', 500);
        }
        if ($id === null) {
            // Race: cap was reached between pre-flight count and locked count.
            $this->clearRegistrationSession();
            return $this->error('Passkey limit reached', 'limit_reached', 409);
        }

        $this->clearRegistrationSession();

        // Return the freshly-stored row so JS can render it identically to the
        // server-rendered initial rows (same date formatting, etc.) without
        // needing a follow-up fetch.
        $row = $this->storage->findById($id);

        return $this->respond([
            'ok' => true,
            'passkey' => [
                'id'       => $id,
                'name'     => $sanitizedName,
                'created'  => $row['created']   ?? date('Y-m-d H:i:s'),
                'lastUsed' => $row['last_used'] ?? null,
            ],
        ]);
    }

    public function loginOptions(): string
    {
        // No auth required (pre-login). No CSRF (challenge replaces it).
        // SEC-D H2: enforce POST so cross-origin <img>-style GETs can't churn
        // challenges or eat rate-limit budget without preflight.
        if ($err = $this->requirePost()) return $err;

        // H2: per-session rate limit. Reject before issuing a new challenge so we
        // don't churn session writes or overwrite an in-flight challenge.
        //
        // H3: cookieless guests still create one new session file per request,
        // bypassing this per-session limiter entirely. We can't fix that here
        // without breaking the legitimate first-time-visitor flow. Production
        // deployments should pair this with a per-IP limit at the web server
        // (fail2ban on the access log, nginx limit_req, or equivalent WAF
        // rule scoped to /passkey-auth/login/options).
        if (!$this->recordLoginRateAndCheck()) {
            return $this->error('Too many login attempts', 'rate_limited', 429);
        }

        $result = $this->server->loginOptions([]);

        $this->session()->setFor(self::SESSION_NAMESPACE, self::LOGIN_CHALLENGE_KEY, $result['challenge']);

        return $this->respond(['options' => $result['options']]);
    }

    /**
     * H2 / SEC-E M-A5: record a login attempt against the per-session rate
     * limiter. Both /login/options and /login/finish increment the same
     * counter. Returns true if the attempt is within the limit (and
     * side-effects the session-stored timestamp list); false if rate-limited.
     */
    private function recordLoginRateAndCheck(): bool
    {
        $stamps = $this->session()->getFor(self::SESSION_NAMESPACE, self::LOGIN_RATE_KEY);
        if (!is_array($stamps)) $stamps = [];

        $check = RateLimit::check($stamps, time(), self::LOGIN_RATE_WINDOW, self::LOGIN_RATE_LIMIT_COMBINED);
        $this->session()->setFor(self::SESSION_NAMESPACE, self::LOGIN_RATE_KEY, $check['next']);
        return $check['allowed'];
    }

    public function loginFinish(): string
    {
        if ($err = $this->requirePost()) return $err;

        // SEC-E M-A2: refuse to perform a passkey login when a session is
        // already authenticated. Identity replacement without an explicit
        // logout is never the legitimate flow; rejecting here removes a
        // confused-deputy surface (e.g. CSRF-shaped post into login/finish
        // from a stale tab on an attacker-influenced page).
        if ($this->user()->isLoggedin()) {
            $this->logLoginFailure('already_logged_in', ['user_id' => (int) $this->user()->id]);
            return $this->error('Already authenticated', 'already_logged_in', 409);
        }

        // SEC-E M-A5: same per-session rate limit as login/options, so a
        // timing-oracle probe on finish is bounded equivalently. Increment
        // before reading the body so a flood of large bodies still trips
        // the limiter on the cheap path.
        if (!$this->recordLoginRateAndCheck()) {
            $this->logLoginFailure('rate_limited');
            return $this->error('Too many login attempts', 'rate_limited', 429);
        }

        $body = $this->readJsonBody();
        $cred = $body['credential'] ?? null;
        if (!is_array($cred)) {
            // M4: ensure any in-flight challenge is cleared on this early return.
            $this->clearLoginSession();
            $this->logLoginFailure('missing_credential');
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        $challenge = $this->session()->getFor(self::SESSION_NAMESPACE, self::LOGIN_CHALLENGE_KEY);
        if (!$challenge) {
            $this->clearLoginSession();
            $this->logLoginFailure('no_challenge');
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        $response = $cred['response'] ?? null;
        if (!is_array($response)) {
            $this->clearLoginSession();
            $this->logLoginFailure('invalid_response_shape');
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        $rawId             = $this->base64UrlDecode((string) ($cred['rawId'] ?? ''));
        $clientDataJson    = $this->base64UrlDecode((string) ($response['clientDataJSON'] ?? ''));
        $authenticatorData = $this->base64UrlDecode((string) ($response['authenticatorData'] ?? ''));
        $signature         = $this->base64UrlDecode((string) ($response['signature'] ?? ''));
        $userHandleRaw     = $response['userHandle'] ?? null;

        if ($rawId === null || $clientDataJson === null || $authenticatorData === null || $signature === null) {
            $this->clearLoginSession();
            $this->logLoginFailure('malformed_b64');
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        $row = $this->storage->findByCredentialId($rawId);
        if (!$row) {
            $this->clearLoginSession();
            $this->logLoginFailure('unknown_credential');
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        // C1: userHandle is REQUIRED. Reject uniformly (auth_failed) if missing,
        // wrong length, or doesn't match the credential row's user_id. Treat all
        // failure modes the same — don't leak which check failed.
        if (!is_string($userHandleRaw) || $userHandleRaw === '') {
            $this->clearLoginSession();
            $this->logLoginFailure('missing_user_handle', ['credential_id' => (int) $row['id']]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }
        $userHandle = $this->base64UrlDecode($userHandleRaw);
        if ($userHandle === null
            || strlen($userHandle) !== 4
            || unpack('N', $userHandle)[1] !== (int) $row['user_id']
        ) {
            $this->clearLoginSession();
            $this->logLoginFailure('user_handle_mismatch', ['credential_id' => (int) $row['id']]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        // Resolve the user and run cheap, fail-closed guards BEFORE crypto verification.
        // Spec ordering: existence + trash + role checks must precede any verification call.
        // Note: this ordering creates a timing difference between unknown-credential (fast),
        // ineligible-user (medium), and bad-signature (slow) branches. The credential rawId
        // is necessarily known to whoever is submitting it, so the leak is small and the
        // tradeoff (don't waste crypto on doomed attempts) is intentional. Do not reorder.
        $userId = (int) $row['user_id'];
        $user = $this->wire->wire('users')->get($userId);
        if (!$user || !$user->id) {
            $this->clearLoginSession();
            $this->logLoginFailure('orphaned_credential', ['credential_id' => (int) $row['id'], 'user_id' => $userId]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }
        // H4: reject login for trashed users. PW soft-delete moves the user under
        // the trash page; the Pages::trashed hook also cascades passkey rows, but
        // this defensive check covers any race between trash and an in-flight
        // login. Untestable without booting PW. `isTrash()` is the standard PW API.
        if ($user->isTrash()) {
            $this->clearLoginSession();
            $this->logLoginFailure('user_trashed', ['credential_id' => (int) $row['id'], 'user_id' => $userId]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }
        if (!$this->isAllowedByRole($user)) {
            $this->clearLoginSession();
            $this->logLoginFailure('role_denied', ['credential_id' => (int) $row['id'], 'user_id' => $userId]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        try {
            $verified = $this->server->verifyLogin(
                $clientDataJson,
                $authenticatorData,
                $signature,
                $userHandle,
                (string) $row['public_key'],
                $challenge,
                (int) $row['sign_count'],
            );
        } catch (\Throwable $e) {
            $this->wire->wire('log')->save('passkey-auth', 'verifyLogin failed: ' . self::sanitizeForLog($e->getMessage()));
            $this->clearLoginSession();
            $this->logLoginFailure('signature_verification_failed', ['credential_id' => (int) $row['id'], 'user_id' => $userId]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        // H3 / SEC-D M4: enforce counter-rollback at our layer.
        //   - Always-zero authenticators (e.g. iCloud Keychain) keep stored at 0
        //     across all assertions. Allowed only while stored is *also* 0.
        //   - Once a credential has reported a non-zero counter, any subsequent
        //     assertion reporting 0 OR a value <= stored is rejected as a clone
        //     indicator.
        $stored = (int) $row['sign_count'];
        $received = (int) $verified['signCount'];
        $rollback = false;
        if ($stored === 0 && $received === 0) {
            // Authenticator that doesn't track a counter; allow.
        } elseif ($received <= $stored) {
            $rollback = true;
        }
        if ($rollback) {
            $this->wire->wire('log')->save('passkey-auth', sprintf(
                'Counter rollback rejected for credential id %d: stored=%d, received=%d',
                (int) $row['id'],
                $stored,
                $received
            ));
            $this->clearLoginSession();
            $this->logLoginFailure('counter_rollback', [
                'credential_id' => (int) $row['id'],
                'user_id'       => $userId,
                'stored'        => $stored,
                'received'      => $received,
            ]);
            return $this->error('Authentication failed', 'auth_failed', 400);
        }

        $this->storage->touchLastUsed((int) $row['id'], $received);
        // SEC-D M3 / SEC-E H-A1: clear any stale registration / banner-dismissal
        // state from the prior session occupant BEFORE forceLogin so the new
        // identity starts with a clean PasskeyAuth namespace. We rely on PW's
        // Session::forceLogin to perform the session-id rotation (it does in
        // PW 3.0.x). An explicit session_regenerate_id here would either be a
        // redundant no-op or, on some session handlers, destroy the file PW
        // just wrote into — so we trust forceLogin and document the assumption.
        $this->clearAllSessionState();
        $this->wire->wire('session')->forceLogin($user);

        return $this->respond([
            'ok' => true,
            'redirect' => $this->wire->wire('config')->urls->admin,
        ]);
    }

    public function rename(): string
    {
        if ($err = $this->requirePost()) return $err;
        if ($err = $this->requireLoggedIn()) return $err;
        $body = $this->readJsonBody();
        if ($err = $this->requireCsrf($body)) return $err;

        $id   = (int) ($body['id'] ?? 0);
        if (!$id) return $this->error('Invalid input', 'invalid_input', 400);
        $name = Naming::sanitize((string) ($body['name'] ?? ''));
        if ($name === null) return $this->error('Invalid name', 'bad_request', 400);

        $row = $this->storage->findById($id);
        if (!$row) return $this->error('Not found', 'not_found', 404);
        $target = $this->targetUser((int) $row['user_id']);
        if (!$target) return $this->error('Forbidden', 'forbidden', 403);
        // H5: role allow-list re-check. Covers users whose role was revoked after
        // registration — they should not be able to manage stale credentials.
        if (!$this->isAllowedByRole($target)) return $this->error('Forbidden', 'forbidden', 403);
        // H6: if the client sent a userId body field, it must match the row owner.
        if (array_key_exists('userId', $body) && $body['userId'] !== null) {
            $supplied = $body['userId'];
            if (!is_int($supplied) && !(is_string($supplied) && ctype_digit($supplied))) {
                return $this->error('Forbidden', 'forbidden', 403);
            }
            if ((int) $supplied !== (int) $row['user_id']) {
                return $this->error('Forbidden', 'forbidden', 403);
            }
        }

        $this->storage->rename($id, $name);
        return $this->respond(['ok' => true]);
    }

    public function delete(): string
    {
        if ($err = $this->requirePost()) return $err;
        if ($err = $this->requireLoggedIn()) return $err;
        $body = $this->readJsonBody();
        if ($err = $this->requireCsrf($body)) return $err;

        $id = (int) ($body['id'] ?? 0);
        if (!$id) return $this->error('Invalid input', 'invalid_input', 400);

        $row = $this->storage->findById($id);
        if (!$row) return $this->error('Not found', 'not_found', 404);
        $target = $this->targetUser((int) $row['user_id']);
        if (!$target) return $this->error('Forbidden', 'forbidden', 403);
        // H5: role allow-list re-check. Covers users whose role was revoked after
        // registration — they should not be able to manage stale credentials.
        if (!$this->isAllowedByRole($target)) return $this->error('Forbidden', 'forbidden', 403);
        // H6: if the client sent a userId body field, it must match the row owner.
        if (array_key_exists('userId', $body) && $body['userId'] !== null) {
            $supplied = $body['userId'];
            if (!is_int($supplied) && !(is_string($supplied) && ctype_digit($supplied))) {
                return $this->error('Forbidden', 'forbidden', 403);
            }
            if ((int) $supplied !== (int) $row['user_id']) {
                return $this->error('Forbidden', 'forbidden', 403);
            }
        }

        $this->storage->delete($id);
        return $this->respond(['ok' => true]);
    }

    public function bannerDismiss(): string
    {
        if ($err = $this->requirePost()) return $err;
        if ($err = $this->requireLoggedIn()) return $err;
        $body = $this->readJsonBody();
        if ($err = $this->requireCsrf($body)) return $err;

        // H5: role allow-list re-check. The banner is only shown to allowed-role
        // users in the first place (shouldShowBanner), but defense in depth — a
        // user whose role was revoked shouldn't be able to set the dismissal flag.
        if (!$this->isAllowedByRole($this->user())) return $this->error('Forbidden', 'forbidden', 403);

        $this->session()->setFor(self::SESSION_NAMESPACE, self::BANNER_DISMISSED_KEY, 1);
        return $this->respond(['ok' => true]);
    }
}
