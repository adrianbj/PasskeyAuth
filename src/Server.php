<?php declare(strict_types=1);

namespace PasskeyAuth;

use lbuchs\WebAuthn\WebAuthn;

final class Server
{
    private WebAuthn $webauthn;
    private string $rpId;

    public function __construct(
        string $rpName,
        string $rpId,
        array $allowedFormats = ['none', 'packed', 'apple']
    ) {
        // 4th arg = $useBase64UrlEncoding. The WebAuthn constructor sets
        // ByteBuffer::$useBase64UrlEncoding from this; without it, the lib defaults
        // to false and serializes binary fields as =?BINARY?B?...?= which atob() rejects.
        $this->webauthn = new WebAuthn($rpName, $rpId, $allowedFormats, true);
        $this->rpId = strtolower($rpId);
    }

    /**
     * SEC-D H1: anchored origin validation. The lbuchs library uses an
     * unanchored regex (`/preg_quote($rpId)$/i`) which accepts any origin
     * whose host *ends in* the rpId — e.g. an rpId of `example.com` matches
     * `evilexample.com`. We extract the origin from clientDataJSON ourselves
     * and require either an exact host match or a proper subdomain (host
     * ends with `.` + rpId). Localhost is allowed over http for development.
     *
     * @throws \RuntimeException if origin is missing/malformed/unauthorized
     */
    private function assertOrigin(string $clientDataJson): void
    {
        try {
            $data = json_decode($clientDataJson, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \RuntimeException('Invalid clientDataJSON');
        }
        if (!is_array($data) || !isset($data['origin']) || !is_string($data['origin'])) {
            throw new \RuntimeException('Missing origin');
        }
        $origin = $data['origin'];

        // SEC-F #5: reject ceremonies started in a cross-origin iframe.
        // WebAuthn Level 3 spec hardening: clientDataJSON.crossOrigin is true
        // when the credential request was issued from a frame whose top-level
        // origin differs from the frame's own origin. Browser Permissions
        // Policy (`publickey-credentials-get`/`-create`) defaults to `self`
        // and already prevents this in compliant browsers, but a non-conformant
        // user agent or a future policy slip should not slip past us. The
        // field is optional in the spec; only reject when it's explicitly true.
        if (isset($data['crossOrigin']) && $data['crossOrigin'] === true) {
            throw new \RuntimeException('Cross-origin ceremony rejected');
        }

        // SEC-E H-A2: explicitly reject origin shapes parse_url silently
        // accepts but the WebAuthn spec forbids:
        //   - userinfo (`user:pass@host`): browsers strip this from
        //     clientDataJSON.origin, but a non-conformant client could include
        //     it; parse_url drops the userinfo, hiding a potential mismatch.
        //   - bracketed IPv6 literals (`[::1]`): rpId is constrained to
        //     hostname charset and can't contain `[`, so any bracketed origin
        //     can never legitimately match. Rejecting up-front avoids relying
        //     on that coincidence.
        //   - explicit ports: WebAuthn origin equality is on host only, but
        //     parse_url leaves `host` clean while the unparsed origin string
        //     could carry a port — the host check below is correct, this just
        //     documents the choice.
        if (strpos($origin, '@') !== false) {
            throw new \RuntimeException('Origin contains userinfo');
        }
        if (strpos($origin, '[') !== false) {
            throw new \RuntimeException('Origin contains bracketed host');
        }

        $parts = parse_url($origin);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new \RuntimeException('Malformed origin');
        }
        $scheme = strtolower($parts['scheme']);
        $host   = strtolower($parts['host']);

        // SEC-E H-A2: strip a single trailing dot (FQDN form) to canonicalise.
        // `https://example.com./` is functionally equivalent to `https://example.com/`
        // and DNS-resolves identically. Rather than reject, normalise then compare.
        if ($host !== '' && $host[strlen($host) - 1] === '.') {
            $host = substr($host, 0, -1);
        }

        if ($scheme !== 'https' && !($scheme === 'http' && ($host === 'localhost' || $host === '127.0.0.1'))) {
            throw new \RuntimeException('Origin scheme not permitted');
        }
        if ($host === $this->rpId) return;
        $suffix = '.' . $this->rpId;
        $sl = strlen($suffix);
        if (strlen($host) > $sl && substr($host, -$sl) === $suffix) return;
        throw new \RuntimeException('Origin does not match rpId');
    }

    /**
     * Generate registration options for a user.
     *
     * @param int    $userId            ProcessWire user ID (binary-encoded as user.id for WebAuthn)
     * @param string $userName          Username (login handle)
     * @param string $userDisplayName   Friendly display name
     * @param string[] $excludeCredentialIds Raw credential ID bytes the user already has
     * @return array Decoded option blob (cast from object) ready for json_encode
     * @note user.id is encoded as 4-byte big-endian via pack('N'); assumes PW user ID fits in unsigned 32-bit.
     */
    public function registrationOptions(
        int $userId,
        string $userName,
        string $userDisplayName,
        array $excludeCredentialIds = [],
        bool $requireResidentKey = true,
    ): array {
        // SEC-D M6: pack('N', ...) silently truncates to 32 unsigned bits. PW user
        // IDs fit today (INT UNSIGNED), but a future migration with values > 2^32
        // would silently collide on the userHandle. Refuse rather than corrupt.
        if ($userId <= 0 || $userId > 0xFFFFFFFF) {
            throw new \RuntimeException('userId out of range for 32-bit userHandle encoding');
        }
        $userIdBin = pack('N', $userId);  // 4-byte big-endian for compactness; alternative: hex
        // userVerification is hardcoded to 'required': this is a passkey module,
        // and the W3C / FIDO Alliance guidance for passkey deployments is UV=required.
        // 'preferred' would silently accept present-but-unverified assertions and
        // 'discouraged' contradicts the passkey security model entirely.
        $args = $this->webauthn->getCreateArgs(
            $userIdBin,
            $userName,
            $userDisplayName,
            30,                                  // timeout seconds — caller-overridable later
            $requireResidentKey,
            'required',
            null,                                // crossPlatformAttachment: null = any (platform + roaming). true = roaming only. false = platform only.
            $excludeCredentialIds
        );
        // Note: getCreateArgs returns stdClass; we keep as object for JSON, but extract challenge for storage
        return [
            'options'   => $args,
            'challenge' => $this->webauthn->getChallenge()->getBinaryString(),
        ];
    }

    public function loginOptions(
        array $allowedCredentialIds = [],
    ): array {
        // userVerification hardcoded to 'required' — see registrationOptions().
        $args = $this->webauthn->getGetArgs(
            $allowedCredentialIds,
            30,
            true,   // typeUsb
            true,   // typeNfc
            true,   // typeBle
            true,   // typeHybrid
            true,   // typeInt
            'required'
        );
        return [
            'options'   => $args,
            'challenge' => $this->webauthn->getChallenge()->getBinaryString(),
        ];
    }

    /**
     * Verify a registration attestation. Returns the data needed for storage.
     *
     * @param string $clientDataJson    Raw clientDataJSON bytes from the browser.
     * @param string $attestationObject Raw attestationObject bytes.
     * @param string $challenge         Original challenge bytes (server-side).
     * @return array{credentialId: string, publicKey: string, signCount: int}
     * @throws \lbuchs\WebAuthn\WebAuthnException on attestation verification failure
     */
    public function verifyRegistration(
        string $clientDataJson,
        string $attestationObject,
        string $challenge,
    ): array {
        // SEC-D H1: anchored origin check before delegating to lbuchs.
        $this->assertOrigin($clientDataJson);
        // Note: lbuchs lib has no setChallenge(); challenge is passed directly to processCreate.
        // UV is required (see registrationOptions); the bool here is the lib's
        // requireUserVerification flag — true means reject assertions without UV.
        $data = $this->webauthn->processCreate(
            $clientDataJson,
            $attestationObject,
            $challenge,
            true,                                // requireUserVerification
            true,                                // requireUserPresent
            true,                                // failIfRootMismatch
        );

        return [
            'credentialId' => $data->credentialId,
            'publicKey'    => $data->credentialPublicKey,
            'signCount'    => (int) ($data->signatureCounter ?? 0),
        ];
    }

    /**
     * Verify a login assertion against a stored credential.
     *
     * @param string      $clientDataJson    Raw clientDataJSON bytes.
     * @param string      $authenticatorData Raw authenticatorData bytes.
     * @param string      $signature         Raw signature bytes.
     * @param string|null $userHandle        Reserved for caller's resident-key lookup; not consumed by the verification call.
     * @param string      $publicKey         Stored credential public key.
     * @param string      $challenge         Original challenge bytes.
     * @param int         $storedSignCount   Last seen signature counter for the credential.
     * @return array{signCount: int}
     * @throws \lbuchs\WebAuthn\WebAuthnException on verification failure
     */
    public function verifyLogin(
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
        ?string $userHandle,
        string $publicKey,
        string $challenge,
        int $storedSignCount,
    ): array {
        // SEC-D H1: anchored origin check before delegating to lbuchs.
        $this->assertOrigin($clientDataJson);
        // Note: lbuchs lib has no setChallenge(); challenge is passed directly to processGet.
        // C1 (post-review): processGet returns bool true on success — NOT an object.
        // The authenticator-reported counter is exposed via getSignatureCounter() which
        // returns ?int (null when the authenticator reports 0, e.g. iCloud Keychain).
        // Falling back to $storedSignCount in the null case preserves existing rollback
        // semantics without ever overwriting our stored counter with a stale value.
        // UV is required — bool true here is the lib's requireUserVerification flag.
        $this->webauthn->processGet(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $publicKey,
            $challenge,
            $storedSignCount,
            true,
        );

        return [
            'signCount' => (int) ($this->webauthn->getSignatureCounter() ?? $storedSignCount),
        ];
    }
}
