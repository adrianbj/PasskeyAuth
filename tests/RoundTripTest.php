<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PasskeyAuth\Server;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end crypto round-trip through Server: build a synthetic ES256 WebAuthn
 * ceremony (a stand-in authenticator), register it via verifyRegistration, then
 * sign and verify a login assertion via verifyLogin. The rest of the suite only
 * exercises option-building and origin parsing; this is the one test that runs
 * the real processCreate/processGet verification path, so a future dependency
 * change that breaks signature verification fails here.
 */
final class RoundTripTest extends TestCase
{
    private const RP_ID  = 'griefcoach.test';
    private const ORIGIN = 'https://griefcoach.test';

    public function testRegisterThenLoginVerifies(): void
    {
        $server = new Server('Test', self::RP_ID);

        // --- synthetic authenticator: EC P-256 keypair ---
        $pkey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertNotFalse($pkey, 'EC keygen failed');
        $det = openssl_pkey_get_details($pkey);
        $x = str_pad($det['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($det['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        // COSE_Key: {1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2:x, -3:y}
        $cose = "\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

        $credId   = random_bytes(16);
        $rpIdHash = hash('sha256', self::RP_ID, true);

        // authenticatorData (registration): rpIdHash | flags UP|UV|AT (0x45) | signCount(0) | attestedCredData
        $authDataReg = $rpIdHash . "\x45" . pack('N', 0)
            . str_repeat("\x00", 16) . pack('n', strlen($credId)) . $credId . $cose;

        // attestationObject: {"fmt":"none","attStmt":{},"authData": bstr(authDataReg)}
        $attObj = "\xA3\x63fmt\x64none\x67attStmt\xA0\x68authData\x58" . chr(strlen($authDataReg)) . $authDataReg;

        $challenge = random_bytes(32);
        $cdCreate  = json_encode([
            'type' => 'webauthn.create', 'challenge' => self::b64u($challenge),
            'origin' => self::ORIGIN, 'crossOrigin' => false,
        ]);

        $reg = $server->verifyRegistration($cdCreate, $attObj, $challenge);
        $this->assertArrayHasKey('publicKey', $reg);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $reg['publicKey'], 'expected a PEM public key');

        // --- login assertion signed by the same key ---
        $challenge2  = random_bytes(32);
        $cdGet       = json_encode([
            'type' => 'webauthn.get', 'challenge' => self::b64u($challenge2),
            'origin' => self::ORIGIN, 'crossOrigin' => false,
        ]);
        $authDataGet = $rpIdHash . "\x05" . pack('N', 1);        // UP|UV, signCount=1
        openssl_sign($authDataGet . hash('sha256', $cdGet, true), $sig, $pkey, OPENSSL_ALGO_SHA256);

        $login = $server->verifyLogin($cdGet, $authDataGet, $sig, null, $reg['publicKey'], $challenge2, 0);
        $this->assertSame(1, $login['signCount'], 'login assertion should verify and report the new counter');
    }

    private static function b64u(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }
}
