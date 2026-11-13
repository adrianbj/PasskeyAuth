<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Endpoints;
use PasskeyAuth\Server;
use PasskeyAuth\Storage;
use ProcessWire\Session;
use ProcessWire\User;
use ProcessWire\Wire;

/**
 * Ceremony state (challenge, user handle) is raw random bytes. Session
 * backends that persist to a text column (SessionHandlerDB) can reject or
 * truncate invalid UTF-8, so what lands in the session must be text-safe.
 */
final class SessionEncodingTest extends TestCase
{
    private const CSRF = 'test-token';

    protected function setUp(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = self::CSRF;
        stream_wrapper_unregister('php');
        stream_wrapper_register('php', MockPhpStream::class);
        MockPhpStream::$input = '{}';
    }

    protected function tearDown(): void
    {
        stream_wrapper_restore('php');
        unset($_SERVER['HTTP_X_CSRF_TOKEN']);
    }

    /** @return array{0: Endpoints, 1: Session} */
    private function build(User $user): array
    {
        $session = new Session(self::CSRF);
        $wire = new Wire();
        $wire->setApiVar('user', $user);
        $wire->setApiVar('session', $session);
        $wire->setApiVar('users', new FakeUsers([$user->id => $user]));
        $wire->setApiVar('log', new FakeLog());
        $endpoints = new Endpoints(
            new Storage(pa_test_pdo(), 'passkey_auth'),
            new Server('Test', 'example.com'),
            $wire,
            [1001],
            true,
        );
        return [$endpoints, $session];
    }

    private function assertTextSafeBytes(mixed $stored, int $expectedLength): void
    {
        $this->assertIsString($stored);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/]+=*$/', $stored);
        $decoded = base64_decode($stored, true);
        $this->assertNotFalse($decoded);
        $this->assertSame($expectedLength, strlen($decoded));
    }

    public function testLoginChallengeIsStoredTextSafe(): void
    {
        $guest = new User(id: 40, superuser: false, roles: [], loggedin: false);
        [$endpoints, $session] = $this->build($guest);

        $body = json_decode($endpoints->loginOptions(), true);
        $this->assertArrayHasKey('options', $body);
        $this->assertTextSafeBytes($session->getFor('PasskeyAuth', 'login_challenge'), 32);
    }

    public function testRegistrationChallengeAndHandleAreStoredTextSafe(): void
    {
        $user = new User(id: 7, superuser: false, roles: [(object) ['id' => 1001]], loggedin: true);
        [$endpoints, $session] = $this->build($user);

        $body = json_decode($endpoints->registerOptions(), true);
        $this->assertArrayHasKey('options', $body);
        $this->assertTextSafeBytes($session->getFor('PasskeyAuth', 'register_challenge'), 32);
        $this->assertTextSafeBytes($session->getFor('PasskeyAuth', 'register_user_handle'), 16);
    }

    public function testRawPreUpgradeChallengeFailsClosed(): void
    {
        // A challenge written raw by pre-upgrade code mid-ceremony must be
        // treated as absent, never passed to verification as-is.
        $guest = new User(id: 40, superuser: false, roles: [], loggedin: false);
        [$endpoints, $session] = $this->build($guest);
        $session->setFor('PasskeyAuth', 'login_challenge', "\xff\xfe\x00raw-bytes");
        MockPhpStream::$input = json_encode(['credential' => ['rawId' => 'AQID', 'response' => []]]);

        $body = json_decode($endpoints->loginFinish(), true);
        $this->assertSame('auth_failed', $body['code']);
        $this->assertSame(400, http_response_code());
    }
}
