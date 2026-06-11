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
 * A logged-in user probing rename/delete with arbitrary ids must not be able
 * to distinguish "row does not exist" from "row exists but belongs to someone
 * else" — the two responses must be byte-identical with the same status code.
 */
final class EndpointsOracleTest extends TestCase
{
    private const CSRF = 'test-token';

    private Storage $storage;
    private Endpoints $endpoints;
    private int $foreignRowId;

    protected function setUp(): void
    {
        $pdo = pa_test_pdo();
        $this->storage = new Storage($pdo, 'passkey_auth');

        // A passkey owned by user 99; the requester is user 7 (not superuser).
        $this->foreignRowId = $this->storage->add(99, [
            'user_handle'   => random_bytes(16),
            'credential_id' => "\x01\x02\x03",
            'public_key'    => "\xAA\xBB\xCC",
            'sign_count'    => 0,
            'name'          => 'Victim passkey',
        ]);

        $requester = new User(id: 7, superuser: false, roles: [(object) ['id' => 1001]], loggedin: true);

        $wire = new Wire();
        $wire->setApiVar('user', $requester);
        $wire->setApiVar('session', new Session(self::CSRF));
        $wire->setApiVar('users', new FakeUsers([7 => $requester]));
        $wire->setApiVar('log', new FakeLog());

        $this->endpoints = new Endpoints(
            $this->storage,
            new Server('Test', 'example.com'),
            $wire,
            [1001],  // allowed role ids (role checks aren't reached on these paths)
            true,
        );

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = self::CSRF;

        stream_wrapper_unregister('php');
        stream_wrapper_register('php', MockPhpStream::class);
    }

    protected function tearDown(): void
    {
        stream_wrapper_restore('php');
        unset($_SERVER['HTTP_X_CSRF_TOKEN']);
    }

    /** @return array{status: int, body: string} */
    private function call(string $method, array $body): array
    {
        MockPhpStream::$input = json_encode($body);
        http_response_code(200);
        $result = $this->endpoints->$method();
        return ['status' => http_response_code(), 'body' => $result];
    }

    public function testDeleteResponseIsIdenticalForForeignAndMissingRows(): void
    {
        $foreign = $this->call('delete', ['id' => $this->foreignRowId]);
        $missing = $this->call('delete', ['id' => 424242]);

        $this->assertSame($missing['status'], $foreign['status']);
        $this->assertSame($missing['body'], $foreign['body']);
    }

    public function testRenameResponseIsIdenticalForForeignAndMissingRows(): void
    {
        $foreign = $this->call('rename', ['id' => $this->foreignRowId, 'name' => 'probe']);
        $missing = $this->call('rename', ['id' => 424242, 'name' => 'probe']);

        $this->assertSame($missing['status'], $foreign['status']);
        $this->assertSame($missing['body'], $foreign['body']);
    }

    public function testForeignRowIsNotActuallyDeletedOrRenamed(): void
    {
        $this->call('delete', ['id' => $this->foreignRowId]);
        $row = $this->storage->findById($this->foreignRowId);
        $this->assertNotNull($row, 'foreign row must survive the delete attempt');

        $this->call('rename', ['id' => $this->foreignRowId, 'name' => 'probe']);
        $row = $this->storage->findById($this->foreignRowId);
        $this->assertSame('Victim passkey', $row['name']);
    }

    public function testOwnerCanStillDeleteOwnRow(): void
    {
        $ownId = $this->storage->add(7, [
            'user_handle'   => random_bytes(16),
            'credential_id' => "\x09\x09\x09",
            'public_key'    => "\xDD\xEE\xFF",
            'sign_count'    => 0,
            'name'          => 'My passkey',
        ]);

        $result = $this->call('delete', ['id' => $ownId]);

        $this->assertSame(200, $result['status']);
        $this->assertNull($this->storage->findById($ownId));
    }
}
