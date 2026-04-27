<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Storage;

final class StorageTest extends TestCase
{
    private \PDO $pdo;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->pdo = pa_test_pdo();
        $this->storage = new Storage($this->pdo, 'passkey_auth');
    }

    public function testAddInsertsRowAndReturnsId(): void
    {
        $id = $this->storage->add(42, [
            'credential_id' => "\x01\x02\x03",
            'public_key'    => "\xAA\xBB\xCC",
            'name'          => 'My Mac',
            'sign_count'    => 0,
        ]);
        $this->assertGreaterThan(0, $id);
    }

    public function testFindByCredentialIdReturnsRow(): void
    {
        $this->storage->add(42, [
            'credential_id' => "\x01\x02\x03",
            'public_key'    => "\xAA\xBB\xCC",
            'name'          => 'My Mac',
            'sign_count'    => 0,
        ]);
        $row = $this->storage->findByCredentialId("\x01\x02\x03");
        $this->assertNotNull($row);
        $this->assertSame(42, (int) $row['user_id']);
        $this->assertSame("\xAA\xBB\xCC", $row['public_key']);
    }

    public function testFindByCredentialIdReturnsNullForUnknown(): void
    {
        $this->assertNull($this->storage->findByCredentialId("\x99\x99"));
    }

    public function testListForUserReturnsAllRows(): void
    {
        $this->storage->add(7, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'a']);
        $this->storage->add(7, ['credential_id' => "\x02", 'public_key' => "\xBB", 'name' => 'b']);
        $this->storage->add(8, ['credential_id' => "\x03", 'public_key' => "\xCC", 'name' => 'c']);
        $rows = $this->storage->listForUser(7);
        $this->assertCount(2, $rows);
    }

    public function testCountForUser(): void
    {
        $this->assertSame(0, $this->storage->countForUser(99));
        $this->storage->add(99, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'a']);
        $this->assertSame(1, $this->storage->countForUser(99));
    }

    public function testRenameUpdatesName(): void
    {
        $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'old']);
        $this->assertTrue($this->storage->rename($id, 'new'));
        $row = $this->storage->findById($id);
        $this->assertSame('new', $row['name']);
    }

    public function testDeleteRemovesRow(): void
    {
        $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'x']);
        $this->assertTrue($this->storage->delete($id));
        $this->assertNull($this->storage->findById($id));
    }

    public function testDeleteAllForUserRemovesOnlyThatUsersRows(): void
    {
        $this->storage->add(7, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'a']);
        $this->storage->add(7, ['credential_id' => "\x02", 'public_key' => "\xBB", 'name' => 'b']);
        $this->storage->add(8, ['credential_id' => "\x03", 'public_key' => "\xCC", 'name' => 'c']);
        $deleted = $this->storage->deleteAllForUser(7);
        $this->assertSame(2, $deleted);
        $this->assertSame(0, $this->storage->countForUser(7));
        $this->assertSame(1, $this->storage->countForUser(8));
    }

    public function testDeleteAllForUserReturnsZeroForUnknownUser(): void
    {
        $this->assertSame(0, $this->storage->deleteAllForUser(404));
    }

    public function testTouchLastUsedUpdatesCounterAndTimestamp(): void
    {
        $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'x']);
        $this->storage->touchLastUsed($id, 5);
        $row = $this->storage->findById($id);
        $this->assertSame(5, (int) $row['sign_count']);
        $this->assertNotNull($row['last_used']);
    }
}
