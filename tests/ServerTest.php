<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Server;

final class ServerTest extends TestCase
{
    public function testRegistrationOptionsHasExpectedFields(): void
    {
        $server = new Server('Test App', 'localhost');
        $result = $server->registrationOptions(random_bytes(16), 'alice', 'Alice');
        $this->assertArrayHasKey('options', $result);
        $this->assertArrayHasKey('challenge', $result);
        $this->assertNotEmpty($result['challenge']);
        $opts = $result['options'];
        $this->assertObjectHasProperty('publicKey', $opts);
        $this->assertObjectHasProperty('challenge', $opts->publicKey);
        $this->assertObjectHasProperty('rp', $opts->publicKey);
        $this->assertSame('Test App', $opts->publicKey->rp->name);
        $this->assertSame('localhost', $opts->publicKey->rp->id);
    }

    public function testRegistrationOptionsRejectsEmptyHandle(): void
    {
        $server = new Server('Test App', 'localhost');
        $this->expectException(\RuntimeException::class);
        $server->registrationOptions('', 'alice', 'Alice');
    }

    public function testRegistrationOptionsRejectsOversizeHandle(): void
    {
        $server = new Server('Test App', 'localhost');
        $this->expectException(\RuntimeException::class);
        $server->registrationOptions(str_repeat("\x00", 65), 'alice', 'Alice');
    }

    public function testLoginOptionsHasExpectedFields(): void
    {
        $server = new Server('Test App', 'localhost');
        $result = $server->loginOptions();
        $this->assertArrayHasKey('options', $result);
        $this->assertArrayHasKey('challenge', $result);
        $opts = $result['options'];
        $this->assertObjectHasProperty('publicKey', $opts);
        $this->assertObjectHasProperty('challenge', $opts->publicKey);
    }
}
