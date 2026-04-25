<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Server;

final class ServerTest extends TestCase
{
    public function testRegistrationOptionsHasExpectedFields(): void
    {
        $server = new Server('Test App', 'localhost');
        $result = $server->registrationOptions(42, 'alice', 'Alice');
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
