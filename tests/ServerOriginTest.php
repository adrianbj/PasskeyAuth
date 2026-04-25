<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Server;

/**
 * Coverage for Server::assertOrigin(), the SEC-D H1 / SEC-E H-A2 anchored
 * origin gate. The method is private; we exercise it via reflection so the
 * tests don't depend on the lbuchs library's verification path (which would
 * require valid attestation/assertion bytes).
 *
 * Intent: every regression in the origin check should turn red here.
 */
final class ServerOriginTest extends TestCase
{
    private function invokeAssertOrigin(Server $server, array $clientData): void
    {
        // setAccessible() is a no-op since PHP 8.1 — private methods are
        // already invokable via reflection. PHP 8.5 emits a deprecation
        // warning if we call it, so we don't.
        $m = new \ReflectionMethod($server, 'assertOrigin');
        $m->invoke($server, json_encode($clientData, JSON_THROW_ON_ERROR));
    }

    private function expectOriginFailure(Server $server, array $clientData, string $messageContains = ''): void
    {
        try {
            $this->invokeAssertOrigin($server, $clientData);
            $this->fail('assertOrigin accepted bad origin: ' . json_encode($clientData));
        } catch (\RuntimeException $e) {
            if ($messageContains !== '') {
                $this->assertStringContainsString($messageContains, $e->getMessage());
            } else {
                $this->assertTrue(true);
            }
        }
    }

    public function testAcceptsExactHostMatchOverHttps(): void
    {
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://example.com']);
        $this->assertTrue(true); // no exception
    }

    public function testAcceptsValidSubdomain(): void
    {
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://www.example.com']);
        $this->assertTrue(true);
    }

    public function testAcceptsDeepSubdomain(): void
    {
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://a.b.example.com']);
        $this->assertTrue(true);
    }

    public function testRejectsEvilPrefixHost(): void
    {
        // The lbuchs library's unanchored regex would accept this; our gate
        // must NOT — `evilexample.com` is a different registrable domain.
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'https://evilexample.com'], 'Origin does not match');
    }

    public function testRejectsSiblingHost(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'https://example.com.attacker.test'], 'Origin does not match');
    }

    public function testNormalisesTrailingDotInHost(): void
    {
        // FQDN form — DNS-equivalent to example.com, must canonicalise.
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://example.com.']);
        $this->assertTrue(true);
    }

    public function testNormalisesTrailingDotOnSubdomain(): void
    {
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://www.example.com.']);
        $this->assertTrue(true);
    }

    public function testRejectsHttpOnNonLocalhost(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'http://example.com'], 'scheme not permitted');
    }

    public function testAcceptsHttpOnLocalhost(): void
    {
        $server = new Server('Test', 'localhost');
        $this->invokeAssertOrigin($server, ['origin' => 'http://localhost']);
        $this->assertTrue(true);
    }

    public function testAcceptsHttpOnLoopbackIp(): void
    {
        $server = new Server('Test', '127.0.0.1');
        $this->invokeAssertOrigin($server, ['origin' => 'http://127.0.0.1']);
        $this->assertTrue(true);
    }

    public function testRejectsMissingOrigin(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['challenge' => 'abc'], 'Missing origin');
    }

    public function testRejectsNonStringOrigin(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 42], 'Missing origin');
    }

    public function testRejectsMalformedOrigin(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'not a url'], 'Malformed origin');
    }

    public function testRejectsOriginContainingUserinfo(): void
    {
        // parse_url silently drops user:pass@; rejecting up-front avoids any
        // chance of an authenticator-supplied origin sneaking past the host
        // check after canonicalisation.
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'https://attacker@example.com'], 'userinfo');
    }

    public function testRejectsOriginContainingBracketedHost(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'https://[::1]'], 'bracketed host');
    }

    public function testRejectsInvalidJson(): void
    {
        $server = new Server('Test', 'example.com');
        $m = new \ReflectionMethod($server, 'assertOrigin');
        $this->expectException(\RuntimeException::class);
        $m->invoke($server, '{not json');
    }

    public function testHostMatchIsCaseInsensitive(): void
    {
        $server = new Server('Test', 'Example.COM');
        $this->invokeAssertOrigin($server, ['origin' => 'https://EXAMPLE.com']);
        $this->assertTrue(true);
    }

    public function testRejectsEmptyHost(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'https:///path']);
    }

    public function testRejectsFileScheme(): void
    {
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure($server, ['origin' => 'file://example.com'], 'scheme not permitted');
    }

    public function testRejectsExplicitCrossOriginTrue(): void
    {
        // SEC-F #5: a ceremony issued from a cross-origin iframe is rejected
        // regardless of how the origin field looks.
        $server = new Server('Test', 'example.com');
        $this->expectOriginFailure(
            $server,
            ['origin' => 'https://example.com', 'crossOrigin' => true],
            'Cross-origin'
        );
    }

    public function testAcceptsExplicitCrossOriginFalse(): void
    {
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://example.com', 'crossOrigin' => false]);
        $this->assertTrue(true);
    }

    public function testAcceptsCrossOriginAbsent(): void
    {
        // The field is optional per spec; absence is treated as same-origin.
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://example.com']);
        $this->assertTrue(true);
    }

    public function testIgnoresNonBoolCrossOrigin(): void
    {
        // Strict `=== true` comparison: non-true values pass through.
        $server = new Server('Test', 'example.com');
        $this->invokeAssertOrigin($server, ['origin' => 'https://example.com', 'crossOrigin' => 'true']);
        $this->assertTrue(true);
    }
}
