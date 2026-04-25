<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\RateLimit;

final class RateLimitTest extends TestCase
{
    public function testEmptyTimestampsAllowsAndAppendsNow(): void
    {
        $now = 1_000_000;
        $result = RateLimit::check([], $now, 60, 10);
        $this->assertTrue($result['allowed']);
        $this->assertSame([$now], $result['next']);
    }

    public function testNineTimestampsWithinWindowAllowsAndYieldsTen(): void
    {
        $now = 1_000_000;
        $stamps = [];
        for ($i = 1; $i <= 9; $i++) {
            $stamps[] = $now - $i;
        }
        $result = RateLimit::check($stamps, $now, 60, 10);
        $this->assertTrue($result['allowed']);
        $this->assertCount(10, $result['next']);
        $this->assertContains($now, $result['next']);
    }

    public function testTenTimestampsWithinWindowDeniesAndKeepsTen(): void
    {
        $now = 1_000_000;
        $stamps = [];
        for ($i = 1; $i <= 10; $i++) {
            $stamps[] = $now - $i;
        }
        $result = RateLimit::check($stamps, $now, 60, 10);
        $this->assertFalse($result['allowed']);
        $this->assertCount(10, $result['next']);
        $this->assertNotContains($now, $result['next']);
    }

    public function testOutOfWindowTimestampsAreFilteredBeforeLimitCheck(): void
    {
        $now = 1_000_000;
        // 5 in-window + 6 out-of-window. Filtered count = 5, so allowed.
        $stamps = [
            $now - 5, $now - 10, $now - 20, $now - 30, $now - 50, // in window (60s)
            $now - 61, $now - 100, $now - 1000, $now - 2000, $now - 3000, $now - 4000, // out
        ];
        $result = RateLimit::check($stamps, $now, 60, 10);
        $this->assertTrue($result['allowed']);
        $this->assertCount(6, $result['next']); // 5 in-window + new now
        foreach ($result['next'] as $t) {
            $this->assertGreaterThan($now - 60, $t);
        }
    }

    public function testNonIntValuesAreFilteredOutDefensively(): void
    {
        $now = 1_000_000;
        $stamps = [$now - 5, 'abc', null, $now - 10, 3.14, false, $now - 15];
        /** @phpstan-ignore-next-line — intentionally bad input */
        $result = RateLimit::check($stamps, $now, 60, 10);
        $this->assertTrue($result['allowed']);
        // Three valid in-window timestamps + the appended now = 4
        $this->assertCount(4, $result['next']);
    }

    public function testCustomWindowAndLimitDeniesWhenAtLimit(): void
    {
        $now = 1_000_000;
        $stamps = [$now - 1, $now - 3, $now - 5, $now - 7, $now - 9];
        $result = RateLimit::check($stamps, $now, 10, 5);
        $this->assertFalse($result['allowed']);
        $this->assertCount(5, $result['next']);
    }
}
