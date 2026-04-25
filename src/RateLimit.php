<?php declare(strict_types=1);

namespace PasskeyAuth;

final class RateLimit
{
    /**
     * Given a list of unix timestamps and a now/window, return:
     * - allowed: whether a new event is permitted given the limit
     * - next:    filtered list, with `now` appended iff allowed
     *
     * Pure function; can be unit-tested without booting ProcessWire.
     *
     * @param array<mixed> $timestamps
     * @return array{allowed: bool, next: list<int>}
     */
    public static function check(array $timestamps, int $now, int $window, int $limit): array
    {
        $cutoff = $now - $window;
        $filtered = array_values(array_filter(
            $timestamps,
            static fn($t) => is_int($t) && $t > $cutoff,
        ));
        $allowed = count($filtered) < $limit;
        $next = $allowed ? [...$filtered, $now] : $filtered;
        return ['allowed' => $allowed, 'next' => $next];
    }
}
