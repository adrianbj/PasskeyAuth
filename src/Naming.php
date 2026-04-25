<?php declare(strict_types=1);

namespace PasskeyAuth;

/**
 * Centralised passkey-name sanitisation.
 *
 * Strips ASCII control characters and Unicode bidi/zero-width characters that
 * could be used to spoof or hide content in management UIs, then clamps to 120
 * UTF-8 characters. Returns null for empty / whitespace-only / fully-stripped
 * input so callers can reject with a single uniform error.
 */
final class Naming
{
    public static function sanitize(string $name): ?string
    {
        $trimmed = trim($name);
        if ($trimmed === '') return null;

        // Strip ASCII control chars (\x00-\x1F and \x7F).
        $stripped = preg_replace('/[\x00-\x1F\x7F]/u', '', $trimmed);
        if ($stripped === null) return null;

        // Strip Unicode bidi controls and zero-width characters.
        // U+200B..U+200F, U+202A..U+202E, U+2066..U+2069
        $stripped = preg_replace(
            '/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u',
            '',
            $stripped
        );
        if ($stripped === null) return null;

        // Clamp to 120 UTF-8 characters.
        $clamped = mb_substr($stripped, 0, 120, 'UTF-8');

        // Final trim in case stripping/clamping left whitespace at edges.
        $clamped = trim($clamped);

        return $clamped === '' ? null : $clamped;
    }
}
