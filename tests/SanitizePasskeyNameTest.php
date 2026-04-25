<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Naming;

final class SanitizePasskeyNameTest extends TestCase
{
    public function testPlainNameWithMiddleDotIsUnchanged(): void
    {
        // U+00B7 MIDDLE DOT is not in our strip list and should pass through.
        $this->assertSame('Mac · 2026-04-25', Naming::sanitize('Mac · 2026-04-25'));
    }

    public function testEmptyStringReturnsNull(): void
    {
        $this->assertNull(Naming::sanitize(''));
    }

    public function testWhitespaceOnlyReturnsNull(): void
    {
        $this->assertNull(Naming::sanitize('   '));
    }

    public function testTrimsLeadingAndTrailingWhitespace(): void
    {
        $this->assertSame('Hello', Naming::sanitize('  Hello  '));
    }

    public function testStripsAsciiControlCharacters(): void
    {
        $this->assertSame('FooBar', Naming::sanitize("Foo\x07Bar"));
    }

    public function testStripsBidiOverride(): void
    {
        // U+202E RIGHT-TO-LEFT OVERRIDE
        $this->assertSame('Macevil', Naming::sanitize("Mac\u{202E}evil"));
    }

    public function testStripsZeroWidthSpace(): void
    {
        // U+200B ZERO WIDTH SPACE
        $this->assertSame('FooBar', Naming::sanitize("Foo\u{200B}Bar"));
    }

    public function testClampsLengthTo120Chars(): void
    {
        $input = str_repeat('a', 200);
        $out = Naming::sanitize($input);
        $this->assertNotNull($out);
        $this->assertSame(120, mb_strlen($out, 'UTF-8'));
    }

    public function testPreservesUnicodeMultibyteAndEmoji(): void
    {
        $this->assertSame('Café 🔑', Naming::sanitize('Café 🔑'));
    }

    public function testPurelyZeroWidthInputBecomesNull(): void
    {
        $this->assertNull(Naming::sanitize("\u{200B}\u{200B}"));
    }

    public function testClampsLengthTo120UsingMbSubstr(): void
    {
        $input = str_repeat('é', 200);
        $result = Naming::sanitize($input);
        $this->assertSame(120, mb_strlen($result, 'UTF-8'),
            'Clamp must count characters (mb_substr) not bytes (substr).');
    }

    public function testStripsZeroWidthBeforeClamping(): void
    {
        // 200 zero-width-padded "a"s. After strip: 200 visible "a"s. After clamp: 120.
        $input = str_repeat("a\u{200B}", 200);
        $result = Naming::sanitize($input);
        $this->assertSame(str_repeat('a', 120), $result);
    }
}
