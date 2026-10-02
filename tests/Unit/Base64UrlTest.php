<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Security\Base64Url;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function test_encoding_is_url_safe_and_unpadded(): void
    {
        $encoded = Base64Url::encode("\xFB\xFF\xFE binary + / ");

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function test_round_trips_arbitrary_binary(): void
    {
        for ($i = 0; $i < 32; $i++) {
            $binary = random_bytes(random_int(1, 512));
            $this->assertSame($binary, Base64Url::decode(Base64Url::encode($binary)));
        }
    }

    public function test_decoding_accepts_padded_standard_base64(): void
    {
        // The server publishes keys as padded standard base64, so the tolerant
        // decoder must accept that form too.
        $this->assertSame('hello', Base64Url::decode(base64_encode('hello')));
    }

    public function test_undecodable_input_returns_an_empty_string(): void
    {
        $this->assertSame('', Base64Url::decode('!!!not base64!!!'));
    }

    #[DataProvider('fixedLengthCases')]
    public function test_fixed_length_decoding_enforces_the_exact_size(string $encoded, ?string $expected): void
    {
        $this->assertSame($expected, Base64Url::decodeFixed($encoded, 32));
    }

    /**
     * @return array<string, array{0: string, 1: string|null}>
     */
    public static function fixedLengthCases(): array
    {
        return [
            'valid 32 bytes' => [Base64Url::encode(str_repeat('a', 32)), str_repeat('a', 32)],
            'too short' => [Base64Url::encode(str_repeat('a', 31)), null],
            'too long' => [Base64Url::encode(str_repeat('a', 33)), null],
            'padded input is refused' => [base64_encode(str_repeat('a', 32)), null],
            'empty' => ['', null],
        ];
    }

    public function test_a_truncated_public_key_is_rejected_rather_than_padded(): void
    {
        // Padding a short key up to 32 bytes would let a truncated paste become a
        // trusted key, so the strict path must refuse it.
        $this->assertNull(Base64Url::decodeFixed(Base64Url::encode(str_repeat('a', 16)), 32));
    }
}
