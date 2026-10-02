<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

/**
 * URL-safe base64 (RFC 4648 §5) without padding.
 *
 * Used for both directions of the certificate token and for nonce/signature
 * headers, so encoding is centralised and byte-compatible with the server.
 */
final class Base64Url
{
    public static function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * Returns an empty string for input that is not decodable, so callers must
     * treat an empty result as a parse failure rather than as empty data.
     */
    public static function decode(string $value): string
    {
        $padded = strtr($value, '-_', '+/');
        $remainder = strlen($padded) % 4;

        if ($remainder !== 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($padded, true);

        return $decoded === false ? '' : $decoded;
    }

    /**
     * Strict decode for security-relevant material: anything that does not
     * decode to exactly `$expectedLength` bytes is rejected outright.
     */
    public static function decodeFixed(string $value, int $expectedLength): ?string
    {
        if ($value === '' || str_contains($value, '=')) {
            return null;
        }

        $decoded = self::decode($value);

        return strlen($decoded) === $expectedLength ? $decoded : null;
    }
}
