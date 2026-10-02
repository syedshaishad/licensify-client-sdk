<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Licensify\Client\Security\Base64Url;

/**
 * The single source of randomness for the SDK.
 *
 * Centralised so nonce and identifier generation can be stubbed in tests, and
 * so `random_bytes` is used everywhere — never `rand()`/`mt_rand()`, whose
 * output is predictable and therefore forgeable.
 */
final class Random
{
    public static function bytes(int $length): string
    {
        return random_bytes($length);
    }

    /**
     * Lower-case hexadecimal, used for installation identifiers.
     */
    public static function hex(int $length): string
    {
        return bin2hex(self::bytes($length));
    }

    /**
     * URL-safe base64 nonce for HMAC request signing (contract §3.2).
     */
    public static function nonce(int $length = 16): string
    {
        return Base64Url::encode(self::bytes($length));
    }
}
