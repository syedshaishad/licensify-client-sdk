<?php

declare(strict_types=1);

namespace Licensify\Client\Exception;

/**
 * The licensing server could not be reached, timed out, or answered with a body
 * that is not a contract-shaped response.
 *
 * This is deliberately distinct from {@see VerificationException}: a network
 * failure means "ask again later, the cached certificate still decides", while
 * a verification failure means "deny now".
 */
class NetworkException extends LicenseException
{
    public static function unreachable(string $url, string $reason, int $httpCode = 0): self
    {
        return new self(
            sprintf('Could not reach the licensing server at %s (%s, HTTP %d).', $url, $reason, $httpCode),
            'SERVER_UNREACHABLE',
            ['url' => $url, 'reason' => $reason, 'http_code' => $httpCode],
        );
    }

    public static function malformedResponse(string $url, string $reason): self
    {
        return new self(
            sprintf('The licensing server at %s returned an unusable response (%s).', $url, $reason),
            'MALFORMED_RESPONSE',
            ['url' => $url, 'reason' => $reason],
        );
    }
}
