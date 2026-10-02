<?php

declare(strict_types=1);

namespace Licensify\Client\Exception;

/**
 * The grace window has closed: there is no verifiable certificate left, or the
 * cached one is past `exp`, and the server could not be reached to renew it.
 *
 * This is the fail-closed terminal state (contract §5.3, §15). Product software
 * must block; it must not fall back to "assume valid".
 */
class GraceExpiredException extends LicenseException
{
    public static function noCertificate(): self
    {
        return new self(
            'No verifiable license certificate is available and the licensing server could not be reached.',
            'NO_VALID_CERTIFICATE',
        );
    }

    public static function expired(int $expiresAt, ?int $now = null): self
    {
        $now ??= time();

        return new self(
            sprintf(
                'The license grace window closed at %s and the licensing server could not be reached.',
                gmdate('c', $expiresAt),
            ),
            'LICENSE_GRACE_EXPIRED',
            ['expired_at' => gmdate('c', $expiresAt), 'now' => gmdate('c', $now)],
        );
    }
}
