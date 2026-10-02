<?php

declare(strict_types=1);

namespace Licensify\Client\Exception;

/**
 * A certificate could not be trusted: bad signature, unknown `kid`, wrong token
 * type, a stale `rev`, or a certificate minted for a different installation.
 *
 * Never recoverable by retrying — the correct response is to deny access and
 * force a fresh online validation.
 */
class VerificationException extends LicenseException
{
    public static function badSignature(string $kid): self
    {
        return new self(
            sprintf('The license certificate signature does not verify against key "%s".', $kid),
            'INVALID_SIGNATURE',
            ['kid' => $kid],
        );
    }

    public static function unknownKey(string $kid): self
    {
        return new self(
            sprintf('No trusted signing key is published for kid "%s".', $kid),
            'UNKNOWN_SIGNING_KEY',
            ['kid' => $kid],
        );
    }

    public static function malformed(string $reason): self
    {
        return new self(
            sprintf('The license certificate is malformed: %s.', $reason),
            'INVALID_CERTIFICATE',
            ['reason' => $reason],
        );
    }

    public static function staleRevocationCounter(int $certificateRev, int $knownRev): self
    {
        return new self(
            sprintf(
                'The license certificate (rev %d) is older than the last trusted certificate (rev %d); the license changed state.',
                $certificateRev,
                $knownRev,
            ),
            'CERTIFICATE_REVOKED',
            ['certificate_rev' => $certificateRev, 'known_rev' => $knownRev],
        );
    }

    public static function notYetValid(int $notBefore, int $now): self
    {
        return new self(
            sprintf('The license certificate is not valid before %d (now %d).', $notBefore, $now),
            'CERTIFICATE_NOT_YET_VALID',
            ['nbf' => $notBefore, 'now' => $now],
        );
    }

    public static function bindingMismatch(string $claim, string $expected, string $actual): self
    {
        return new self(
            sprintf('The license certificate is bound to a different %s than this installation.', $claim),
            'CERTIFICATE_MISMATCH',
            ['claim' => $claim, 'expected' => $expected, 'actual' => $actual],
        );
    }
}
