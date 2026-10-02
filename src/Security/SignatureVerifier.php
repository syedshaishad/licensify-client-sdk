<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

use Licensify\Client\Exception\VerificationException;

/**
 * The only place in the SDK that decides whether a certificate is genuine.
 *
 * Every certificate goes through the same four gates in the same order — token
 * type, algorithm, known key, Ed25519 signature — so there is no code path in
 * which a certificate is "used" without being verified first (contract §5.2).
 */
final class SignatureVerifier
{
    /**
     * The contract writes `EdDSA`; the server emits the lowercase libsodium
     * name. Both are accepted, nothing else is.
     */
    public const ACCEPTED_ALGORITHMS = ['EdDSA', 'ed25519'];

    public const EXPECTED_TYPE = 'LIC';

    /**
     * @throws VerificationException
     */
    public static function verify(Certificate $certificate, Keyring $keyring): void
    {
        if ($certificate->type() !== self::EXPECTED_TYPE) {
            throw VerificationException::malformed(sprintf('unexpected token type "%s"', $certificate->type()));
        }

        if (! in_array($certificate->algorithm(), self::ACCEPTED_ALGORITHMS, true)) {
            throw VerificationException::malformed(
                sprintf('unsupported algorithm "%s"', $certificate->algorithm()),
            );
        }

        $kid = $certificate->kid();

        if ($kid === '') {
            throw VerificationException::malformed('the header does not name a signing key');
        }

        $publicKey = $keyring->get($kid);

        if ($publicKey === null) {
            throw VerificationException::unknownKey($kid);
        }

        // libsodium's verification is constant-time for the signature itself.
        if (! sodium_crypto_sign_verify_detached($certificate->signature, $certificate->signingInput, $publicKey)) {
            throw VerificationException::badSignature($kid);
        }
    }

    /**
     * Convenience predicate for call sites that treat verification failure as
     * a boolean rather than an exception.
     */
    public static function isValid(Certificate $certificate, Keyring $keyring): bool
    {
        try {
            self::verify($certificate, $keyring);

            return true;
        } catch (VerificationException) {
            return false;
        }
    }
}
