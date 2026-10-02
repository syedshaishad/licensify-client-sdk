<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

use Licensify\Client\Exception\ConfigurationException;

/**
 * The set of Ed25519 public keys an installation trusts, keyed by `kid`.
 *
 * Several keys are held at once on purpose: the server rotates its signing key
 * and keeps the retired one published for a retention window, so certificates
 * already sitting in customer caches must keep verifying (contract §5.1).
 *
 * Trust can only ever be *widened* by an operator action (`add()`) or by a
 * successful online bootstrap from `GET /api/v1/products/{code}/public-key`
 * (`mergeFromServer()`). Nothing the SDK reads from its own cache can add a key.
 */
final class Keyring
{
    /** Length in bytes of an Ed25519 public key. */
    public const PUBLIC_KEY_BYTES = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

    /**
     * Placeholder bootstrap key shipped so the class is never empty.
     *
     * It is a structurally valid Ed25519 public key with **no private half in
     * existence** — it can never sign a certificate, so it cannot be used to
     * forge one. Every product must replace it with its server's real published
     * key, either through the `LICENSE_PUBLIC_KEY` environment variable or
     * `License::trustKey($kid, $publicKey)`. Certificates signed by anything
     * else are refused.
     */
    public const PLACEHOLDER_KID = 'key_placeholder';

    public const PLACEHOLDER_PUBLIC_KEY = 'y1BTDigK89i9nswekvNMi2JDj5q6uUYG96YzROVQVnY=';

    /**
     * @var array<string, string> Raw 32-byte public keys keyed by `kid`.
     */
    private array $keys;

    /**
     * @param  array<string, string>  $keys  Raw public keys keyed by `kid`.
     */
    public function __construct(array $keys = [])
    {
        $this->keys = [];

        foreach ($keys as $kid => $publicKey) {
            $this->add((string) $kid, (string) $publicKey);
        }
    }

    /**
     * A keyring containing only the unusable shipped placeholder.
     */
    public static function bootstrap(): self
    {
        return new self([
            self::PLACEHOLDER_KID => self::PLACEHOLDER_PUBLIC_KEY,
        ]);
    }

    /**
     * Trusts a key. Re-adding a `kid` with different material is refused: an
     * attacker who could rewrite the keyring must not be able to redirect a
     * known `kid` at their own key.
     *
     * @throws ConfigurationException
     */
    public function add(string $kid, string $publicKey): self
    {
        $kid = trim($kid);

        if ($kid === '') {
            throw new ConfigurationException('A signing key id (kid) is required.', 'INVALID_KEY_ID');
        }

        $decoded = self::normalisePublicKey($publicKey);

        if (isset($this->keys[$kid])) {
            if (! hash_equals($this->keys[$kid], $decoded)) {
                throw new ConfigurationException(
                    sprintf('Refusing to replace signing key "%s" with different material.', $kid),
                    'KEY_CONFLICT',
                );
            }

            return $this;
        }

        $this->keys[$kid] = $decoded;

        return $this;
    }

    /**
     * Replaces the whole keyring, used when an operator supplies an explicit
     * pinned set that supersedes whatever was cached before.
     *
     * @param  array<string, string>  $keys
     *
     * @throws ConfigurationException
     */
    public function replace(array $keys): self
    {
        $replacement = new self;

        foreach ($keys as $kid => $publicKey) {
            $replacement->add((string) $kid, (string) $publicKey);
        }

        $this->keys = $replacement->keys;

        return $this;
    }

    public function has(string $kid): bool
    {
        return isset($this->keys[$kid]);
    }

    /**
     * Raw public key bytes, or null when the `kid` is not trusted.
     */
    public function get(string $kid): ?string
    {
        return $this->keys[$kid] ?? null;
    }

    public function forget(string $kid): self
    {
        unset($this->keys[$kid]);

        return $this;
    }

    /**
     * @return array<string, string> Raw keys keyed by `kid`.
     */
    public function all(): array
    {
        return $this->keys;
    }

    /**
     * `kid => base64 public key`, the shape persisted in the cache store and
     * expected by the trust-bootstrap endpoint.
     *
     * @return array<string, string>
     */
    public function toBase64Array(): array
    {
        return array_map(base64_encode(...), $this->keys);
    }

    /**
     * @param  array<string, string>  $keys  Raw keys keyed by `kid`.
     *
     * @throws ConfigurationException
     */
    public static function fromBase64Array(array $keys): self
    {
        $keyring = new self;

        foreach ($keys as $kid => $publicKey) {
            $keyring->add((string) $kid, (string) $publicKey);
        }

        return $keyring;
    }

    /**
     * Ingests the payload of `GET /api/v1/products/{code}/public-key`.
     *
     * Both the plain `keys` map and the `data.algorithm`-style envelopes are
     * accepted, because the field names come from the server side of the
     * contract and may be wrapped or flat.
     *
     * @param  array<string, mixed>  $payload
     *
     * @throws ConfigurationException
     */
    public function mergeFromServer(array $payload): self
    {
        // Only the documented key members are considered. Falling back to the
        // whole payload would try to read unrelated response fields — a product
        // code, a URL — as keys.
        $candidates = $payload['keys'] ?? $payload['public_keys'] ?? null;

        if (! is_array($candidates) || $candidates === []) {
            return $this;
        }

        foreach ($candidates as $index => $key) {
            $kid = is_string($index) ? $index : null;

            if (is_array($key)) {
                // Only an explicit `kid` member is a key id; a bare array index is
                // a position, not an identity.
                $kid = is_string($key['kid'] ?? null) ? $key['kid'] : null;
                $key = (string) ($key['public_key'] ?? $key['publicKey'] ?? '');
            }

            if ($kid === null || trim($kid) === '' || ! is_string($key) || trim($key) === '') {
                continue;
            }

            $this->add($kid, $key);
        }

        return $this;
    }

    /**
     * @throws ConfigurationException
     */
    private static function normalisePublicKey(string $publicKey): string
    {
        $trimmed = trim($publicKey);
        $decoded = Base64Url::decodeFixed($trimmed, self::PUBLIC_KEY_BYTES);

        if ($decoded === null) {
            $decoded = base64_decode($trimmed, true);
        }

        if ($decoded === false || strlen($decoded) !== self::PUBLIC_KEY_BYTES) {
            throw new ConfigurationException(
                'An Ed25519 public key must be 32 raw bytes encoded as standard or URL-safe base64.',
                'INVALID_PUBLIC_KEY',
            );
        }

        return $decoded;
    }
}
