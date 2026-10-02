<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

use Licensify\Client\Support\AuthScheme;
use SensitiveParameter;

/**
 * Builds the authentication headers for an API call (contract §3).
 *
 * HMAC signing is the default because it does not transmit the shared secret:
 * the signature covers method, path, canonical query, body digest, timestamp
 * and nonce, so a captured request cannot be replayed or edited.
 *
 *     canonical_string = METHOD \n path \n query \n sha256hex(body) \n ts \n nonce
 */
final readonly class RequestSigner
{
    public function __construct(
        private AuthScheme $scheme,
        #[SensitiveParameter]
        private string $apiKey,
        #[SensitiveParameter]
        private string $apiSecret,
    ) {}

    /**
     * The secret is used and discarded here; nothing else needs to hold it.
     */
    public static function fromCredentials(string $apiKey, string $apiSecret, ?AuthScheme $scheme = null): self
    {
        return new self($scheme ?? AuthScheme::Hmac, $apiKey, $apiSecret);
    }

    /**
     * @param  array<string, scalar>  $query
     * @return array<string, string>
     */
    public function headers(string $method, string $path, array $query = [], ?string $body = null, ?int $timestamp = null): array
    {
        if ($this->scheme === AuthScheme::Bearer) {
            return [
                'Authorization' => sprintf('Bearer %s.%s', $this->apiKey, $this->apiSecret),
            ];
        }

        $timestamp ??= time();
        $nonce = Base64Url::encode(random_bytes(16));

        return [
            'X-License-Key' => $this->apiKey,
            'X-License-Timestamp' => (string) $timestamp,
            'X-License-Nonce' => $nonce,
            'X-License-Signature' => self::sign(
                $this->apiSecret,
                self::canonicalString($method, $path, self::canonicalQuery($query), $body, $timestamp, $nonce),
            ),
        ];
    }

    /**
     * Exactly six LF-joined lines with no trailing newline.
     */
    public static function canonicalString(
        string $method,
        string $path,
        string $canonicalQuery,
        ?string $body,
        int $timestamp,
        string $nonce,
    ): string {
        return implode("\n", [
            strtoupper($method),
            self::canonicalPath($path),
            $canonicalQuery,
            hash('sha256', $body ?? ''),
            (string) $timestamp,
            $nonce,
        ]);
    }

    /**
     * Parameters sorted by key, RFC 3986 percent-encoded, joined with `&`.
     *
     * @param  array<string, scalar>  $query
     */
    public static function canonicalQuery(array $query): string
    {
        if ($query === []) {
            return '';
        }

        ksort($query, SORT_STRING);

        $pairs = [];

        foreach ($query as $key => $value) {
            if ($value === null) {
                continue;
            }

            if (is_bool($value)) {
                $value = $value ? 'true' : 'false';
            }

            $pairs[] = rawurlencode((string) $key).'='.rawurlencode((string) $value);
        }

        return implode('&', $pairs);
    }

    public static function sign(string $apiSecret, string $canonicalString): string
    {
        return Base64Url::encode(hash_hmac('sha256', $canonicalString, $apiSecret, true));
    }

    /**
     * Verifies a signature the way the server does. Exposed so a client-side
     * proxy or a test can reproduce the server's check exactly.
     */
    public static function verify(string $apiSecret, string $canonicalString, string $providedSignature): bool
    {
        return hash_equals(self::sign($apiSecret, $canonicalString), $providedSignature);
    }

    public function scheme(): AuthScheme
    {
        return $this->scheme;
    }

    private static function canonicalPath(string $path): string
    {
        $path = '/'.ltrim($path, '/');

        // The canonical string separates path from query, so any query string
        // that arrived inline must be dropped or both sides would disagree.
        return explode('?', $path, 2)[0];
    }
}
