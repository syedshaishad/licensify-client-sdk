<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

use JsonException;
use Licensify\Client\Exception\VerificationException;

/**
 * A parsed — but not yet verified — license certificate (contract §5).
 *
 * The wire format is JWT-*shaped* yet deliberately not a JWT: it carries
 * `typ: LIC` so it can never be accepted by generic JWT middleware, and this
 * SDK never passes one to any.
 *
 *     base64url(header) "." base64url(payload) "." base64url(ed25519 signature)
 *
 * Parsing is structural only. Nothing in this class says the token is genuine;
 * that verdict comes from {@see SignatureVerifier}.
 */
final readonly class Certificate
{
    /**
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $payload
     */
    private function __construct(
        public array $header,
        public array $payload,
        public string $signature,
        public string $signingInput,
    ) {}

    /**
     * @throws VerificationException
     */
    public static function parse(string $token): self
    {
        $token = trim($token);

        if ($token === '') {
            throw VerificationException::malformed('the token is empty');
        }

        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw VerificationException::malformed('expected three dot-separated segments');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = self::decodeSegment($encodedHeader);
        $payload = self::decodeSegment($encodedPayload);

        $signature = Base64Url::decode($encodedSignature);

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw VerificationException::malformed('the signature is not a 64-byte Ed25519 signature');
        }

        return new self(
            header: $header,
            payload: $payload,
            signature: $signature,
            signingInput: $encodedHeader.'.'.$encodedPayload,
        );
    }

    /**
     * Verifies the signature against every key the keyring trusts for this
     * `kid`, and returns the token unchanged so callers can read claims.
     *
     * @throws VerificationException
     */
    public function verify(Keyring $keyring): self
    {
        SignatureVerifier::verify($this, $keyring);

        return $this;
    }

    public function kid(): string
    {
        return (string) ($this->header['kid'] ?? '');
    }

    public function algorithm(): string
    {
        return (string) ($this->header['alg'] ?? '');
    }

    public function type(): string
    {
        return (string) ($this->header['typ'] ?? '');
    }

    public function version(): int
    {
        return (int) ($this->header['v'] ?? 1);
    }

    public function issuer(): string
    {
        return (string) ($this->payload['iss'] ?? '');
    }

    public function subject(): string
    {
        return (string) ($this->payload['sub'] ?? '');
    }

    public function licenseId(): string
    {
        return (string) ($this->payload['lid'] ?? '');
    }

    public function licenseFingerprint(): string
    {
        return (string) ($this->payload['lkey_fp'] ?? '');
    }

    public function installationId(): string
    {
        return (string) ($this->payload['inst'] ?? $this->payload['sub'] ?? '');
    }

    public function productCode(): string
    {
        return (string) ($this->payload['pcode'] ?? '');
    }

    public function domain(): string
    {
        return (string) ($this->payload['dom'] ?? '');
    }

    public function status(): string
    {
        return (string) ($this->payload['status'] ?? '');
    }

    public function plan(): string
    {
        return (string) ($this->payload['plan'] ?? '');
    }

    public function softwareVersion(): string
    {
        return (string) ($this->payload['ver'] ?? '');
    }

    /**
     * Per-license monotonic state counter (contract §5.2). Anything lower than
     * the highest value this installation has already trusted is refused.
     */
    public function revocationCounter(): int
    {
        return (int) ($this->payload['rev'] ?? 0);
    }

    public function issuedAt(): int
    {
        return (int) ($this->payload['iat'] ?? 0);
    }

    public function notBefore(): int
    {
        return (int) ($this->payload['nbf'] ?? $this->issuedAt());
    }

    public function expiresAt(): int
    {
        return (int) ($this->payload['exp'] ?? 0);
    }

    public function graceSeconds(): int
    {
        return (int) ($this->payload['grace'] ?? 0);
    }

    public function isExpired(?int $now = null): bool
    {
        return ($now ?? time()) > $this->expiresAt();
    }

    public function secondsUntilExpiry(?int $now = null): int
    {
        return max(0, $this->expiresAt() - ($now ?? time()));
    }

    /**
     * @return array<string, mixed>
     */
    public function payloadArray(): array
    {
        return $this->payload;
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $segment): array
    {
        $json = Base64Url::decode($segment);

        if ($json === '') {
            throw VerificationException::malformed('a segment is not valid base64url');
        }

        try {
            $decoded = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw VerificationException::malformed('a segment is not valid JSON');
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw VerificationException::malformed('a segment is not a JSON object');
        }

        return $decoded;
    }
}
