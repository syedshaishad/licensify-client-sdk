<?php

declare(strict_types=1);

namespace Licensify\Client;

use DateTimeImmutable;
use DateTimeZone;
use Licensify\Client\Security\Certificate;

/**
 * The immutable answer to "may this installation run?" (contract §10).
 *
 * Every path — a live server response, a locally verified cached certificate,
 * or a refusal — produces one of these, so callers never have to know which
 * happened. The distinction that does matter is `offline`: when it is true the
 * answer rests on a cached certificate and `graceSecondsRemaining()` is the
 * real deadline.
 */
final readonly class LicenseStatus
{
    /**
     * @param  array<string, mixed>  $details
     */
    public function __construct(
        public bool $valid,
        public string $status,
        public string $productCode,
        /** True when this verdict came from a cached certificate, not the server. */
        public bool $offline = false,
        public ?string $licenseType = null,
        public ?DateTimeImmutable $expiresAt = null,
        public ?string $installationId = null,
        public ?string $domain = null,
        public bool $updateAvailable = false,
        public ?string $latestVersion = null,
        public ?DateTimeImmutable $graceExpiresAt = null,
        public int $graceSecondsRemaining = 0,
        public ?string $certificate = null,
        public ?string $publicKeyId = null,
        public int $revocationCounter = 0,
        public ?string $errorCode = null,
        public string $message = '',
        public ?int $verifiedAt = null,
        public array $details = [],
    ) {}

    /**
     * A refusal. Still a `LicenseStatus` so callers handle one type.
     *
     * @param  array<string, mixed>  $details
     */
    public static function invalid(string $status, string $errorCode, string $message = '', array $details = []): self
    {
        return new self(
            valid: false,
            status: $status,
            productCode: '',
            errorCode: $errorCode,
            message: $message,
            details: $details,
        );
    }

    /**
     * Builds a status from the flat `validate` response body (contract §1.3).
     *
     * The response is untrusted input: every field is type-checked, and the
     * certificate is *not* trusted here — the caller verifies it and re-derives
     * the offline status from {@see self::fromCertificate()} when appropriate.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function fromApiResponse(array $payload, ?int $now = null): self
    {
        $now ??= time();
        $valid = ($payload['valid'] ?? false) === true;

        return new self(
            valid: $valid,
            status: self::stringOrEmpty($payload['status'] ?? ($valid ? 'active' : 'invalid')),
            productCode: self::stringOrEmpty($payload['product'] ?? ''),
            licenseType: self::stringOrNull($payload['license_type'] ?? null),
            expiresAt: self::dateFrom($payload['expires_at'] ?? null),
            installationId: self::stringOrNull($payload['installation_id'] ?? null),
            domain: self::stringOrNull($payload['domain'] ?? null),
            updateAvailable: ($payload['update_available'] ?? false) === true,
            latestVersion: self::stringOrNull($payload['latest_version'] ?? null),
            graceExpiresAt: self::dateFrom($payload['offline_until'] ?? null),
            graceSecondsRemaining: self::intOrZero($payload['grace_expires_in'] ?? null),
            certificate: self::stringOrNull($payload['certificate'] ?? null),
            publicKeyId: self::stringOrNull($payload['public_key_id'] ?? null),
            errorCode: $valid ? null : self::stringOrNull($payload['error_code'] ?? null),
            message: self::stringOrEmpty($payload['message'] ?? ''),
            verifiedAt: $now,
        );
    }

    /**
     * Re-derives a status from a certificate that has *already* passed
     * signature, window and revocation-counter checks.
     */
    public static function fromCertificate(
        Certificate $certificate,
        string $productCode,
        ?string $licenseType = null,
        ?string $domain = null,
        bool $updateAvailable = false,
        ?string $latestVersion = null,
        ?int $now = null,
    ): self {
        $now ??= time();
        $expiresAt = $certificate->expiresAt();

        return new self(
            valid: true,
            status: $certificate->status(),
            productCode: $certificate->productCode() !== '' ? $certificate->productCode() : $productCode,
            offline: true,
            licenseType: $licenseType ?? ($certificate->plan() !== '' ? $certificate->plan() : null),
            expiresAt: self::dateFromUnix($expiresAt),
            installationId: $certificate->installationId(),
            domain: $domain ?? ($certificate->domain() !== '' ? $certificate->domain() : null),
            updateAvailable: $updateAvailable,
            latestVersion: $latestVersion,
            graceExpiresAt: self::dateFromUnix($expiresAt),
            graceSecondsRemaining: $certificate->secondsUntilExpiry($now),
            certificate: null,
            publicKeyId: $certificate->kid(),
            revocationCounter: $certificate->revocationCounter(),
            message: 'Validated offline against the cached certificate.',
            verifiedAt: $now,
        );
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * Days left in the grace window, rounded down. Zero once the window closes.
     */
    public function offlineDaysRemaining(): int
    {
        return intdiv($this->graceSecondsRemaining, 86400);
    }

    public function graceExpiresIn(): string
    {
        $seconds = $this->graceSecondsRemaining;

        if ($seconds <= 0) {
            return 'expired';
        }

        $days = intdiv($seconds, 86400);
        $hours = intdiv($seconds % 86400, 3600);
        $minutes = intdiv($seconds % 3600, 60);

        return match (true) {
            $days > 0 => sprintf('%dd %dh', $days, $hours),
            $hours > 0 => sprintf('%dh %dm', $hours, $minutes),
            default => sprintf('%dm', $minutes),
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'status' => $this->status,
            'product' => $this->productCode,
            'offline' => $this->offline,
            'license_type' => $this->licenseType,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'installation_id' => $this->installationId,
            'domain' => $this->domain,
            'update_available' => $this->updateAvailable,
            'latest_version' => $this->latestVersion,
            'offline_until' => $this->graceExpiresAt?->format(DATE_ATOM),
            'grace_expires_in' => $this->graceSecondsRemaining,
            'certificate' => $this->certificate,
            'public_key_id' => $this->publicKeyId,
            'revocation_counter' => $this->revocationCounter,
            'error_code' => $this->errorCode,
            'message' => $this->message,
            'verified_at' => $this->verifiedAt,
        ];
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    private static function stringOrEmpty(mixed $value): string
    {
        return is_string($value) ? trim($value) : '';
    }

    private static function intOrZero(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Parses an ISO-8601 date or datetime. A bare date means end-of-day UTC,
     * which is what a licence expiry means in the contract.
     */
    private static function dateFrom(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        $value = trim($value);
        $hasTime = preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/', $value) === 1;
        $normalised = $hasTime ? $value : $value.' 23:59:59';

        try {
            return (new DateTimeImmutable($normalised, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }

    private static function dateFromUnix(int $timestamp): DateTimeImmutable
    {
        return (new DateTimeImmutable('@'.$timestamp))->setTimezone(new DateTimeZone('UTC'));
    }
}
