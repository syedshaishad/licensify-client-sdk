<?php

declare(strict_types=1);

namespace Licensify\Client;

use DateTimeImmutable;
use DateTimeInterface;
use Licensify\Client\Exception\LicenseException;

/**
 * What the server returns when a customer asks for an update package.
 *
 * It is deliberately separate from {@see UpdateInfo}: update availability
 * tells software whether to advertise an update; this is the artefact the
 * caller downloads and verifies before swapping anything in.
 */
final readonly class UpdatePackage
{
    public function __construct(
        public string $url,
        public string $version,
        public string $filename,
        public int $sizeBytes,
        public ?DateTimeInterface $expiresAt,
        public string $sha256,
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     */
    public static function fromArray(array $payload): self
    {
        $url = self::stringValue($payload, 'url');
        $version = self::stringValue($payload, 'version');
        $filename = self::stringValue($payload, 'filename') ?? '';
        $sha256 = self::stringValue($payload, 'sha256') ?? self::unprefixChecksum(self::stringValue($payload, 'checksum'));

        $size = $payload['size_bytes'] ?? 0;
        $size = is_numeric($size) ? max(0, (int) $size) : 0;

        if ($url === null || $version === null || $sha256 === null) {
            throw new LicenseException(
                'The server did not return a complete download grant.',
                'DOWNLOAD_GRANT_INVALID',
            );
        }

        $expires = self::dateValue($payload['expires_at'] ?? null);

        return new self(
            url: $url,
            version: $version,
            filename: $filename,
            sizeBytes: $size,
            expiresAt: $expires,
            sha256: strtolower($sha256),
        );
    }

    /**
     * Whether the downloaded bytes match the checksum the server reported.
     *
     * @throws LicenseException when the package cannot be read; a mismatch is
     *                          represented by `false`, not by an exception.
     */
    public function verify(string $path): bool
    {
        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            throw new LicenseException('The package file could not be read for verification.', 'PACKAGE_UNREADABLE');
        }

        $actual = hash_file('sha256', $path);

        fclose($handle);

        return is_string($actual) && hash_equals($this->sha256, strtolower($actual));
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function stringValue(array $payload, string $key): ?string
    {
        $value = $payload[$key] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    private static function unprefixChecksum(?string $checksum): ?string
    {
        if ($checksum === null) {
            return null;
        }

        $checksum = trim($checksum);

        if (str_starts_with($checksum, 'sha256:')) {
            $checksum = substr($checksum, strlen('sha256:'));
        }

        $checksum = strtolower($checksum);

        return preg_match('/^[a-f0-9]{64}$/', $checksum) === 1 ? $checksum : null;
    }

    private static function dateValue(mixed $value): ?\DateTimeInterface
    {
        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        try {
            return new DateTimeImmutable(trim($value));
        } catch (\Exception) {
            return null;
        }
    }
}
