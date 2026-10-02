<?php

declare(strict_types=1);

namespace Licensify\Client;

use DateTimeImmutable;
use DateTimeZone;
use Licensify\Client\Support\Semver;

/**
 * The answer to "is there a newer release?" (contract §4, `/updates/check`).
 *
 * `updateAvailable` is decided with semver comparison rather than string
 * inequality, so `2.10.0` beats `2.9.0` and `2.5.0-beta.1` does not beat
 * `2.5.0`.
 */
final readonly class UpdateInfo
{
    public function __construct(
        public bool $updateAvailable,
        public string $currentVersion,
        public ?string $latestVersion = null,
        public ?string $releaseType = null,
        public ?string $releaseNotes = null,
        public ?DateTimeImmutable $publishedAt = null,
        public bool $downloadAvailable = false,
        public ?string $minimumPhpVersion = null,
        public ?string $minimumLaravelVersion = null,
        public ?string $changelogUrl = null,
        public bool $requiresFullDownload = false,
    ) {}

    /**
     * @param  array<string, mixed>  $payload  Untrusted response body; every field is type-checked.
     */
    public static function fromArray(array $payload, string $currentVersion): self
    {
        $latest = is_string($payload['latest_version'] ?? null) ? trim($payload['latest_version']) : '';

        // Trust the server's own flag when it sent one, but never let it claim
        // an update when the versions actually say otherwise.
        $available = ($payload['update_available'] ?? null) === true;

        if ($latest !== '' && $currentVersion !== '') {
            $available = Semver::isNewer($latest, $currentVersion);
        } elseif ($latest === '' || $currentVersion === '') {
            $available = false;
        }

        return new self(
            updateAvailable: $available,
            currentVersion: $currentVersion,
            latestVersion: $latest === '' ? null : $latest,
            releaseType: self::stringOrNull($payload['release_type'] ?? null),
            releaseNotes: self::stringOrNull($payload['release_notes'] ?? null),
            publishedAt: self::dateFrom($payload['published_at'] ?? null),
            downloadAvailable: ($payload['download_available'] ?? false) === true,
            minimumPhpVersion: self::stringOrNull($payload['minimum_php_version'] ?? null),
            minimumLaravelVersion: self::stringOrNull($payload['minimum_laravel_version'] ?? null),
            changelogUrl: self::stringOrNull($payload['changelog_url'] ?? null),
            requiresFullDownload: ($payload['requires_full_download'] ?? false) === true,
        );
    }

    /**
     * Is the running installation even able to take this release? Guards against
     * an operator being told to update to something their host cannot run.
     */
    public function isCompatibleWith(string $phpVersion, ?string $laravelVersion = null): bool
    {
        if ($this->minimumPhpVersion !== null && $this->minimumPhpVersion !== ''
            && Semver::compare($phpVersion, $this->minimumPhpVersion) < 0) {
            return false;
        }

        if ($this->minimumLaravelVersion !== null && $this->minimumLaravelVersion !== ''
            && $laravelVersion !== null && $laravelVersion !== ''
            && Semver::compare($laravelVersion, $this->minimumLaravelVersion) < 0) {
            return false;
        }

        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'update_available' => $this->updateAvailable,
            'current_version' => $this->currentVersion,
            'latest_version' => $this->latestVersion,
            'release_type' => $this->releaseType,
            'release_notes' => $this->releaseNotes,
            'published_at' => $this->publishedAt?->format(DATE_ATOM),
            'download_available' => $this->downloadAvailable,
            'minimum_php_version' => $this->minimumPhpVersion,
            'minimum_laravel_version' => $this->minimumLaravelVersion,
            'changelog_url' => $this->changelogUrl,
            'requires_full_download' => $this->requiresFullDownload,
        ];
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    private static function dateFrom(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        try {
            return new DateTimeImmutable(trim($value), new DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }
}
