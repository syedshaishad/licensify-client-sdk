<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Throwable;

/**
 * Works out which version of the customer's software is running.
 *
 * Detection order is explicit override → a well-known version constant →
 * `composer.json` (where Composer publishes `extra.licensify.version`) →
 * empty. An undetectable version is reported as `''` rather than guessed at,
 * because a wrong version silently misreports what is installed.
 */
final class VersionDetector
{
    /**
     * Constants checked, in order, when no override is supplied.
     *
     * @var array<int, string>
     */
    public const VERSION_CONSTANTS = [
        'LICENSE_VERSION',
        'APP_VERSION',
        'MYAPP_VERSION',
        'VERSION',
    ];

    public function __construct(
        private readonly ?string $projectPath = null,
        /** @var array<int, string> */
        private readonly array $versionConstants = self::VERSION_CONSTANTS,
    ) {}

    /**
     * A detector rooted at this configuration's project directory. An explicit
     * `LICENSE_VERSION` is supplied to {@see self::detect()} instead, so it
     * still takes precedence over detection.
     */
    public static function fromConfiguration(Configuration $configuration): self
    {
        return new self($configuration->version !== null ? null : self::projectPath());
    }

    /**
     * @param  array<string, mixed>  $server
     * @return string The detected version, or `''` when it cannot be determined.
     */
    public function detect(?string $override = null, ?array $server = null): string
    {
        if ($override !== null && trim($override) !== '') {
            return trim($override);
        }

        $server ??= $_SERVER;

        foreach ($this->versionConstants as $constant) {
            $value = $server[$constant] ?? null;

            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        $declared = defined('APP_VERSION') ? constant('APP_VERSION') : null;

        if (is_string($declared) && trim($declared) !== '') {
            return trim($declared);
        }

        return $this->fromComposerJson();
    }

    public function isNewer(string $candidate, string $current): bool
    {
        if ($candidate === '' || $current === '') {
            return false;
        }

        return Semver::isNewer($candidate, $current);
    }

    private function fromComposerJson(): string
    {
        $path = rtrim($this->projectPath ?? self::projectPath(), '/').'/composer.json';

        if (! is_file($path) || ! is_readable($path)) {
            return '';
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return '';
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            return '';
        }

        $extra = $decoded['extra'] ?? null;

        if (! is_array($extra)) {
            return '';
        }

        $candidates = [
            $extra['licensify']['version'] ?? null,
            $extra['version'] ?? null,
        ];

        foreach ($candidates as $candidate) {
            if (is_string($candidate) && trim($candidate) !== '') {
                return trim($candidate);
            }
        }

        return '';
    }

    /**
     * Project root, honouring Laravel's `base_path()` when it is available.
     */
    private static function projectPath(): string
    {
        // `base_path()` throws unless a Laravel container is bound, so an
        // unbound container simply means "not a Laravel app".
        try {
            if (function_exists('base_path')) {
                $path = base_path();

                if (is_string($path) && $path !== '') {
                    return $path;
                }
            }
        } catch (Throwable) {
            // Fall through to the working directory.
        }

        return getcwd() ?: '.';
    }
}
