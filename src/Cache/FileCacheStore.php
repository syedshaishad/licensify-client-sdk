<?php

declare(strict_types=1);

namespace Licensify\Client\Cache;

use JsonException;
use Throwable;

/**
 * The default store: one JSON file per key under a private directory.
 *
 * Writes go to a temporary file in the same directory and are then renamed,
 * because `rename()` is atomic within a filesystem. A half-written certificate
 * would be indistinguishable from a tampered one, and a partially written file
 * after a crash must never be read as a valid licence.
 *
 * The stored certificate is *trustworthy data about* trust, never a substitute
 * for it: every read is re-verified against the pinned keyring, so editing this
 * file can at worst deny access.
 */
final class FileCacheStore implements CacheStoreInterface
{
    private const FILE_EXTENSION = '.json';

    public function __construct(
        private readonly string $directory,
        private readonly string $prefix = 'licensify',
        private readonly int $filePermissions = 0600,
    ) {}

    /**
     * Default location: `storage_path()` inside a Laravel app, otherwise the
     * system temp directory. Never the document root.
     */
    public static function default(): self
    {
        return new self(self::defaultDirectory());
    }

    public static function defaultDirectory(): string
    {
        return self::laravelPath('licensify') ?? rtrim(sys_get_temp_dir(), '/').'/licensify-sdk';
    }

    /**
     * `storage_path()` exists as soon as Laravel's helpers are loaded but throws
     * unless a container is bound. The SDK must also work in plain PHP, so an
     * unbound container is an ordinary "this is not a Laravel app" answer.
     */
    private static function laravelPath(string $relative): ?string
    {
        if (! function_exists('storage_path')) {
            return null;
        }

        try {
            $path = storage_path($relative);
        } catch (Throwable) {
            return null;
        }

        return is_string($path) && $path !== '' ? $path : null;
    }

    public function get(string $key): mixed
    {
        $path = $this->pathFor($key);

        if (! is_file($path) || ! is_readable($path)) {
            return null;
        }

        $contents = file_get_contents($path);

        if ($contents === false || trim($contents) === '') {
            return null;
        }

        try {
            $decoded = json_decode($contents, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            // A corrupt file is treated as absent: the SDK then re-validates
            // online, which is the fail-closed behaviour, rather than trusting
            // whatever partial content was left behind.
            return null;
        }

        if (! is_array($decoded) || ! array_key_exists('value', $decoded)) {
            return null;
        }

        $expiresAt = $decoded['expires_at'] ?? null;

        if (is_int($expiresAt) && $expiresAt <= time()) {
            $this->forget($key);

            return null;
        }

        return $decoded['value'];
    }

    public function put(string $key, mixed $value, ?int $ttl = null): void
    {
        $this->ensureDirectoryExists();

        $payload = json_encode([
            'key' => $key,
            'expires_at' => $ttl === null ? null : time() + $ttl,
            'stored_at' => time(),
            'value' => $value,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        $path = $this->pathFor($key);
        $temporary = $path.'.'.bin2hex(random_bytes(6)).'.tmp';

        if (file_put_contents($temporary, $payload, LOCK_EX) === false) {
            throw new CacheWriteException(sprintf('Could not write the licence cache file "%s".', $temporary));
        }

        @chmod($temporary, $this->filePermissions);

        if (! @rename($temporary, $path)) {
            @unlink($temporary);

            throw new CacheWriteException(sprintf('Could not commit the licence cache file "%s".', $path));
        }
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function forget(string $key): void
    {
        $path = $this->pathFor($key);

        if (is_file($path)) {
            @unlink($path);
        }
    }

    public function flush(): void
    {
        $pattern = $this->directory.DIRECTORY_SEPARATOR.$this->prefix.'-*'.self::FILE_EXTENSION;

        foreach (glob($pattern) ?: [] as $file) {
            @unlink($file);
        }
    }

    public function key(string $name): string
    {
        return $this->prefix.'-'.$this->sanitise($name);
    }

    public function directory(): string
    {
        return $this->directory;
    }

    private function pathFor(string $key): string
    {
        return $this->directory.DIRECTORY_SEPARATOR.$this->key($key).self::FILE_EXTENSION;
    }

    private function ensureDirectoryExists(): void
    {
        if (is_dir($this->directory)) {
            return;
        }

        if (! @mkdir($this->directory, 0700, true) && ! is_dir($this->directory)) {
            throw new CacheWriteException(sprintf('Could not create the licence cache directory "%s".', $this->directory));
        }
    }

    /**
     * Key names are attacker-influenced in the sense that they may contain a
     * product code, so anything but `[A-Za-z0-9._-]` is collapsed. That keeps a
     * crafted product code from escaping the cache directory via `../`.
     */
    private function sanitise(string $name): string
    {
        $sanitised = preg_replace('/[^A-Za-z0-9._-]+/', '-', $name) ?? '';
        $sanitised = trim($sanitised, '-.');

        return $sanitised === '' ? 'unnamed' : substr($sanitised, 0, 180);
    }
}
