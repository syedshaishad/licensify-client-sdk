<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Licensify\Client\Cache\CacheStoreInterface;

/**
 * A stable per-installation identifier: `inst_` + 32 hex characters (contract §10).
 *
 * Generated once and then persisted, because it is what the server counts
 * activations against. Regenerating it on every request would let a single
 * customer consume unlimited activations, so the value is only ever created
 * when it is genuinely absent.
 */
final class InstallationId
{
    public const PREFIX = 'inst_';

    /** Hex characters after the prefix (16 random bytes). */
    public const LENGTH = 32;

    public function __construct(
        private readonly CacheStoreInterface $cache,
        private readonly string $cacheKey = 'installation-id',
    ) {}

    /**
     * Returns the existing identifier or creates and persists one.
     */
    public function resolve(): string
    {
        $existing = $this->cache->get($this->cacheKey);

        if (is_string($existing) && self::isWellFormed($existing)) {
            return $existing;
        }

        $generated = self::PREFIX.Random::hex(self::LENGTH / 2);
        $this->cache->put($this->cacheKey, $generated);

        return $generated;
    }

    /**
     * Reads the identifier without creating one, for diagnostics.
     */
    public function peek(): ?string
    {
        $existing = $this->cache->get($this->cacheKey);

        return is_string($existing) && self::isWellFormed($existing) ? $existing : null;
    }

    /**
     * Discards the identifier, e.g. after a full deactivation.
     */
    public function forget(): void
    {
        $this->cache->forget($this->cacheKey);
    }

    public static function isWellFormed(string $value): bool
    {
        return preg_match('/^'.preg_quote(self::PREFIX, '/').'[a-f0-9]{'.self::LENGTH.'}$/', $value) === 1;
    }

    /**
     * Convenience for wiring an installation id into a fresh store.
     */
    public static function generate(): string
    {
        return self::PREFIX.Random::hex(self::LENGTH / 2);
    }
}
