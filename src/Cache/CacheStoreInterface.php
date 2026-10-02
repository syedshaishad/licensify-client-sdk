<?php

declare(strict_types=1);

namespace Licensify\Client\Cache;

/**
 * The SDK's only writable surface.
 *
 * Nothing else in the package touches storage, so an operator can point the
 * SDK at a directory, a Laravel cache, or an in-memory array in tests by
 * swapping one object. Contract §10 requires this boundary explicitly.
 */
interface CacheStoreInterface
{
    public function get(string $key): mixed;

    /**
     * @param  int|null  $ttl  Seconds to keep the value. Null means "until the
     *                         next process reads it", i.e. persisted with no
     *                         expiry, which is only appropriate for values such
     *                         as the installation id and the revocation floor.
     */
    public function put(string $key, mixed $value, ?int $ttl = null): void;

    public function has(string $key): bool;

    public function forget(string $key): void;

    /**
     * Removes every key owned by this SDK, leaving no trace that could be
     * mistaken for a valid licence.
     */
    public function flush(): void;

    /**
     * Namespaced key derivation, so several licences can share one store.
     */
    public function key(string $name): string;
}
