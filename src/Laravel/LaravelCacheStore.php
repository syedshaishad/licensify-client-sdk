<?php

declare(strict_types=1);

namespace Licensify\Client\Laravel;

use DateInterval;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Licensify\Client\Cache\CacheStoreInterface;

/**
 * Backs the SDK's cache contract with the application's own cache.
 *
 * The SDK writes through this adapter and nothing else, so a deployment can
 * point the certificate cache at Redis, Memcached, the database, or the file
 * driver without the licensing code knowing.
 */
final readonly class LaravelCacheStore implements CacheStoreInterface
{
    public function __construct(
        private CacheRepository $cache,
        private string $prefix = 'licensify',
    ) {}

    public function get(string $key): mixed
    {
        $value = $this->cache->get($this->key($key));

        // A certificate is stored as a string; anything else means another
        // component wrote to the same key and it must not be trusted as one.
        return is_string($value) || is_array($value) || is_numeric($value) || is_bool($value) || $value === null
            ? $value
            : null;
    }

    public function put(string $key, mixed $value, ?int $ttl = null): void
    {
        if ($ttl === null) {
            $this->cache->forever($this->key($key), $value);

            return;
        }

        $this->cache->put($this->key($key), $value, DateInterval::createFromDateString($ttl.' seconds'));
    }

    public function has(string $key): bool
    {
        return $this->cache->has($this->key($key));
    }

    public function forget(string $key): void
    {
        $this->cache->forget($this->key($key));
    }

    public function flush(): void
    {
        // Scoped by prefix rather than `flush()`, which would empty the whole
        // application cache as a side effect of a licensing operation.
        foreach ($this->knownKeys() as $key) {
            $this->cache->forget($this->key($key));
        }
    }

    public function key(string $name): string
    {
        return $this->prefix.'-'.preg_replace('/[^A-Za-z0-9._-]+/', '-', $name);
    }

    /**
     * @return array<int, string>
     */
    private function knownKeys(): array
    {
        return [
            'installation-id',
            'certificate',
            'status',
            'rev-floor',
        ];
    }
}
