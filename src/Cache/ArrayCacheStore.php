<?php

declare(strict_types=1);

namespace Licensify\Client\Cache;

/**
 * In-memory store for tests and short-lived CLI processes.
 *
 * Expiry is honoured exactly like {@see FileCacheStore} so behaviour under
 * test matches behaviour in production.
 */
final class ArrayCacheStore implements CacheStoreInterface
{
    /**
     * @var array<string, array{value: mixed, expires_at: int|null}>
     */
    private array $items = [];

    public function __construct(private readonly string $prefix = 'licensify') {}

    public function get(string $key): mixed
    {
        $key = $this->key($key);

        if (! isset($this->items[$key])) {
            return null;
        }

        $item = $this->items[$key];

        if ($item['expires_at'] !== null && $item['expires_at'] <= time()) {
            unset($this->items[$key]);

            return null;
        }

        return $item['value'];
    }

    public function put(string $key, mixed $value, ?int $ttl = null): void
    {
        $this->items[$this->key($key)] = [
            'value' => $value,
            'expires_at' => $ttl === null ? null : time() + $ttl,
        ];
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function forget(string $key): void
    {
        unset($this->items[$this->key($key)]);
    }

    public function flush(): void
    {
        $this->items = [];
    }

    public function key(string $name): string
    {
        return $this->prefix.':'.$name;
    }
}
