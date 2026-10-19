<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Licensify\Client\Laravel\LaravelCacheStore;
use PHPUnit\Framework\TestCase;

/**
 * The adapter that backs the SDK's cache with the application's own cache.
 *
 * A deployment can point the certificate cache at Redis, Memcached, the
 * database or the file driver without the licensing code knowing. What matters
 * here is that the adapter is scoped: it must never empty the application's
 * cache as a side effect of a licensing operation.
 */
final class LaravelCacheStoreTest extends TestCase
{
    private Repository $cache;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cache = new Repository(new ArrayStore);
    }

    public function test_a_value_survives_a_round_trip(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $store->put('certificate', 'a-token');

        $this->assertSame('a-token', $store->get('certificate'));
    }

    public function test_it_writes_through_to_the_applications_cache(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $store->put('certificate', 'a-token');

        $this->assertSame('a-token', $this->cache->get('licensify-certificate'));
    }

    public function test_keys_are_scoped_by_prefix(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $store->put('certificate', 'a-token');

        $this->assertTrue($this->cache->has('licensify-certificate'));
        $this->assertFalse($this->cache->has('certificate'), 'the key escaped the prefix');
    }

    public function test_it_reports_what_it_has(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $this->assertFalse($store->has('certificate'));

        $store->put('certificate', 'a-token');

        $this->assertTrue($store->has('certificate'));
    }

    public function test_it_forgets(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $store->put('certificate', 'a-token');
        $store->forget('certificate');

        $this->assertFalse($store->has('certificate'));
        $this->assertNull($store->get('certificate'));
    }

    public function test_flushing_empties_only_the_sdk_keys(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $store->put('certificate', 'a-token');
        $this->cache->forever('the-application-own-key', 'untouched');

        $store->flush();

        $this->assertFalse($store->has('certificate'));
        $this->assertSame(
            'untouched',
            $this->cache->get('the-application-own-key'),
            'flushing the licence cache emptied the application cache',
        );
    }

    public function test_a_value_that_is_not_a_certificate_is_not_trusted(): void
    {
        $store = new LaravelCacheStore($this->cache);

        // Something else wrote an object to the same key.
        $this->cache->forever('licensify-certificate', new \stdClass);

        $this->assertNull($store->get('certificate'));
    }

    public function test_the_key_is_made_safe(): void
    {
        $store = new LaravelCacheStore($this->cache);

        $this->assertSame('licensify-some-key', $store->key('some/key'));
        $this->assertSame('licensify-some-key', $store->key('some key'));
    }
}
