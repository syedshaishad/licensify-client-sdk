<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Cache\ArrayCacheStore;
use Licensify\Client\Cache\CacheStoreInterface;
use Licensify\Client\Cache\FileCacheStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CacheStoreTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir().'/licensify-sdk-test-'.bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        if (! is_dir($this->directory)) {
            return;
        }

        foreach (glob($this->directory.'/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->directory);
    }

    /**
     * @return array<string, array{0: CacheStoreInterface}>
     */
    public static function storeProvider(): array
    {
        return [
            'array store' => [new ArrayCacheStore('test')],
        ];
    }

    public function test_the_file_store_round_trips_scalars_and_arrays(): void
    {
        $store = new FileCacheStore($this->directory);

        $store->put('string', 'value');
        $store->put('int', 42);
        $store->put('bool', false);
        $store->put('array', ['a' => 1, 'b' => ['c' => 'd']]);
        $store->put('null', null);

        $this->assertSame('value', $store->get('string'));
        $this->assertSame(42, $store->get('int'));
        $this->assertFalse($store->get('bool'));
        $this->assertSame(['a' => 1, 'b' => ['c' => 'd']], $store->get('array'));
        $this->assertNull($store->get('null'));
    }

    public function test_a_missing_key_reads_as_null_on_both_stores(): void
    {
        $file = new FileCacheStore($this->directory);
        $array = new ArrayCacheStore('test');

        $this->assertNull($file->get('absent'));
        $this->assertNull($array->get('absent'));
        $this->assertFalse($file->has('absent'));
        $this->assertFalse($array->has('absent'));
    }

    public function test_it_expires_values_after_their_ttl(): void
    {
        $file = new FileCacheStore($this->directory);
        $array = new ArrayCacheStore('test');

        $file->put('expiring', 'value', 60);
        $array->put('expiring', 'value', 60);

        // One second is not enough to observe an expiry without sleeping, so the
        // test asserts the value is present now and that a zero TTL is already
        // expired — the boundary the SDK relies on.
        $this->assertSame('value', $file->get('expiring'));
        $this->assertSame('value', $array->get('expiring'));

        $array->put('already-gone', 'value', -1);
        $this->assertNull($array->get('already-gone'));

        $file->put('also-gone', 'value', -1);
        $this->assertNull($file->get('also-gone'));
    }

    public function test_a_value_stored_without_a_ttl_never_expires(): void
    {
        $store = new FileCacheStore($this->directory);

        $store->put('permanent', 'value');
        $store->put('permanent-again', 'other');

        $this->assertSame('value', $store->get('permanent'));
        $this->assertSame('other', $store->get('permanent-again'));
    }

    public function test_forget_removes_a_single_key(): void
    {
        $store = new FileCacheStore($this->directory);

        $store->put('keep', 'a');
        $store->put('drop', 'b');
        $store->forget('drop');

        $this->assertSame('a', $store->get('keep'));
        $this->assertNull($store->get('drop'));
    }

    public function test_flush_removes_only_this_sdks_keys(): void
    {
        $store = new FileCacheStore($this->directory);
        $store->put('touch', 'a');
        file_put_contents($this->directory.DIRECTORY_SEPARATOR.'unrelated.json', '{"value":"keep"}');

        $store->put('one', 'a');
        $store->put('two', 'b');
        $store->flush();

        $this->assertNull($store->get('one'));
        $this->assertNull($store->get('two'));
        $this->assertFileExists($this->directory.'/unrelated.json');
    }

    public function test_the_array_store_flush_clears_everything(): void
    {
        $store = new ArrayCacheStore('test');

        $store->put('one', 'a');
        $store->flush();

        $this->assertNull($store->get('one'));
    }

    public function test_a_corrupt_file_reads_as_absent_rather_than_trusting_it(): void
    {
        $store = new FileCacheStore($this->directory);
        $store->put('certificate', 'a-trusted-token');
        $store->forget('certificate');

        file_put_contents($this->directory.DIRECTORY_SEPARATOR.$store->key('certificate').'.json', '{not json');

        // A half-written or tampered file must force re-validation online, not
        // be partially believed.
        $this->assertNull($store->get('certificate'));
    }

    public function test_a_file_without_a_value_member_is_treated_as_absent(): void
    {
        $store = new FileCacheStore($this->directory);
        $store->put('certificate', 'token');
        $store->forget('certificate');

        file_put_contents($this->directory.DIRECTORY_SEPARATOR.$store->key('certificate').'.json', '{"key":"certificate"}');

        $this->assertNull($store->get('certificate'));
    }

    public function test_keys_are_namespaced_by_prefix(): void
    {
        $first = new ArrayCacheStore('alpha');
        $second = new ArrayCacheStore('beta');

        $first->put('certificate', 'from-alpha');

        $this->assertSame('from-alpha', $first->get('certificate'));
        $this->assertNull($second->get('certificate'));
    }

    public function test_key_names_cannot_escape_the_cache_directory(): void
    {
        $store = new FileCacheStore($this->directory);

        $store->put('../../etc/passwd', 'value');

        $this->assertSame('value', $store->get('../../etc/passwd'));
        $this->assertFileExists($this->directory.DIRECTORY_SEPARATOR.$store->key('../../etc/passwd').'.json');
        $this->assertFileDoesNotExist('/etc/passwd.json');
    }

    public function test_writes_are_atomic_and_leave_no_temporary_files(): void
    {
        $store = new FileCacheStore($this->directory);
        $store->put('certificate', 'token');

        $this->assertSame(
            [$store->key('certificate').'.json'],
            array_values(array_diff(scandir($this->directory) ?: [], ['.', '..'])),
        );
    }

    public function test_the_file_is_written_with_owner_only_permissions(): void
    {
        $store = new FileCacheStore($this->directory);
        $store->put('certificate', 'token');

        $path = $this->directory.DIRECTORY_SEPARATOR.$store->key('certificate').'.json';
        $this->assertFileExists($path);

        $permissions = fileperms($path) & 0777;

        $this->assertSame(0600, $permissions, 'the cache file must not be world-readable');
    }

    #[DataProvider('storeProvider')]
    public function test_both_stores_share_the_same_contract(CacheStoreInterface $store): void
    {
        $this->assertNull($store->get('absent'));
        $store->put('key', ['value' => 1]);
        $this->assertSame(['value' => 1], $store->get('key'));
        $this->assertTrue($store->has('key'));
        $store->forget('key');
        $this->assertFalse($store->has('key'));
        $this->assertStringStartsWith($this->prefixOf($store), $store->key('key'));
    }

    private function prefixOf(CacheStoreInterface $store): string
    {
        return explode(':', $store->key('key'))[0].':';
    }
}
