<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Cache\ArrayCacheStore;
use Licensify\Client\Cache\FileCacheStore;
use Licensify\Client\Support\InstallationId;
use PHPUnit\Framework\TestCase;

final class InstallationIdTest extends TestCase
{
    private ArrayCacheStore $cache;

    private InstallationId $installationId;

    protected function setUp(): void
    {
        $this->cache = new ArrayCacheStore('test');
        $this->installationId = new InstallationId($this->cache);
    }

    public function test_it_generates_a_contract_shaped_identifier(): void
    {
        $id = $this->installationId->resolve();

        $this->assertMatchesRegularExpression('/^inst_[a-f0-9]{32}$/', $id);
        $this->assertTrue(InstallationId::isWellFormed($id));
    }

    public function test_it_is_stable_across_calls(): void
    {
        // Regenerating would let one customer consume unlimited activations,
        // because the server counts activations per installation id.
        $first = $this->installationId->resolve();

        $this->assertSame($first, $this->installationId->resolve());
        $this->assertSame($first, $this->installationId->resolve());
    }

    public function test_the_identifier_is_persisted_in_the_store(): void
    {
        $id = $this->installationId->resolve();

        $fresh = new InstallationId($this->cache);

        $this->assertSame($id, $fresh->resolve());
        $this->assertSame($id, $this->cache->get('installation-id'));
    }

    public function test_peek_reports_none_before_the_first_resolve(): void
    {
        $this->assertNull($this->installationId->peek());

        $id = $this->installationId->resolve();

        $this->assertSame($id, $this->installationId->peek());
    }

    public function test_a_malformed_stored_value_is_replaced_rather_than_reused(): void
    {
        $this->cache->put('installation-id', 'not-an-installation-id');

        $id = $this->installationId->resolve();

        $this->assertTrue(InstallationId::isWellFormed($id));
    }

    public function test_forget_discards_it(): void
    {
        $first = $this->installationId->resolve();
        $this->installationId->forget();

        $this->assertNull($this->installationId->peek());
        $this->assertNotSame($first, $this->installationId->resolve());
    }

    public function test_generated_identifiers_are_unique(): void
    {
        $identifiers = [];

        for ($i = 0; $i < 100; $i++) {
            $identifiers[] = InstallationId::generate();
        }

        $this->assertCount(100, array_unique($identifiers));
    }

    public function test_validation_rejects_the_wrong_shape(): void
    {
        $this->assertFalse(InstallationId::isWellFormed('inst_'));
        $this->assertFalse(InstallationId::isWellFormed('inst_ABCD'));
        $this->assertFalse(InstallationId::isWellFormed(str_repeat('a', 37)));
        $this->assertFalse(InstallationId::isWellFormed('inst_'.$this->tooLong()));
        $this->assertTrue(InstallationId::isWellFormed('inst_'.str_repeat('a', 32)));
    }

    public function test_it_survives_a_file_store_round_trip(): void
    {
        $directory = sys_get_temp_dir().'/licensify-inst-'.bin2hex(random_bytes(6));
        $store = new FileCacheStore($directory);

        try {
            $first = (new InstallationId($store))->resolve();
            $second = (new InstallationId($store))->resolve();

            $this->assertSame($first, $second);
        } finally {
            $store->flush();
            @rmdir($directory);
        }
    }

    private function tooLong(): string
    {
        return str_repeat('f', 33);
    }
}
