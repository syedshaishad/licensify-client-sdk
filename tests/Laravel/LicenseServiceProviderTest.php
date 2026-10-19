<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Licensify\Client\Laravel\LaravelCacheStore;
use Licensify\Client\Laravel\LicenseServiceProvider;
use Licensify\Client\LicenseManager;
use Licensify\Client\Support\Configuration;
use Licensify\Client\Tests\Laravel\Support\TestApplication;
use PHPUnit\Framework\TestCase;

/**
 * The bridge's job is to make the SDK usable from a Laravel application.
 *
 * These are the parts a customer actually touches: the container bindings, the
 * configuration, and the alias the middleware and the facade resolve.
 */
final class LicenseServiceProviderTest extends TestCase
{
    public function test_it_binds_the_manager(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        $this->assertInstanceOf(LicenseManager::class, $app->make(LicenseManager::class));
    }

    public function test_the_manager_is_a_singleton(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        $this->assertSame($app->make(LicenseManager::class), $app->make(LicenseManager::class));
    }

    public function test_the_alias_resolves_to_the_manager(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        $this->assertSame($app->make(LicenseManager::class), $app->make('license'));
    }

    public function test_it_binds_the_configuration(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        $this->assertInstanceOf(Configuration::class, $app->make(Configuration::class));
    }

    public function test_it_merges_the_package_configuration(): void
    {
        $app = new TestApplication;

        (new LicenseServiceProvider($app))->register();

        // The shipped defaults are merged in, so an application that publishes
        // the config file is not required for the SDK to work.
        $config = $app->make('config')->get('license');

        $this->assertIsArray($config);
        $this->assertArrayHasKey('server_url', $config);
        $this->assertArrayHasKey('product_code', $config);
    }

    public function test_it_uses_the_applications_cache_when_there_is_one(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        // What Laravel registers: a repository under 'cache.store', with the
        // contract as an alias of it.
        $app->instance('cache.store', new Repository(new ArrayStore));
        $app->alias('cache.store', CacheRepository::class);

        (new LicenseServiceProvider($app))->register();

        $this->assertInstanceOf(
            LaravelCacheStore::class,
            $app->make(LicenseManager::class)->cache(),
            'the application cache was not used',
        );
    }

    public function test_it_falls_back_to_its_own_cache_when_there_is_none(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        // A container answers `bound()` with true for an alias whether or not
        // the aliased service was registered, so a provider that asked for the
        // contract would try to build a cache that is not there.
        $this->assertNotInstanceOf(
            LaravelCacheStore::class,
            $app->make(LicenseManager::class)->cache(),
        );
    }

    public function test_an_applications_own_values_win(): void
    {
        $app = new TestApplication;
        $app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.example.com',
            ],
        ]);

        (new LicenseServiceProvider($app))->register();

        $this->assertSame(
            'https://licensing.example.com',
            $app->make('config')->get('license.server_url'),
        );
    }
}
