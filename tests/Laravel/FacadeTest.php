<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel;

use Illuminate\Support\Facades\Facade;
use Licensify\Client\Laravel\Facades\License;
use Licensify\Client\Laravel\LicenseServiceProvider;
use Licensify\Client\LicenseManager;
use Licensify\Client\Tests\Laravel\Support\TestApplication;
use PHPUnit\Framework\TestCase;

/**
 * The facade is what a Laravel application actually calls.
 *
 * It has to resolve the manager the provider bound, and it has to keep
 * pointing at the container's instance — a facade that cached its own copy
 * would quietly ignore the application's cache and configuration.
 */
final class FacadeTest extends TestCase
{
    private TestApplication $app;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app = new TestApplication;
        $this->app->withConfig([
            'license' => [
                'server_url' => 'https://licensing.test',
                'product_code' => 'MYCRM',
                'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            ],
        ]);

        Facade::setFacadeApplication($this->app);
        Facade::clearResolvedInstances();
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        parent::tearDown();
    }

    public function test_it_resolves_the_bound_manager(): void
    {
        (new LicenseServiceProvider($this->app))->register();

        $this->assertInstanceOf(LicenseManager::class, License::getFacadeRoot());
    }

    public function test_it_resolves_the_same_instance_the_container_holds(): void
    {
        (new LicenseServiceProvider($this->app))->register();

        $this->assertSame($this->app->make(LicenseManager::class), License::getFacadeRoot());
    }

    public function test_the_provider_clears_a_stale_facade_instance(): void
    {
        (new LicenseServiceProvider($this->app))->register();

        // Resolve it once, so a cached instance exists.
        $first = License::getFacadeRoot();

        // A second registration, as happens when the application reboots.
        (new LicenseServiceProvider($this->app))->register();

        $this->assertNotSame($first, License::getFacadeRoot());
        $this->assertSame($this->app->make(LicenseManager::class), License::getFacadeRoot());
    }
}
