<?php

declare(strict_types=1);

namespace Licensify\Client\Laravel;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\ServiceProvider;
use Licensify\Client\LicenseManager;
use Licensify\Client\Support\Configuration;

/**
 * Wires the SDK into a Laravel application.
 *
 * Entirely optional: the core package has no Laravel dependency and works in
 * plain PHP. This bridge adds only container binding, config publishing, a
 * facade, a middleware and an artisan command.
 */
final class LicenseServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/license.php', 'license');

        // The configuration comes out of the container rather than the global
        // config() helper, which lives in the framework this package does not
        // require. The helper is only sugar over the same binding.
        $this->app->singleton(Configuration::class, fn (): Configuration => Configuration::fromArray(
            (array) $this->app->make('config')->get('license', []),
        ));

        $this->app->singleton(LicenseManager::class, function ($app): LicenseManager {
            $manager = new LicenseManager($app->make(Configuration::class));

            // The Laravel cache is preferred so a licence survives a deploy that
            // replaces local files. `config/license.cache_path` overrides it.
            //
            // The cache is asked for and a failure is not fatal. Laravel
            // registers the cache repository as an alias of 'cache.store', and
            // a container answers `bound()` with true for an alias whether or
            // not the aliased service was ever registered — so there is no
            // check that can tell the truth here. The SDK ships a file cache
            // of its own, and a licence that could not be stored in the
            // application's cache is better than an application that cannot
            // boot.
            try {
                $manager->setCache(new LaravelCacheStore($app->make(CacheRepository::class)));
            } catch (\Throwable) {
                // No cache in this application. The SDK's own is used instead.
            }

            return $manager;
        });

        $this->app->alias(LicenseManager::class, 'license');

        // Keep the static facade pointing at the container's instance, so the
        // injected cache and configuration are what `License::` calls use.
        Facades\License::clearResolvedInstance(LicenseManager::class);
    }

    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../../config/license.php' => $this->app->configPath('license.php'),
        ], 'licensify-config');

        $this->commands([
            Console\LicenseCheckCommand::class,
        ]);
    }
}
