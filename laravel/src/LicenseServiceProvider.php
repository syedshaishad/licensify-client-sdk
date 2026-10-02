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

        $this->app->singleton(Configuration::class, fn (): Configuration => Configuration::fromArray(
            (array) config('license', []),
        ));

        $this->app->singleton(LicenseManager::class, function ($app): LicenseManager {
            $manager = new LicenseManager($app->make(Configuration::class));

            // The Laravel cache is preferred so a licence survives a deploy that
            // replaces local files. `config/license.cache_path` overrides it.
            if ($app->bound(CacheRepository::class)) {
                $manager->setCache(new LaravelCacheStore($app->make(CacheRepository::class)));
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
