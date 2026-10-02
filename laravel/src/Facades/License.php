<?php

declare(strict_types=1);

namespace Licensify\Client\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use Licensify\Client\LicenseManager;
use Licensify\Client\LicenseStatus;
use Licensify\Client\UpdateInfo;

/**
 * Laravel facade over the bound {@see LicenseManager}.
 *
 * Every method mirrors the static core API, so `Licensify\Client\Laravel\Facades\License`
 * is a drop-in replacement for `Licensify\Client\License` in a Laravel app.
 *
 * @method static LicenseStatus validate(bool $force = false)
 * @method static LicenseStatus activate()
 * @method static bool deactivate(?string $reason = null)
 * @method static LicenseStatus status()
 * @method static UpdateInfo|null updateAvailable()
 * @method static bool valid()
 * @method static string|null certificate()
 * @method static \DateTimeImmutable|null graceExpiresAt()
 * @method static int offlineDaysRemaining()
 * @method static void expireCache()
 * @method static void clearAll()
 * @method static \Licensify\Client\Security\Keyring keyring()
 * @method static string installationId()
 * @method static array context()
 *
 * @see LicenseManager
 */
final class License extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return LicenseManager::class;
    }
}
