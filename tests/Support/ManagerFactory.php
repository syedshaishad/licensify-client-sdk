<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Support;

use Licensify\Client\Cache\ArrayCacheStore;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Support\Configuration;

/**
 * Assembles a fully offline {@see LicenseManager} for tests: array cache,
 * frozen clock, fake transport and an explicit keyring.
 */
final class ManagerFactory
{
    public const INSTALLATION_ID = 'inst_0000000000000000000000000000abcd';

    public const PRODUCT_CODE = 'MYCRM';

    /**
     * @param  array<string, mixed>  $overrides
     */
    public static function configuration(array $overrides = []): Configuration
    {
        return Configuration::fromArray(array_merge([
            'server_url' => 'https://licensing.test',
            'product_code' => self::PRODUCT_CODE,
            'license_key' => 'AAAA-BBBB-CCCC-DDDD-EEEE',
            'api_key' => 'lk_test',
            'api_secret' => 'cs_test_secret',
            'domain' => 'example.com',
            'version' => '2.4.1',
        ], $overrides));
    }

    /**
     * @param  array<string, mixed>  $configuration
     */
    public static function make(
        FakeTransport $transport,
        FrozenClock $clock,
        array $configuration = [],
        ?Keyring $keyring = null,
    ): LicenseManager {
        $manager = new LicenseManager(self::configuration($configuration));
        $manager->setTransport($transport)
            ->setClock($clock)
            ->setCache(new ArrayCacheStore('test'))
            ->setKeyring($keyring ?? Keyring::bootstrap());

        // Pin the installation id so certificates minted by the factory bind to
        // this installation rather than to a fresh random one. The store applies
        // its own prefix, so the key is passed unprefixed as InstallationId does.
        $manager->cache()->put('installation-id', self::INSTALLATION_ID);

        return $manager;
    }

    /**
     * The §1.3 flat validate body a live server returns.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public static function validateResponse(string $certificate, array $overrides = []): array
    {
        return array_merge([
            'success' => true,
            'valid' => true,
            'status' => 'active',
            'product' => self::PRODUCT_CODE,
            'license_type' => 'subscription',
            'expires_at' => '2027-12-31',
            'installation_id' => self::INSTALLATION_ID,
            'domain' => 'example.com',
            'update_available' => false,
            'offline_until' => gmdate('c', time() + 259200),
            'grace_expires_in' => 259200,
            'certificate' => $certificate,
            'public_key_id' => 'key_test',
            'meta' => ['request_id' => 'req_test'],
        ], $overrides);
    }

    /**
     * The §1.1 success envelope around a data object.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public static function envelope(array $data): array
    {
        return [
            'success' => true,
            'data' => $data,
            'meta' => ['request_id' => 'req_test'],
        ];
    }
}
