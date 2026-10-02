<?php

declare(strict_types=1);

namespace Licensify\Client;

use DateTimeImmutable;
use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Support\Configuration;

/**
 * The public entry point (contract §10).
 *
 * A thin static facade over {@see LicenseManager}: every call is forwarded, so
 * there is no logic here that could disagree with the injectable manager. For
 * testability, dependency injection or a per-request configuration, build a
 * {@see LicenseManager} yourself and call it directly.
 *
 *     License::validate()->valid;          // throws when it cannot be proven
 *     License::valid();                     // never throws; false means deny
 *     License::trustKey('key_2026_01', $publicKeyB64);
 */
final class License
{
    private static ?LicenseManager $manager = null;

    /**
     * The shared manager, built from the environment on first use.
     *
     * @throws ConfigurationException
     */
    public static function manager(): LicenseManager
    {
        return self::$manager ??= new LicenseManager;
    }

    /**
     * Installs a pre-built manager, replacing the environment-derived one. The
     * Laravel bridge and tests use this.
     */
    public static function swap(?LicenseManager $manager): void
    {
        self::$manager = $manager;
    }

    /**
     * Builds and installs a manager from explicit configuration.
     *
     * @throws ConfigurationException
     */
    public static function configure(Configuration $config): LicenseManager
    {
        return self::swap(new LicenseManager($config)) ?? self::manager();
    }

    /**
     * Trusts an additional Ed25519 public key for a `kid`.
     *
     * Call this *before* a server-side rotation starts signing, so no
     * certificate is ever unverifiable (contract §5.1).
     *
     * @throws ConfigurationException
     */
    public static function trustKey(string $kid, string $publicKey): void
    {
        self::manager()->trustKey($kid, $publicKey);
    }

    /**
     * Validates the licence, using the cached certificate while it is inside
     * its grace window and contacting the server otherwise.
     *
     * `$force` forces a fresh online check (contract §5.3).
     *
     * @throws LicenseException
     */
    public static function validate(bool $force = false): LicenseStatus
    {
        return self::manager()->validate($force);
    }

    /**
     * Activates this installation. Idempotent (contract §7.7).
     *
     * @throws LicenseException
     */
    public static function activate(): LicenseStatus
    {
        return self::manager()->activate();
    }

    /**
     * Deactivates this installation and destroys the cached certificate.
     *
     * @throws LicenseException
     */
    public static function deactivate(?string $reason = null): bool
    {
        return self::manager()->deactivate($reason);
    }

    /**
     * Licence-level state; takes no installation and yields no certificate.
     *
     * @throws LicenseException
     */
    public static function status(): LicenseStatus
    {
        return self::manager()->status();
    }

    /**
     * Release information, or null when nothing newer is published.
     *
     * @throws LicenseException
     */
    public static function updateAvailable(): ?UpdateInfo
    {
        return self::manager()->updateAvailable();
    }

    /**
     * May this installation run? Never throws — an unreachable server or an
     * untrusted certificate is a `false`, never a `true` (contract §53).
     */
    public static function valid(): bool
    {
        return self::manager()->valid();
    }

    /**
     * The cached compact certificate token, for diagnostics. Not proof on its
     * own: it is only meaningful together with a successful `valid()`.
     */
    public static function certificate(): ?string
    {
        return self::manager()->certificate();
    }

    /**
     * When the cached certificate's grace window closes.
     */
    public static function graceExpiresAt(): ?DateTimeImmutable
    {
        return self::manager()->graceExpiresAt();
    }

    /**
     * Whole days of grace left (contract §5.3).
     */
    public static function offlineDaysRemaining(): int
    {
        return self::manager()->offlineDaysRemaining();
    }

    /**
     * Drops the cached certificate. This does **not** grant access: the next
     * call re-validates against the server, and an unreachable server means
     * refused (contract §5.2).
     */
    public static function expireCache(): void
    {
        self::manager()->expireCache();
    }

    /**
     * The trusted keyring, for a diagnostics screen.
     */
    public static function keyring(): Keyring
    {
        return self::manager()->keyring();
    }
}
