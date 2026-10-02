<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

/**
 * How a normalised domain is classified (contract §6 step 7).
 *
 * Classification is descriptive only. `Localhost` and `Development` are never
 * implicitly trusted: honouring them is an explicit operator decision.
 */
enum DomainEnvironment: string
{
    case Production = 'production';
    case Subdomain = 'subdomain';
    case Localhost = 'localhost';
    case IpAddress = 'ip_address';
    case Development = 'development';

    /**
     * Hostnames that must never be trusted without an explicit opt-in.
     */
    public function isDevelopment(): bool
    {
        return in_array($this, [self::Localhost, self::Development], true);
    }

    public function isProduction(): bool
    {
        return in_array($this, [self::Production, self::Subdomain], true);
    }
}
