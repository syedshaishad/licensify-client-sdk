<?php

declare(strict_types=1);

namespace Licensify\Client\Exception;

/**
 * The SDK is not configured well enough to contact the server: missing server
 * URL, product code or license key, or an unusable cached environment value.
 */
class ConfigurationException extends LicenseException
{
    /**
     * @param  array<string, mixed>  $values
     */
    public static function missingEnvironment(array $values): self
    {
        $names = implode(', ', $values);

        return new self(
            sprintf('Missing required licence SDK configuration: %s.', $names),
            'SDK_NOT_CONFIGURED',
            ['missing' => $values],
        );
    }
}
