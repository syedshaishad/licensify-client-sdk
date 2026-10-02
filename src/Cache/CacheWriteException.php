<?php

declare(strict_types=1);

namespace Licensify\Client\Cache;

use Licensify\Client\Exception\LicenseException;

/**
 * The cache directory exists but cannot be written to.
 *
 * Separate from the licensing failures on purpose: an unwritable cache is an
 * environment problem, and the operator needs to hear about it rather than
 * silently lose their offline grace window.
 */
final class CacheWriteException extends LicenseException
{
    public function __construct(string $message)
    {
        parent::__construct($message, 'CACHE_NOT_WRITABLE');
    }
}
