<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

/**
 * Injectable clock so grace-window and revocation-counter behaviour can be
 * tested without sleeping.
 */
interface Clock
{
    /** Unix timestamp in seconds. */
    public function now(): int;

    /**
     * The same instant as an immutable date object, always in UTC.
     */
    public function dateTime(): \DateTimeImmutable;
}
