<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Wall-clock time, expressed in UTC. The SDK never calls `time()` directly so
 * that a `Clock` can be injected instead.
 */
final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }

    public function dateTime(): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.time(), new DateTimeZone('UTC'));
    }
}
