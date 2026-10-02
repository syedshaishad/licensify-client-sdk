<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Support;

use DateTimeImmutable;
use DateTimeZone;
use Licensify\Client\Support\Clock;

/**
 * A clock the test controls, so grace windows and revocation counters can be
 * exercised without sleeping.
 */
final class FrozenClock implements Clock
{
    public function __construct(private int $timestamp) {}

    public function now(): int
    {
        return $this->timestamp;
    }

    public function dateTime(): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.$this->timestamp, new DateTimeZone('UTC'));
    }

    public function advance(int $seconds): self
    {
        $this->timestamp += $seconds;

        return $this;
    }

    public function set(int $timestamp): self
    {
        $this->timestamp = $timestamp;

        return $this;
    }
}
