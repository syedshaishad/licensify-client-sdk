<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel\Support;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;

/**
 * The smallest thing the bridge can be registered against.
 *
 * The bridge is meant to work inside a full Laravel application, but it does
 * not need one: it needs a container, a configuration repository and the two
 * answers the provider asks for. Building the whole framework to test a
 * service provider would test the framework instead.
 */
final class TestApplication extends Container
{
    public function __construct(private bool $console = false)
    {
        $this->instance('config', new Repository([
            'license' => [],
        ]));
    }

    /**
     * Laravel's answer to "are we running from a terminal", which the
     * provider asks before registering the artisan command.
     */
    public function runningInConsole(): bool
    {
        return $this->console;
    }

    public function runningUnitTests(): bool
    {
        return true;
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public function withConfig(array $values): self
    {
        $this->instance('config', new Repository($values));

        return $this;
    }
}
