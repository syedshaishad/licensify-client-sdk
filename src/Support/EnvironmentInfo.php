<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Illuminate\Foundation\Application;

/**
 * Facts about the machine running the licensed software, sent alongside
 * activation and validation so the operator can see the install context.
 *
 * Nothing here is secret and nothing here is trusted by the server for a
 * decision: it exists for support and triage.
 */
final class EnvironmentInfo
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'php_version' => $this->phpVersion(),
            'laravel_version' => $this->laravelVersion(),
            'sapi' => PHP_SAPI,
            'os' => $this->os(),
            'server_software' => $this->serverSoftware(),
            'architecture' => php_uname('m'),
        ];
    }

    public function phpVersion(): string
    {
        return PHP_VERSION;
    }

    /**
     * The Laravel version, when the SDK happens to run inside a Laravel app.
     * Reflection is used rather than a hard class reference so the package
     * stays framework-agnostic and has no Laravel dependency.
     */
    public function laravelVersion(): ?string
    {
        if (! class_exists(Application::class)) {
            return null;
        }

        try {
            $constant = new \ReflectionClass(Application::class);
            $value = $constant->getConstant('VERSION');
        } catch (\ReflectionException) {
            return null;
        }

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function serverSoftware(): ?string
    {
        $value = $_SERVER['SERVER_SOFTWARE'] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array{os: string, os_family: string}
     */
    public function os(): array
    {
        return [
            'os' => PHP_OS,
            'os_family' => PHP_OS_FAMILY,
        ];
    }
}
