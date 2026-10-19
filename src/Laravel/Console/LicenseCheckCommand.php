<?php

declare(strict_types=1);

namespace Licensify\Client\Laravel\Console;

use Illuminate\Console\Command;
use Licensify\Client\Exception\LicenseException;
use Licensify\Client\LicenseManager;

/**
 * `php artisan license:check` — the command an operator reaches for when a
 * customer reports "it says my licence is invalid".
 *
 * Exits non-zero whenever the licence cannot be proven, so it is usable as a
 * deployment gate or a monitoring probe.
 */
final class LicenseCheckCommand extends Command
{
    protected $signature = 'license:check
        {--force : Skip the cached certificate and contact the server}
        {--json : Emit machine-readable output}';

    protected $description = 'Verify this installation\'s licence against the licensing server.';

    public function handle(LicenseManager $manager): int
    {
        try {
            $status = $manager->validate((bool) $this->option('force'));
        } catch (LicenseException $e) {
            $this->report([
                'valid' => false,
                'error_code' => $e->errorCode(),
                'message' => $e->getMessage(),
            ]);

            return self::FAILURE;
        }

        $payload = $status->toArray() + [
            'installation_id' => $manager->installationId(),
            'grace_expires_at' => $status->graceExpiresAt?->format(DATE_ATOM),
            'grace_expires_in_human' => $status->graceExpiresIn(),
            'offline_days_remaining' => $status->offlineDaysRemaining(),
            'context' => $manager->context(),
            'trusted_keys' => array_keys($manager->keyring()->all()),
        ];

        $this->report($payload);

        return $status->valid ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function report(array $payload): void
    {
        if ($this->option('json')) {
            $this->line((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return;
        }

        foreach ($payload as $key => $value) {
            $this->line(sprintf(
                '%-24s %s',
                $key.':',
                is_scalar($value) || $value === null
                    ? var_export($value, true)
                    : (string) json_encode($value, JSON_UNESCAPED_SLASHES),
            ));
        }

        // A human reading this needs the headline first, not after 20 lines.
        $this->newLine();
        $this->line($payload['valid'] === true ? 'Licence is valid.' : 'Licence is NOT valid.');
    }
}
