<?php

declare(strict_types=1);

namespace Licensify\Client\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Licensify\Client\Exception\GraceExpiredException;
use Licensify\Client\Exception\LicenseException;
use Licensify\Client\LicenseManager;
use Licensify\Client\LicenseStatus;
use Symfony\Component\HttpFoundation\Response;

/**
 * Blocks a request unless the licence is currently valid.
 *
 * Failure is a 403 with a machine-readable reason, never a redirect to a login
 * page and never a pass: a customer whose grace window has closed has to stop.
 */
final readonly class EnsureLicenseIsValid
{
    public function __construct(private LicenseManager $manager) {}

    public function handle(Request $request, Closure $next): Response
    {
        $force = (bool) $request->boolean('license_force_refresh');

        try {
            $status = $this->manager->validate($force);
        } catch (LicenseException $e) {
            return $this->deny($e->errorCode() ?? 'LICENSE_UNAVAILABLE', $e->getMessage());
        }

        if (! $status->valid) {
            return $this->deny($status->errorCode ?? 'LICENSE_INVALID', $status->message);
        }

        return $next($request);
    }

    private function deny(string $code, string $message): Response
    {
        $expired = $code === 'LICENSE_GRACE_EXPIRED' || $code === 'NO_VALID_CERTIFICATE';

        return new JsonResponse([
            'success' => false,
            'error' => [
                'code' => $code,
                // The two grace conditions get an actionable message; the rest
                // get the server's own wording.
                'message' => $expired
                    ? 'The license could not be verified. Connect this installation to the licensing server to restore access.'
                    : $message,
                'grace_expired' => $expired,
            ],
        ], Response::HTTP_FORBIDDEN);
    }

    /**
     * The status a request was admitted under, for downstream consumers.
     */
    public function status(): ?LicenseStatus
    {
        try {
            return $this->manager->validate();
        } catch (GraceExpiredException|LicenseException) {
            return null;
        }
    }
}
