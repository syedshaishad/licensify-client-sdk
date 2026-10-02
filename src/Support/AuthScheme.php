<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

/**
 * How the SDK proves its identity to the API (contract §3).
 *
 * A license key is never authentication — it is the *subject* being
 * authorised. The API key authenticates the calling product.
 */
enum AuthScheme: string
{
    /** Request signing: the production default. */
    case Hmac = 'hmac';

    /** `Authorization: Bearer <api_key>.<api_secret>`, for direct/curl use. */
    case Bearer = 'bearer';

    public function label(): string
    {
        return match ($this) {
            self::Hmac => 'HMAC request signing',
            self::Bearer => 'Bearer API key',
        };
    }
}
