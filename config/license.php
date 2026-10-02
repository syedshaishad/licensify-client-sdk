<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Server
    |--------------------------------------------------------------------------
    |
    | The licensing server this installation talks to. HTTPS is required except
    | on loopback, so a misconfigured URL fails loudly instead of putting the
    | licence key and API secret on the wire in clear text.
    |
    */

    'server_url' => env('LICENSE_SERVER_URL'),

    'product_code' => env('LICENSE_PRODUCT_CODE'),

    'license_key' => env('LICENSE_KEY'),

    /*
    |--------------------------------------------------------------------------
    | API authentication
    |--------------------------------------------------------------------------
    |
    | A licence key is never authentication — it is the subject being
    | authorised. The API key authenticates the calling product. Leave these
    | unset for an unauthenticated server; the SDK then sends no credentials
    | rather than a malformed header.
    |
    */

    'api_key' => env('LICENSE_API_KEY'),

    'api_secret' => env('LICENSE_API_SECRET'),

    /** 'hmac' (recommended) or 'bearer'. */
    'auth_scheme' => env('LICENSE_AUTH_SCHEME', 'hmac'),

    /*
    |--------------------------------------------------------------------------
    | Certificate trust
    |--------------------------------------------------------------------------
    |
    | The server's Ed25519 public key. `public_key_id` binds it to one `kid`;
    | leaving it null trusts the key for whichever `kid` the server names, which
    | is what makes a key rotation survivable. When unset, only the SDK's
    | unusable placeholder is trusted and certificates are fetched from
    | GET /api/v1/products/{code}/public-key.
    |
    */

    'public_key' => env('LICENSE_PUBLIC_KEY'),

    'public_key_id' => env('LICENSE_PUBLIC_KEY_ID'),

    /*
    |--------------------------------------------------------------------------
    | Offline grace
    |--------------------------------------------------------------------------
    |
    | The grace window is server-controlled and readable from the certificate
    | (contract §5.3). `grace_override` is an operator escape hatch for
    | *tightening* the window locally, e.g. to force daily re-validation.
    |
    */

    'grace_override' => env('LICENSE_GRACE_OVERRIDE') !== null
        ? (int) env('LICENSE_GRACE_OVERRIDE')
        : null,

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    |
    | The only writable surface. Nothing outside the cache adapter is written,
    | and a deleted cache is fail-closed: it forces re-validation rather than
    | granting access. `store` is 'file' or any CacheStoreInterface
    | implementation you bind.
    |
    */

    'cache_path' => env('LICENSE_CACHE_PATH'),

    'store' => env('LICENSE_CACHE_STORE', 'file'),

    /*
    |--------------------------------------------------------------------------
    | Transport
    |--------------------------------------------------------------------------
    |
    | Explicit timeouts on every request, and TLS verification on by default.
    | Turning verification off exposes the API secret; it exists only for a
    | developer pointing the SDK at a local server with a self-signed
    | certificate.
    |
    */

    'timeout' => (float) env('LICENSE_TIMEOUT', 10),

    'connect_timeout' => (float) env('LICENSE_CONNECT_TIMEOUT', 5),

    'verify_ssl' => filter_var(env('LICENSE_VERIFY_SSL', true), FILTER_VALIDATE_BOOL),

    /*
    |--------------------------------------------------------------------------
    | Local policy
    |--------------------------------------------------------------------------
    |
    | `domain` overrides detection from $_SERVER['HTTP_HOST']; `version`
    | overrides detection from a constant or composer.json. `allow_localhost`
    | permits loopback and development hostnames, which are never trusted
    | implicitly (contract §6.8).
    |
    */

    'domain' => env('LICENSE_DOMAIN'),

    'version' => env('LICENSE_VERSION'),

    'allow_localhost' => filter_var(env('LICENSE_ALLOW_LOCALHOST', false), FILTER_VALIDATE_BOOL),

    /*
    |--------------------------------------------------------------------------
    | Middleware
    |--------------------------------------------------------------------------
    */

    'middleware' => [
        'enabled' => filter_var(env('LICENSE_MIDDLEWARE_ENABLED', true), FILTER_VALIDATE_BOOL),

        /** Routes the middleware never guards, e.g. health checks. */
        'except' => [
            'health',
            'up',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    |
    | The SDK never logs the licence key or the API secret. When logging is on,
    | only the installation id, product code and outcome are recorded.
    |
    */

    'logging' => [
        'enabled' => filter_var(env('LICENSE_LOGGING_ENABLED', false), FILTER_VALIDATE_BOOL),
        'channel' => env('LICENSE_LOG_CHANNEL'),
    ],

];
