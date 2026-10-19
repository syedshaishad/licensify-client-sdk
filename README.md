# licensify/client-sdk

A framework-agnostic PHP client SDK for the Licensify licensing server.

It exists to make one thing hard for a customer to do: **use licensed software
without a valid licence.** Everything below follows from that.

- **Fail-closed, never fail-open.** No verifiable certificate plus an unreachable
  server means `valid()` is `false`. Deleting the cache does not grant access; it
  forces re-validation.
- **Offline grace is cryptographic.** Access survives a server outage for
  exactly as long as an Ed25519-signed certificate says it may.
- **The client cannot mint.** There is no signing code in `src/`. A forged or
  hand-edited certificate fails the signature check.

Zero runtime dependencies. Requires PHP 8.3+, `ext-sodium`, `ext-json` and
`ext-openssl`.

## Install

The package is published as its own repository so it can be installed without
the platform itself. Add the repository to your `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/syedshaishad/licensify-client-sdk.git"
        }
    ]
}
```

Then install it:

```bash
composer require licensify/client-sdk
```

To pin a particular release rather than tracking the branch:

```bash
composer require licensify/client-sdk:dev-main#<commit-sha>
```

### Without Composer

The SDK has no runtime dependencies, so the `src/` directory can be copied into
your project and autoloaded under the `Licensify\Client\` namespace if you
would rather not add a repository entry.

## Configure

All configuration comes from the environment. Nothing is hardcoded.

```dotenv
LICENSE_SERVER_URL=https://licensing.example.com
LICENSE_PRODUCT_CODE=MYCRM
LICENSE_KEY=AAAAA-BBBBB-CCCCC-DDDDD-EEEEE

# Optional: API credentials for the calling product. HMAC signing is the default.
LICENSE_API_KEY=lk_...
LICENSE_API_SECRET=...
LICENSE_PUBLIC_KEY=...            # the server's Ed25519 public key
LICENSE_PUBLIC_KEY_ID=key_2026_01 # optional; binds the key to one kid
LICENSE_AUTH_SCHEME=hmac          # or `bearer`
```

<details>
<summary>Optional settings</summary>

| Variable | Default | Purpose |
|---|---|---|
| `LICENSE_GRACE_OVERRIDE` | server-controlled | Tighten the offline window locally, in seconds |
| `LICENSE_CACHE_PATH` | `storage_path('licensify')` or the system temp dir | Where the certificate cache lives |
| `LICENSE_TIMEOUT` | `10` | Total request timeout, seconds |
| `LICENSE_CONNECT_TIMEOUT` | `5` | Connect timeout, seconds |
| `LICENSE_VERIFY_SSL` | `true` | TLS verification. Turning it off exposes the API secret |
| `LICENSE_ALLOW_LOCALHOST` | `false` | Permit loopback and development hostnames |
| `LICENSE_DOMAIN` | detected from `$_SERVER['HTTP_HOST']` | Override domain detection (needed for CLI/queues) |
| `LICENSE_VERSION` | detected from a constant or `composer.json` | Override version detection |

</details>

`LICENSE_SERVER_URL` must be `https` unless the host is loopback, which keeps a
misconfigured URL from putting the licence key and API secret on the wire in
clear text.

## Use

```php
use Licensify\Client\License;

// The gate. Never throws; false means deny.
if (! License::valid()) {
    abort(403, 'Licence could not be verified.');
}

// The detailed answer, including the grace window.
$status = License::validate();

$status->valid;                 // bool
$status->offline;               // true when answered from a cached certificate
$status->graceSecondsRemaining; // the real deadline when offline
$status->graceExpiresAt();      // DateTimeImmutable
$status->revocationCounter;     // per-licence state counter
```

`validate()` throws rather than guessing. Use it when you want to tell the
customer *why*; use `valid()` when you just need the gate.

```php
License::activate();              // idempotent; a repeat call is a success
License::deactivate('moving host');
License::status();                // licence-level state, no certificate
License::updateAvailable();       // ?UpdateInfo, semver-correct
License::certificate();           // the cached token, for diagnostics
License::offlineDaysRemaining();
License::expireCache();           // for support — does NOT grant access
License::trustKey($kid, $publicKeyBase64);
```

### Exceptions

```
LicenseException
├── ConfigurationException   misconfigured SDK
├── NetworkException        server unreachable or unusable response
├── VerificationException   certificate cannot be trusted (forged, wrong kid, stale rev)
└── GraceExpiredException   no verifiable certificate, or the window closed
```

Each carries the API's canonical `errorCode()` so you can branch on
`LICENSE_EXPIRED` rather than on message text.

## The Laravel bridge

Optional and not autoloaded by this package. Install
`licensify/client-sdk-laravel` for a service provider, a `License` facade,
`EnsureLicenseIsValid` middleware and `php artisan license:check`.

```php
Route::get('/reports', ReportController::class)->middleware(EnsureLicenseIsValid::class);
```

In a plain PHP app, or in tests, inject the manager directly — every collaborator
is replaceable:

```php
$manager = (new LicenseManager(Configuration::fromEnvironment()))
    ->setTransport($myTransport)
    ->setCache(new ArrayCacheStore)
    ->setClock($myClock)
    ->setKeyring($myKeyring);
```

## Trusting the server's signing key

The SDK ships one bootstrap key so the keyring is never empty. Its private half
exists nowhere, so no certificate signed by it can ever be forged — with nothing
else configured, an unreachable server means no access.

For a real deployment, do one of:

1. Set `LICENSE_PUBLIC_KEY` (and optionally `LICENSE_PUBLIC_KEY_ID`).
2. Call `License::trustKey($kid, $publicKeyB64)` at boot.
3. Let the SDK bootstrap from `GET /api/v1/products/{code}/public-key` when it
   first meets an unknown `kid`.

Several keys are held at once so a server-side rotation does not break
certificates already sitting in customer caches. For a clean rotation, add the
new key *before* the server starts signing with it.

## How the offline grace works

1. `validate()` succeeds online → the server's compact Ed25519 certificate is
   cached, along with the highest `rev` seen for this licence.
2. Later calls verify the cached certificate locally: signature against the
   trusted keyring, then `nbf`/`exp`, then the revocation counter, then that the
   certificate is bound to *this* product and *this* installation.
3. Inside the window, access is allowed with `offline = true` and the remaining
   seconds.
4. Past `exp`, access is refused (`GraceExpiredException`). `valid()` is `false`.

The `rev` counter is what bounds the damage from a compromised install: the
server bumps it on suspend, revoke, block, or a domain/activation-limit change,
and the SDK refuses any certificate older than one it already trusted. A
hand-edited cache cannot lower that floor.

## Development

```bash
composer install
composer test
```

## Licence

MIT. See [LICENSE](LICENSE).
