<?php

declare(strict_types=1);

namespace Licensify\Client;

use DateTimeImmutable;
use Licensify\Client\Cache\CacheStoreInterface;
use Licensify\Client\Cache\FileCacheStore;
use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Exception\GraceExpiredException;
use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Exception\VerificationException;
use Licensify\Client\Http\CurlTransport;
use Licensify\Client\Http\LicenseClient;
use Licensify\Client\Http\StreamTransport;
use Licensify\Client\Http\Transport;
use Licensify\Client\Security\Certificate;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Security\RequestSigner;
use Licensify\Client\Security\SignatureVerifier;
use Licensify\Client\Support\Clock;
use Licensify\Client\Support\Configuration;
use Licensify\Client\Support\DomainDetector;
use Licensify\Client\Support\EnvironmentInfo;
use Licensify\Client\Support\InstallationId;
use Licensify\Client\Support\SystemClock;
use Licensify\Client\Support\VersionDetector;

/**
 * The whole SDK, with every collaborator injectable (contract §10).
 *
 * The single rule this class exists to enforce: **fail closed, never open.** The
 * order of operations in {@see self::validate()} is deliberately
 *
 *     usable cached certificate → network → cached certificate again → refuse
 *
 * so a deleted or expired cache can only ever cost the customer their access.
 * There is no branch in which "could not check" turns into "allowed".
 *
 * Every collaborator has a default, so a plain-PHP consumer constructs it with
 * nothing but a {@see Configuration}, while a Laravel app or a test swaps in its
 * own transport, cache, clock and keyring.
 */
class LicenseManager
{
    protected Configuration $config;

    protected Transport $transport;

    protected CacheStoreInterface $cache;

    protected Clock $clock;

    protected Keyring $keyring;

    protected ?LicenseClient $client = null;

    protected DomainDetector $domains;

    protected VersionDetector $versions;

    protected EnvironmentInfo $environment;

    protected InstallationId $installationIds;

    /** @var array<string, string>|null Public keys fetched from the server this run. */
    protected ?array $fetchedKeyring = null;

    /**
     * Reject cached certificates this many seconds past `exp`. A small leeway
     * keeps ordinary clock drift from locking a paying customer out mid-window;
     * it can never extend a window by more than the clock's own uncertainty.
     */
    protected const EXPIRY_LEEWAY_SECONDS = 60;

    public function __construct(?Configuration $config = null)
    {
        $this->config = $config ?? Configuration::fromEnvironment();

        $this->clock = new SystemClock;
        $this->cache = FileCacheStore::default();
        $this->transport = $this->defaultTransport();
        $this->keyring = $this->bootstrapKeyring();
        $this->domains = new DomainDetector;
        $this->versions = VersionDetector::fromConfiguration($this->config);
        $this->environment = new EnvironmentInfo;
        $this->installationIds = new InstallationId($this->cache);
    }

    /**
     * Replaces the configuration in place. Intended for the framework bridge and
     * for tests; no public API call happens as a side effect.
     */
    public function setConfiguration(Configuration $config): static
    {
        $this->config = $config;
        $this->client = null;
        $this->versions = VersionDetector::fromConfiguration($config);

        return $this;
    }

    public function setTransport(Transport $transport): static
    {
        $this->transport = $transport;
        $this->client = null;

        return $this;
    }

    public function setCache(CacheStoreInterface $cache): static
    {
        $this->cache = $cache;
        $this->installationIds = new InstallationId($cache);

        return $this;
    }

    public function setClock(Clock $clock): static
    {
        $this->clock = $clock;

        return $this;
    }

    public function setKeyring(Keyring $keyring): static
    {
        $this->keyring = $keyring;

        return $this;
    }

    public function setDomainDetector(DomainDetector $domains): static
    {
        $this->domains = $domains;

        return $this;
    }

    public function setVersionDetector(VersionDetector $versions): static
    {
        $this->versions = $versions;

        return $this;
    }

    /**
     * Trusts an additional Ed25519 public key. Call this for a server-side key
     * rotation *before* the new key starts signing, so no certificate is ever
     * unverifiable (contract §5.1).
     *
     * @throws ConfigurationException
     */
    public function trustKey(string $kid, string $publicKey): static
    {
        $this->keyring->add($kid, $publicKey);

        return $this;
    }

    public function keyring(): Keyring
    {
        return $this->keyring;
    }

    public function config(): Configuration
    {
        return $this->config;
    }

    public function clock(): Clock
    {
        return $this->clock;
    }

    public function cache(): CacheStoreInterface
    {
        return $this->cache;
    }

    /**
     * The stable `inst_…` identifier for this installation (contract §10).
     */
    public function installationId(): string
    {
        return $this->installationIds->resolve();
    }

    /**
     * Validates the licence, preferring a still-valid cached certificate and
     * falling back to the server.
     *
     * `$force` skips the cached certificate entirely, which is the manual
     * re-check of contract §5.3.
     *
     * @throws GraceExpiredException no verifiable certificate exists (fail-closed)
     * @throws VerificationException a certificate exists but cannot be trusted
     * @throws LicenseException the server answered and refused
     */
    public function validate(bool $force = false): LicenseStatus
    {
        if (! $force) {
            $cached = $this->statusFromCache();

            if ($cached !== null) {
                return $cached;
            }
        }

        try {
            $status = $this->validateOnline();
        } catch (NetworkException $e) {
            // The server is unreachable. That is not the same as "the licence is
            // fine" and it is not the same as "the licence is invalid": fall back
            // to the certificate, and refuse if there is no usable one.
            //
            // A forced check does not fall back, because the caller explicitly
            // asked for the server's answer and quietly serving the cache would
            // hide that the server could not be reached.
            if ($force) {
                throw $e;
            }

            return $this->statusWithoutServer($e);
        }

        $this->persist($status);

        return $status;
    }

    /**
     * Activates this installation and caches the resulting certificate.
     *
     * Safe to call repeatedly for the same installation: the server reports
     * `already_activated`, which is a success (contract §7.7).
     *
     * @throws LicenseException
     */
    public function activate(): LicenseStatus
    {
        $data = $this->client()->activate($this->activationPayload());

        $certificate = $this->certificateFromData($data);

        $status = LicenseStatus::fromApiResponse([
            'valid' => true,
            'status' => $data['status'] ?? 'active',
            'product' => $this->config->productCode,
            'license_type' => $data['license_type'] ?? null,
            'installation_id' => $this->installationId(),
            'domain' => $this->currentDomain(),
            'certificate' => $certificate,
            'public_key_id' => $data['public_key_id'] ?? null,
            'offline_until' => $this->normaliseInstant($data['offline_until'] ?? null),
            'grace_expires_in' => $this->graceSeconds($certificate, $data),
            'message' => ($data['already_activated'] ?? false) === true
                ? 'This installation was already activated.'
                : 'Activation succeeded.',
        ], $this->now());

        $this->persist($status, $certificate);

        return $status;
    }

    /**
     * Deactivates this installation and discards the cached certificate.
     *
     * @throws LicenseException
     */
    public function deactivate(?string $reason = null): bool
    {
        $data = $this->client()->deactivate([
            'license_key' => $this->config->licenseKey,
            'product_code' => $this->config->productCode,
            'domain' => $this->currentDomain(),
            'installation_id' => $this->installationId(),
            'reason' => $reason,
        ]);

        if (($data['deactivated'] ?? false) !== true) {
            return false;
        }

        // The certificate is destroyed deliberately. Leaving it behind would let
        // the next request keep working offline after an operator deactivation.
        // The revocation floor and the installation id survive: forgetting those
        // would hand an attacker the ability to re-present an older certificate.
        $this->cache->forget($this->cacheKey('certificate'));
        $this->cache->forget($this->cacheKey('status'));

        return true;
    }

    /**
     * Licence-level state. Deliberately takes no certificate: this is about the
     * licence, not this installation (contract §4).
     *
     * @throws LicenseException
     */
    public function status(): LicenseStatus
    {
        $data = $this->client()->status([
            'license_key' => $this->config->licenseKey,
            'product_code' => $this->config->productCode,
        ]);

        return LicenseStatus::fromApiResponse($data + ['valid' => ($data['status'] ?? '') === 'active'], $this->now());
    }

    /**
     * Release information, or null when the server has nothing newer.
     *
     * @throws LicenseException
     */
    public function updateAvailable(): ?UpdateInfo
    {
        $data = $this->client()->checkUpdates([
            'product_code' => $this->config->productCode,
            'license_key' => $this->config->licenseKey,
            'current_version' => $this->currentVersion(),
            'domain' => $this->currentDomain(),
            'installation_id' => $this->installationId(),
        ]);

        $info = UpdateInfo::fromArray($data, $this->currentVersion());

        return $info->updateAvailable ? $info : null;
    }

    /**
     * The single question product software should ask, and the one that must
     * never throw: an unreachable server or an untrusted cache is a `false`,
     * not an exception (contract §10, §53).
     */
    public function valid(): bool
    {
        try {
            return $this->validate()->valid;
        } catch (LicenseException) {
            return false;
        }
    }

    /**
     * The compact certificate token, whether or not it is still inside its
     * window. Useful for diagnostics and for handing the token to a support
     * request; it is not proof on its own.
     */
    public function certificate(): ?string
    {
        $token = $this->cache->get($this->cacheKey('certificate'));

        return is_string($token) && $token !== '' ? $token : null;
    }

    public function graceExpiresAt(): ?DateTimeImmutable
    {
        $status = $this->statusFromCache(verify: false);

        if ($status?->graceExpiresAt !== null) {
            return $status->graceExpiresAt;
        }

        $token = $this->certificate();

        if ($token === null) {
            return null;
        }

        try {
            return new DateTimeImmutable('@'.Certificate::parse($token)->expiresAt());
        } catch (VerificationException) {
            return null;
        }
    }

    /**
     * Whole days of grace left, per contract §5.3.
     */
    public function offlineDaysRemaining(): int
    {
        return $this->statusFromCache()?->offlineDaysRemaining() ?? 0;
    }

    /**
     * Drops the cached certificate, metadata and revocation floor.
     *
     * This does **not** grant access: with no certificate, the next call goes
     * to the server, and if the server is unreachable the licence is refused
     * (contract §5.2). It is an operation for support, not a bypass.
     */
    public function expireCache(): void
    {
        $this->cache->forget($this->cacheKey('certificate'));
        $this->cache->forget($this->cacheKey('status'));
        $this->cache->forget($this->cacheKey('rev-floor'));
    }

    /**
     * Clears the whole store, including the installation id and any fetched
     * keyring. The next call re-validates from scratch.
     */
    public function clearAll(): void
    {
        $this->cache->flush();
        $this->fetchedKeyring = null;
    }

    /**
     * Refreshes the trusted keyring from the server.
     *
     * Only reached once a certificate has been seen, so the trust bootstrap
     * cannot be used to inject a key before there is anything to verify.
     *
     * @throws LicenseException
     */
    public function refreshKeyring(): Keyring
    {
        if ($this->fetchedKeyring !== null) {
            return $this->keyring;
        }

        $payload = $this->client()->publicKeyring();

        $this->keyring->mergeFromServer($payload);
        $this->fetchedKeyring = $this->keyring->toBase64Array();

        return $this->keyring;
    }

    /**
     * The context the SDK reports about itself (contract §10).
     *
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return [
            'installation_id' => $this->installationId(),
            'domain' => $this->currentDomain(),
            'version' => $this->currentVersion(),
        ] + $this->environment->toArray();
    }

    public function currentDomain(): string
    {
        return $this->domains->detect($this->config->domain);
    }

    public function currentVersion(): string
    {
        return $this->versions->detect($this->config->version);
    }

    /*
    |--------------------------------------------------------------------------
    | Server interaction
    |--------------------------------------------------------------------------
    */

    /**
     * @throws LicenseException
     */
    protected function validateOnline(): LicenseStatus
    {
        $payload = $this->validationPayload();

        $response = $this->client()->validate($payload);

        // HTTP 200 with `valid:false` is the documented shape for a recoverable
        // licence-state outcome (expired, suspended, domain refused) — the
        // transport worked, the licence did not (contract §1.3).
        if (($response['valid'] ?? null) !== true) {
            $this->cache->forget($this->cacheKey('certificate'));

            return LicenseStatus::fromApiResponse($response, $this->now());
        }

        $certificate = $this->certificateFromData($response);
        $status = LicenseStatus::fromApiResponse($response + ['certificate' => $certificate], $this->now());

        return $status;
    }

    /**
     * The offline path, and the refusal that ends it.
     *
     * @throws GraceExpiredException
     * @throws VerificationException
     */
    protected function statusWithoutServer(NetworkException $unreachable): LicenseStatus
    {
        $cached = $this->statusFromCache();

        if ($cached !== null) {
            return $cached;
        }

        $token = $this->certificate();

        // No certificate at all: refuse. We never saw a signature we can trust,
        // and guessing would be exactly the fail-open the contract forbids.
        if ($token === null) {
            throw GraceExpiredException::noCertificate();
        }

        // A certificate is cached but unusable. Distinguish the two causes, so
        // the operator sees "your grace ran out" rather than "tampering".
        try {
            $certificate = Certificate::parse($token);
        } catch (VerificationException $e) {
            throw $e;
        }

        $now = $this->now();

        if ($certificate->isExpired($now + self::EXPIRY_LEEWAY_SECONDS)) {
            throw GraceExpiredException::expired($certificate->expiresAt(), $now);
        }

        // Verified but revoked or mismatched: a hard failure, not a grace case.
        throw new VerificationException(
            $unreachable->getMessage(),
            'CERTIFICATE_NOT_TRUSTED',
            ['cause' => 'offline validation failed while the server was unreachable'],
        );
    }

    /**
     * Builds a status from the cached certificate, verifying it locally.
     *
     * Returns null — never a `false` — when there is nothing usable, so the
     * caller decides between asking the server and refusing.
     *
     * @throws VerificationException
     * @throws GraceExpiredException
     */
    protected function statusFromCache(bool $verify = true): ?LicenseStatus
    {
        $token = $this->certificate();

        if ($token === null) {
            return null;
        }

        $certificate = Certificate::parse($token);
        $now = $this->now();

        if ($verify) {
            $this->assertCertificateIsTrustworthy($certificate, $now);
        }

        $metadata = $this->cachedMetadata();

        return LicenseStatus::fromCertificate(
            $certificate,
            $this->config->productCode,
            $metadata['license_type'] ?? null,
            $certificate->domain(),
            (bool) ($metadata['update_available'] ?? false),
            $metadata['latest_version'] ?? null,
            $now,
        );
    }

    /**
     * The three offline gates, in the order of contract §5.3: signature, then
     * the `nbf`/`exp` window, then the revocation counter.
     *
     * @throws VerificationException
     * @throws GraceExpiredException
     */
    protected function assertCertificateIsTrustworthy(Certificate $certificate, int $now): void
    {
        SignatureVerifier::verify($certificate, $this->keyring);

        $leeway = self::EXPIRY_LEEWAY_SECONDS;

        if ($now + $leeway < $certificate->notBefore()) {
            throw VerificationException::notYetValid($certificate->notBefore(), $now);
        }

        if ($now > $certificate->expiresAt() + $leeway) {
            throw GraceExpiredException::expired($certificate->expiresAt(), $now);
        }

        $this->assertCertificateBindings($certificate);
    }

    /**
     * Local consistency checks that apply to every certificate, however it
     * arrived.
     *
     * A certificate for another product or another installation proves that
     * *someone* has a valid licence, not that *this* installation does. Checking
     * on the online path as well as offline keeps a misconfigured or hostile
     * response from seeding the cache with a token that names someone else.
     *
     * @throws VerificationException
     */
    protected function assertCertificateBindings(Certificate $certificate): void
    {
        // Monotonic per-licence counter: a certificate older than one already
        // trusted means the licence was suspended, revoked or had its domain
        // list changed (contract §5.2). This is also what stops a hand-edited
        // cache from lowering trust.
        $floor = $this->revocationFloor();

        if ($floor !== null && $certificate->revocationCounter() < $floor) {
            throw VerificationException::staleRevocationCounter($certificate->revocationCounter(), $floor);
        }

        if (! hash_equals($this->config->productCode, $certificate->productCode())) {
            throw VerificationException::bindingMismatch(
                'product',
                $this->config->productCode,
                $certificate->productCode(),
            );
        }

        if ($certificate->installationId() !== '' && ! hash_equals($this->installationId(), $certificate->installationId())) {
            throw VerificationException::bindingMismatch(
                'installation',
                $this->installationId(),
                $certificate->installationId(),
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    protected function cachedMetadata(): array
    {
        $metadata = $this->cache->get($this->cacheKey('status'));

        return is_array($metadata) ? $metadata : [];
    }

    /**
     * Writes a successful status to the cache, subject to the revocation floor.
     *
     * A certificate that would lower the floor is *not* stored: accepting it
     * would let a replayed old token roll trust backwards.
     *
     * @param  string|null  $certificate  Already extracted token, if any.
     */
    protected function persist(LicenseStatus $status, ?string $certificate = null): void
    {
        if (! $status->valid) {
            return;
        }

        $token = $certificate ?? $status->certificate;
        $floor = $this->revocationFloor();

        if ($token !== null && $token !== '') {
            try {
                $parsed = Certificate::parse($token);
            } catch (VerificationException) {
                // A malformed certificate is never cached; without it the next
                // call must go to the server rather than trust a broken token.
                return;
            }

            if ($floor !== null && $parsed->revocationCounter() < $floor) {
                return;
            }

            // Verified again here rather than trusting the caller: this is the
            // point where an unverified token would become the installation's
            // standing trust anchor, so it gets its own gate.
            try {
                SignatureVerifier::verify($parsed, $this->keyring);
            } catch (VerificationException) {
                return;
            }

            $this->cache->put($this->cacheKey('certificate'), $token);
            $this->cache->put(
                $this->cacheKey('rev-floor'),
                $floor === null ? $parsed->revocationCounter() : max($floor, $parsed->revocationCounter()),
            );
        }

        $metadata = [
            'certificate' => $token,
            'public_key_id' => $status->publicKeyId,
            'status' => $status->status,
            'valid' => $status->valid,
            'error_code' => $status->errorCode,
            'message' => $status->message,
            'product' => $status->productCode,
            'license_type' => $status->licenseType,
            'expires_at' => $status->expiresAt?->format(DATE_ATOM),
            'installation_id' => $status->installationId,
            'domain' => $status->domain,
            'update_available' => $status->updateAvailable,
            'latest_version' => $status->latestVersion,
            'offline_until' => $status->graceExpiresAt?->format(DATE_ATOM),
            'grace_expires_in' => $status->graceSecondsRemaining,
            'revocation_counter' => $status->revocationCounter,
            'verified_at' => $status->verifiedAt,
        ];

        // Metadata lives beside the certificate so the offline path can enrich
        // a locally verified certificate with the server's own wording. It is
        // presentation only: nothing here grants access on its own.
        $this->cache->put($this->cacheKey('status'), $metadata);
    }

    protected function revocationFloor(): ?int
    {
        $value = $this->cache->get($this->cacheKey('rev-floor'));

        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    protected function validationPayload(): array
    {
        return [
            'license_key' => $this->config->licenseKey,
            'product_code' => $this->config->productCode,
            'domain' => $this->currentDomain(),
            'installation_id' => $this->installationId(),
            'version' => $this->currentVersion(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function activationPayload(): array
    {
        return [
            'license_key' => $this->config->licenseKey,
            'product_code' => $this->config->productCode,
            'domain' => $this->currentDomain(),
            'installation_id' => $this->installationId(),
            'version' => $this->currentVersion(),
        ] + $this->environment->toArray();
    }

    /**
     * The last exception {@see self::valid()} swallowed, for logging.
     */
    public function lastError(): ?LicenseException
    {
        try {
            $this->validate();
        } catch (LicenseException $e) {
            return $e;
        }

        return null;
    }

    /**
     * Extracts a certificate token from a response, verifying it before use.
     *
     * An unverifiable certificate is discarded: the *signature* is what makes a
     * response trustworthy, so a response carrying a bad one is treated as
     * carrying none.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws VerificationException
     */
    protected function certificateFromData(array $data): ?string
    {
        $token = $data['certificate'] ?? null;

        if (! is_string($token) || trim($token) === '') {
            return null;
        }

        $certificate = Certificate::parse($token);

        // An unfamiliar `kid` means the server may have rotated its signing key.
        // Pull the published set so trust can be established before verifying,
        // rather than refusing a legitimate certificate after a rotation.
        if (! $this->keyring->has($certificate->kid())) {
            try {
                $this->refreshKeyring();
            } catch (LicenseException) {
                // Fall through to verification, which will report the unknown key.
            }
        }

        SignatureVerifier::verify($certificate, $this->keyring);

        // The window is checked on the online path too. A certificate the server
        // claims is valid but which is not yet valid, or already expired, means
        // clock skew or a stale token; either way it must not become this
        // installation's standing trust anchor.
        $now = $this->now();
        $leeway = self::EXPIRY_LEEWAY_SECONDS;

        if ($now + $leeway < $certificate->notBefore()) {
            throw VerificationException::notYetValid($certificate->notBefore(), $now);
        }

        if ($now > $certificate->expiresAt() + $leeway) {
            throw GraceExpiredException::expired($certificate->expiresAt(), $now);
        }

        $this->assertCertificateBindings($certificate);

        return $token;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    protected function graceSeconds(?string $certificate, array $data): int
    {
        // `LICENSE_GRACE_OVERRIDE` is an operator escape hatch for tightening
        // the window locally; the server's own value always wins otherwise, so
        // lowering the grace server-side takes effect on the next contact
        // (contract §5.3).
        if ($this->config->graceOverride !== null) {
            return max(0, $this->config->graceOverride);
        }

        if ($certificate !== null) {
            return Certificate::parse($certificate)->graceSeconds();
        }

        return is_numeric($data['grace_expires_in'] ?? null) ? (int) $data['grace_expires_in'] : 0;
    }

    protected function normaliseInstant(mixed $value): ?string
    {
        if (is_int($value)) {
            return gmdate('c', $value);
        }

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected function now(): int
    {
        return $this->clock->now();
    }

    protected function client(): LicenseClient
    {
        return $this->client ??= new LicenseClient($this->config, $this->transport, $this->signer());
    }

    /**
     * Returns null when no API credentials are configured. The endpoints are
     * authenticated for the calling *product*, and a licence key alone is never
     * authentication (contract §3), so an unconfigured deployment gets a clear
     * error rather than a puzzling 401.
     */
    protected function signer(): ?RequestSigner
    {
        if (! $this->config->hasApiCredentials()) {
            return null;
        }

        return RequestSigner::fromCredentials(
            (string) $this->config->apiKey,
            (string) $this->config->apiSecret,
            $this->config->authScheme,
        );
    }

    protected function defaultTransport(): Transport
    {
        return CurlTransport::isSupported()
            ? new CurlTransport($this->config->timeout, $this->config->connectTimeout, $this->config->verifySsl)
            : new StreamTransport($this->config->timeout, $this->config->connectTimeout, $this->config->verifySsl);
    }

    /**
     * The shipped placeholder key plus anything the operator pinned.
     *
     * A configured `LICENSE_PUBLIC_KEY` is trusted immediately. Without one the
     * placeholder is all there is, and it has no private half anywhere, so a
     * certificate that verifies against it is a certificate the server issued.
     */
    protected function bootstrapKeyring(): Keyring
    {
        $keyring = Keyring::bootstrap();

        $configured = $this->config->publicKey;
        $configuredId = $this->config->publicKeyId;

        if ($configured !== null && $configured !== '') {
            // Without an explicit kid the key is trusted for whatever `kid` the
            // server names, which is what makes a rotation survivable.
            $keyring->add($configuredId ?? 'configured', $configured);
        }

        return $keyring;
    }

    protected function cacheKey(string $suffix): string
    {
        return $this->cache->key($suffix);
    }
}
