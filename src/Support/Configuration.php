<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Licensify\Client\Exception\ConfigurationException;
use SensitiveParameter;

/**
 * Immutable, fully resolved SDK configuration (contract §34).
 *
 * Everything comes from the environment; nothing is hardcoded. Secrets are held
 * here and nowhere else, and {@see self::toArray()} redacts them so a
 * configuration object is safe to log.
 */
final readonly class Configuration
{
    public const DEFAULT_TIMEOUT = 10.0;

    public const DEFAULT_CONNECT_TIMEOUT = 5.0;

    /**
     * @param  string|null  $publicKey  Operator-pinned Ed25519 public key, base64.
     * @param  string|null  $publicKeyId  `kid` the pinned key is bound to. When
     *                                    null the key is used for any `kid`, which
     *                                    is safe because the signature must still
     *                                    verify against that exact key material.
     */
    public function __construct(
        public string $serverUrl,
        public string $productCode,
        #[SensitiveParameter]
        public string $licenseKey,
        #[SensitiveParameter]
        public ?string $apiKey = null,
        #[SensitiveParameter]
        public ?string $apiSecret = null,
        public AuthScheme $authScheme = AuthScheme::Hmac,
        public ?string $publicKey = null,
        public ?string $publicKeyId = null,
        public ?int $graceOverride = null,
        public ?string $cachePath = null,
        public float $timeout = self::DEFAULT_TIMEOUT,
        public float $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT,
        public bool $verifySsl = true,
        public bool $allowLocalhost = false,
        public ?string $domain = null,
        public ?string $version = null,
    ) {}

    /**
     * Reads the documented `LICENSE_*` environment variables.
     *
     * @param  array<string, mixed>|null  $environment  Defaults to the process environment.
     *
     * @throws ConfigurationException
     */
    public static function fromEnvironment(?array $environment = null): self
    {
        $environment ??= self::environment();

        return self::fromArray([
            'server_url' => self::requireString($environment, 'LICENSE_SERVER_URL'),
            'product_code' => self::requireString($environment, 'LICENSE_PRODUCT_CODE'),
            'license_key' => self::requireString($environment, 'LICENSE_KEY'),
            'api_key' => self::stringOrNull($environment, 'LICENSE_API_KEY'),
            'api_secret' => self::stringOrNull($environment, 'LICENSE_API_SECRET'),
            'auth_scheme' => self::authScheme($environment),
            'public_key' => self::stringOrNull($environment, 'LICENSE_PUBLIC_KEY'),
            'public_key_id' => self::stringOrNull($environment, 'LICENSE_PUBLIC_KEY_ID'),
            'grace_override' => self::intOrNull($environment, 'LICENSE_GRACE_OVERRIDE'),
            'cache_path' => self::stringOrNull($environment, 'LICENSE_CACHE_PATH'),
            'timeout' => self::floatOrNull($environment, 'LICENSE_TIMEOUT') ?? self::DEFAULT_TIMEOUT,
            'connect_timeout' => self::floatOrNull($environment, 'LICENSE_CONNECT_TIMEOUT') ?? self::DEFAULT_CONNECT_TIMEOUT,
            'verify_ssl' => self::boolOrNull($environment, 'LICENSE_VERIFY_SSL') ?? true,
            'allow_localhost' => self::boolOrNull($environment, 'LICENSE_ALLOW_LOCALHOST') ?? false,
            'domain' => self::stringOrNull($environment, 'LICENSE_DOMAIN'),
            'version' => self::stringOrNull($environment, 'LICENSE_VERSION'),
        ]);
    }

    /**
     * Builds a configuration from an explicit array — the injection point for
     * frameworks and for tests.
     *
     * @param  array<string, mixed>  $values
     *
     * @throws ConfigurationException
     */
    public static function fromArray(array $values): self
    {
        $configuration = new self(
            serverUrl: (string) ($values['server_url'] ?? ''),
            productCode: (string) ($values['product_code'] ?? ''),
            licenseKey: (string) ($values['license_key'] ?? ''),
            apiKey: self::nullableString($values['api_key'] ?? null),
            apiSecret: self::nullableString($values['api_secret'] ?? null),
            authScheme: self::coerceAuthScheme($values['auth_scheme'] ?? null),
            publicKey: self::nullableString($values['public_key'] ?? null),
            publicKeyId: self::nullableString($values['public_key_id'] ?? null),
            graceOverride: isset($values['grace_override']) ? (int) $values['grace_override'] : null,
            cachePath: self::nullableString($values['cache_path'] ?? null),
            timeout: isset($values['timeout']) ? (float) $values['timeout'] : self::DEFAULT_TIMEOUT,
            connectTimeout: isset($values['connect_timeout']) ? (float) $values['connect_timeout'] : self::DEFAULT_CONNECT_TIMEOUT,
            verifySsl: (bool) ($values['verify_ssl'] ?? true),
            allowLocalhost: (bool) ($values['allow_localhost'] ?? false),
            domain: self::nullableString($values['domain'] ?? null),
            version: self::nullableString($values['version'] ?? null),
        );

        return $configuration->assertUsable();
    }

    /**
     * Base URL with exactly one trailing slash removed, so paths can be
     * appended without producing `//api/v1/...`.
     */
    public function baseUrl(): string
    {
        return rtrim(trim($this->serverUrl), '/');
    }

    /**
     * @throws ConfigurationException
     */
    public function endpoint(string $path): string
    {
        return $this->baseUrl().'/'.ltrim($path, '/');
    }

    public function hasApiCredentials(): bool
    {
        return $this->apiKey !== null && $this->apiKey !== '' && $this->apiSecret !== null && $this->apiSecret !== '';
    }

    /**
     * True when the pinned key is deliberately not tied to one `kid`, which lets
     * the SDK follow a server-side key rotation without a redeploy.
     */
    public function hasUnboundPublicKey(): bool
    {
        return $this->publicKey !== null && $this->publicKey !== '' && $this->publicKeyId === null;
    }

    /**
     * Where the file cache lives when no path is configured.
     */
    public function resolvedCachePath(): string
    {
        if ($this->cachePath !== null && $this->cachePath !== '') {
            return rtrim($this->cachePath, '/');
        }

        // Framework-agnostic default. Never the current working directory: a
        // cache file dropped next to the code is both guessable and easily
        // published by a misconfigured web root.
        return rtrim(sys_get_temp_dir(), '/').'/licensify-sdk';
    }

    /**
     * Safe to log: secrets are replaced with a presence marker.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'server_url' => $this->serverUrl,
            'product_code' => $this->productCode,
            'license_key' => self::redact($this->licenseKey),
            'api_key' => self::redact($this->apiKey),
            'api_secret' => self::redact($this->apiSecret),
            'auth_scheme' => $this->authScheme->value,
            'public_key' => self::redact($this->publicKey),
            'public_key_id' => $this->publicKeyId,
            'grace_override' => $this->graceOverride,
            'cache_path' => $this->resolvedCachePath(),
            'timeout' => $this->timeout,
            'connect_timeout' => $this->connectTimeout,
            'verify_ssl' => $this->verifySsl,
            'allow_localhost' => $this->allowLocalhost,
            'domain' => $this->domain,
            'version' => $this->version,
        ];
    }

    /**
     * @throws ConfigurationException
     */
    public function assertUsable(): self
    {
        $missing = [];

        foreach (['server_url' => $this->serverUrl, 'product_code' => $this->productCode, 'license_key' => $this->licenseKey] as $name => $value) {
            if (trim($value) === '') {
                $missing[] = $name;
            }
        }

        if ($missing !== []) {
            throw ConfigurationException::missingEnvironment($missing);
        }

        if ($this->timeout <= 0 || $this->connectTimeout <= 0) {
            throw new ConfigurationException('HTTP timeouts must be greater than zero.', 'INVALID_TIMEOUT');
        }

        $scheme = parse_url($this->serverUrl, PHP_URL_SCHEME);
        $host = (string) parse_url($this->serverUrl, PHP_URL_HOST);

        if ($scheme === null || $host === '') {
            throw new ConfigurationException(
                sprintf('LICENSE_SERVER_URL "%s" is not a valid absolute URL.', $this->serverUrl),
                'INVALID_SERVER_URL',
            );
        }

        // Plaintext credentials would put the licence key and the shared API
        // secret on the wire in the clear. Loopback is exempt so that a
        // developer can point the SDK at a local licensing server.
        if ($scheme !== 'https' && ! self::isLoopbackHost($host)) {
            throw new ConfigurationException(
                sprintf('LICENSE_SERVER_URL must use https (got "%s").', $scheme),
                'INSECURE_TRANSPORT',
            );
        }

        return $this;
    }

    /**
     * The process environment, tolerating the several places PHP exposes it.
     *
     * @return array<string, mixed>
     */
    private static function environment(): array
    {
        $getenv = getenv();

        return array_merge(is_array($getenv) ? $getenv : [], $_ENV, $_SERVER);
    }

    /**
     * @param  array<string, mixed>  $environment
     *
     * @throws ConfigurationException
     */
    private static function requireString(array $environment, string $key): string
    {
        $value = self::stringOrNull($environment, $key);

        if ($value === null) {
            throw ConfigurationException::missingEnvironment([$key]);
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $environment
     */
    private static function stringOrNull(array $environment, string $key): ?string
    {
        $value = $environment[$key] ?? null;

        if ($value === null || is_array($value) || is_object($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }

    private static function nullableString(mixed $value): ?string
    {
        if ($value === null || is_array($value) || is_object($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }

    /**
     * @param  array<string, mixed>  $environment
     */
    private static function intOrNull(array $environment, string $key): ?int
    {
        $value = self::stringOrNull($environment, $key);

        return $value === null || ! is_numeric($value) ? null : (int) $value;
    }

    /**
     * @param  array<string, mixed>  $environment
     */
    private static function floatOrNull(array $environment, string $key): ?float
    {
        $value = self::stringOrNull($environment, $key);

        return $value === null || ! is_numeric($value) ? null : (float) $value;
    }

    /**
     * @param  array<string, mixed>  $environment
     */
    private static function boolOrNull(array $environment, string $key): ?bool
    {
        $value = self::stringOrNull($environment, $key);

        if ($value === null) {
            return null;
        }

        return match (strtolower($value)) {
            '1', 'true', 'yes', 'on' => true,
            '0', 'false', 'no', 'off' => false,
            default => null,
        };
    }

    /**
     * @param  array<string, mixed>  $environment
     *
     * @throws ConfigurationException
     */
    private static function authScheme(array $environment): AuthScheme
    {
        $value = self::stringOrNull($environment, 'LICENSE_AUTH_SCHEME') ?? self::stringOrNull($environment, 'LICENSE_API_AUTH_SCHEME');

        return self::coerceAuthScheme($value);
    }

    /**
     * @throws ConfigurationException
     */
    private static function coerceAuthScheme(mixed $value): AuthScheme
    {
        if ($value === null || $value === '') {
            return AuthScheme::Hmac;
        }

        if ($value instanceof AuthScheme) {
            return $value;
        }

        return AuthScheme::tryFrom(strtolower((string) $value))
            ?? throw new ConfigurationException(
                sprintf('Unknown licence auth scheme "%s"; expected "hmac" or "bearer".', (string) $value),
                'INVALID_AUTH_SCHEME',
            );
    }

    private static function isLoopbackHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        if (in_array($host, ['localhost', '::1', '127.0.0.1'], true)) {
            return true;
        }

        return str_starts_with($host, '127.');
    }

    private static function redact(?string $value): string
    {
        if ($value === null || $value === '') {
            return '(not set)';
        }

        // Never echo even a prefix of a secret; only whether one is present.
        return '(set)';
    }
}
