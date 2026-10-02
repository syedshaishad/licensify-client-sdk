<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

use Licensify\Client\Exception\ConfigurationException;

/**
 * Derives the domain this installation is running on and normalises it the
 * same way the server does (contract §6).
 *
 * Matching a licence therefore compares like with like: `www.example.com`,
 * `https://example.com:8443/app` and `EXAMPLE.com.` are one domain, and an IDN
 * host arrives at the server as punycode.
 */
final class DomainDetector
{
    /**
     * Patterns that mark a hostname as a development environment. Mirrors the
     * server's default list so both sides classify `foo.test` the same way.
     *
     * @var array<int, string>
     */
    public const DEFAULT_DEVELOPMENT_PATTERNS = [
        '\.local$',
        '\.test$',
        '\.localhost$',
        '\.dev$',
        '^stg\.',
        '^dev\.',
    ];

    /**
     * @param  bool  $stripWww  Whether a leading `www.` is removed (default true).
     */
    public function __construct(
        private readonly bool $stripWww = true,
        private readonly array $developmentPatterns = self::DEFAULT_DEVELOPMENT_PATTERNS,
    ) {}

    /**
     * Reads the current domain from the process environment.
     *
     * Priority: explicit override, `HTTP_HOST`, `SERVER_NAME`, then
     * `SERVER_ADDR`. CLI processes have none of these, which is why the
     * override exists.
     *
     * @param  array<string, mixed>|null  $server
     *
     * @throws ConfigurationException
     */
    public function detect(?string $override = null, ?array $server = null): string
    {
        if ($override !== null && trim($override) !== '') {
            return $this->normalize($override);
        }

        $server ??= $_SERVER;

        foreach (['HTTP_HOST', 'SERVER_NAME', 'SERVER_ADDR'] as $key) {
            $candidate = $server[$key] ?? null;

            if (is_string($candidate) && trim($candidate) !== '') {
                return $this->normalize($candidate);
            }
        }

        throw new ConfigurationException(
            'No domain could be detected; set LICENSE_DOMAIN for this environment.',
            'DOMAIN_UNDETECTABLE',
        );
    }

    /**
     * Full normalisation pipeline (contract §6 steps 1–7).
     *
     * @throws ConfigurationException
     */
    public function normalize(string $input): string
    {
        return $this->describe($input)->domain;
    }

    /**
     * Normalises and classifies in one pass.
     *
     * @throws ConfigurationException
     */
    public function describe(string $input): NormalizedDomain
    {
        $host = $this->toLowercase($this->stripControlCharacters(trim($input)));

        if ($host === '') {
            throw new ConfigurationException('The domain to normalise is empty.', 'DOMAIN_EMPTY');
        }

        $host = $this->extractHost($host);
        $host = $this->toPunycode($host);
        $host = rtrim($host, '.');

        if ($host === '' || ! $this->isWellFormed($host)) {
            throw new ConfigurationException(
                sprintf('"%s" is not a usable domain.', $input),
                'DOMAIN_MALFORMED',
            );
        }

        $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;

        if ($isIp) {
            $host = $this->normalizeIp($host);
        }

        $domain = $this->stripWwwPrefix($host);

        return new NormalizedDomain(
            host: $host,
            domain: $domain,
            environment: $this->classify($domain, $isIp),
            isIpAddress: $isIp,
        );
    }

    /**
     * Classifies an already-normalised domain (contract §6 step 7).
     */
    public function classify(string $normalizedDomain, ?bool $isIp = null): DomainEnvironment
    {
        $domain = strtolower($normalizedDomain);
        $isIp ??= filter_var($domain, FILTER_VALIDATE_IP) !== false;

        if ($isIp) {
            $isLoopback = in_array($domain, ['127.0.0.1', '::1'], true) || str_starts_with($domain, '127.');

            return $isLoopback ? DomainEnvironment::Localhost : DomainEnvironment::IpAddress;
        }

        if ($domain === 'localhost' || str_ends_with($domain, '.localhost')) {
            return DomainEnvironment::Localhost;
        }

        foreach ($this->developmentPatterns as $pattern) {
            if ($pattern !== '' && @preg_match('#'.$pattern.'#i', $domain) === 1) {
                return DomainEnvironment::Development;
            }
        }

        if (str_contains($domain, '.')) {
            return $domain === $this->registrableDomain($domain)
                ? DomainEnvironment::Production
                : DomainEnvironment::Subdomain;
        }

        return DomainEnvironment::Production;
    }

    /**
     * Is this domain acceptable to activate against, given local policy?
     *
     * Loopback is tolerated when `allowLocalhost` is set because blocking a
     * developer machine makes the SDK untestable; everything else follows the
     * server's product policy and is decided server-side.
     */
    public function isLocallyAcceptable(NormalizedDomain $domain, bool $allowLocalhost): bool
    {
        if (! $allowLocalhost && $domain->isDevelopment()) {
            return false;
        }

        return true;
    }

    /**
     * Does a normalised domain satisfy a stored pattern that may be a wildcard?
     *
     * @param  int  $depth  Labels a wildcard may stand in for (contract §6.9).
     */
    public function matchesPattern(string $normalizedDomain, string $pattern, bool $includeApex = false, int $depth = 1): bool
    {
        $domain = strtolower($normalizedDomain);
        $pattern = strtolower($pattern);

        if ($domain === '') {
            return false;
        }

        if (! str_starts_with($pattern, '*.')) {
            return $domain === $pattern;
        }

        $base = substr($pattern, 2);

        if ($domain === $base) {
            return $includeApex;
        }

        $suffix = '.'.$base;

        if (! str_ends_with($domain, $suffix)) {
            return false;
        }

        $labels = substr_count(substr($domain, 0, -strlen($suffix)), '.') + 1;

        return $labels <= max(1, $depth);
    }

    /**
     * Reduce a domain to its registrable parent using a conservative built-in
     * suffix list — no runtime network lookup, which an offline install cannot
     * make anyway.
     */
    public function registrableDomain(string $normalizedDomain): string
    {
        $labels = explode('.', strtolower($normalizedDomain));

        if (count($labels) < 2) {
            return strtolower($normalizedDomain);
        }

        $twoPartSuffixes = [
            'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'co.nz', 'com.au',
            'co.za', 'com.br', 'co.in', 'com.mx', 'com.tr', 'com.cn', 'com.sg',
        ];

        $lastTwo = implode('.', array_slice($labels, -2));
        $offset = in_array($lastTwo, $twoPartSuffixes, true) && count($labels) >= 3 ? 3 : 2;

        return implode('.', array_slice($labels, -$offset));
    }

    /**
     * Strips scheme, userinfo, path, query, fragment and port from any input.
     */
    private function extractHost(string $input): string
    {
        $value = preg_replace('#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', '', $input) ?? $input;
        $value = preg_replace('#^//#', '', $value) ?? $value;
        $value = preg_replace('#[/?\#].*$#', '', $value) ?? $value;

        if (str_contains($value, '@')) {
            $value = substr($value, (int) strrpos($value, '@') + 1);
        }

        // Bracketed IPv6 literal, e.g. [::1]:8080.
        if (str_starts_with($value, '[')) {
            $closing = strpos($value, ']');

            return $closing === false ? $value : substr($value, 1, $closing - 1);
        }

        // A bare IPv6 literal contains several colons and has no port.
        if (substr_count($value, ':') === 1) {
            $value = preg_replace('/:\d+$/', '', $value) ?? $value;
        }

        return $value;
    }

    /**
     * Lowercases using multibyte rules and drops the zero-width characters
     * that let an attacker register a domain that *looks* identical.
     */
    private function toLowercase(string $host): string
    {
        $host = str_replace(["\xE2\x80\x8B", "\xE2\x80\x8C", "\xE2\x80\x8D", "\xEF\xBB\xBF"], '', $host);

        return mb_strtolower($host, 'UTF-8');
    }

    private function stripControlCharacters(string $value): string
    {
        return preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? $value;
    }

    private function toPunycode(string $host): string
    {
        if ($host === '' || ! function_exists('idn_to_ascii')) {
            return $host;
        }

        if (preg_match('/^[\x20-\x7E]+$/', $host) === 1) {
            return $host;
        }

        $converted = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

        return $converted === false ? $host : strtolower($converted);
    }

    private function isWellFormed(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        if (preg_match('/^[a-z0-9\-._]+$/', $host) !== 1) {
            return false;
        }

        foreach (explode('.', $host) as $label) {
            if ($label === '' || strlen($label) > 63) {
                return false;
            }
        }

        return true;
    }

    /**
     * IPv4-mapped IPv6 collapses to plain IPv4; IPv6 takes its compressed form.
     */
    private function normalizeIp(string $host): string
    {
        $packed = @inet_pton($host);

        if ($packed === false) {
            return $host;
        }

        if (strlen($packed) === 16 && str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF")) {
            $mapped = @inet_ntop(substr($packed, 12));

            if ($mapped !== false && filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $mapped;
            }
        }

        $normalized = @inet_ntop($packed);

        return $normalized === false ? $host : $normalized;
    }

    private function stripWwwPrefix(string $host): string
    {
        if (! $this->stripWww || $host === 'www') {
            return $host;
        }

        // Only strip when a registrable domain remains behind it.
        return preg_replace('/^www\.(?=.+\..+$)/', '', $host) ?? $host;
    }
}
