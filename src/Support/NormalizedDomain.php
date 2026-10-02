<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

/**
 * A normalised domain plus its classification (contract §6).
 */
final readonly class NormalizedDomain
{
    public function __construct(
        /** Host after scheme, userinfo, port, path and trailing-dot removal. */
        public string $host,
        /** Value sent to the server and compared against stored domains. */
        public string $domain,
        /** Classification used for policy decisions. */
        public DomainEnvironment $environment,
        public bool $isIpAddress,
    ) {}

    public function isDevelopment(): bool
    {
        return $this->environment->isDevelopment();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'host' => $this->host,
            'domain' => $this->domain,
            'environment' => $this->environment->value,
            'is_ip_address' => $this->isIpAddress,
        ];
    }
}
