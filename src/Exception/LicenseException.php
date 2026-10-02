<?php

declare(strict_types=1);

namespace Licensify\Client\Exception;

use RuntimeException;
use Throwable;

/**
 * Base type for every failure the SDK raises.
 *
 * Carries the API's canonical error code (contract §2) when the failure came
 * from the server, so callers can branch on `LICENSE_EXPIRED` rather than on
 * message text.
 */
class LicenseException extends RuntimeException
{
    /**
     * @param  array<string, mixed>  $details
     */
    public function __construct(
        string $message,
        private readonly ?string $errorCode = null,
        private readonly array $details = [],
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * @param  array<string, mixed>  $details
     */
    public static function withErrorCode(
        string $errorCode,
        string $message,
        array $details = [],
        ?Throwable $previous = null,
    ): static {
        return new static($message, $errorCode, $details, $previous);
    }

    public function errorCode(): ?string
    {
        return $this->errorCode;
    }

    /**
     * @return array<string, mixed>
     */
    public function details(): array
    {
        return $this->details;
    }

    public function hasErrorCode(string $errorCode): bool
    {
        return $this->errorCode !== null && hash_equals($errorCode, $this->errorCode);
    }
}
