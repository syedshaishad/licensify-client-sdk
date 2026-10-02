<?php

declare(strict_types=1);

namespace Licensify\Client\Http;

/**
 * An HTTP response as received, with no interpretation applied.
 */
final readonly class ApiResponse
{
    /**
     * @param  array<string, string>  $headers  Lower-cased header names.
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
    ) {}

    /**
     * @param  array<string, mixed>  $headers
     */
    public static function make(int $status, array $headers, string $body): self
    {
        $normalised = [];

        foreach ($headers as $name => $value) {
            $normalised[strtolower((string) $name)] = is_array($value) ? implode(', ', $value) : (string) $value;
        }

        return new self($status, $normalised, $body);
    }

    public function isSuccessful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    public function isServerError(): bool
    {
        return $this->status >= 500;
    }

    /**
     * Decoded JSON object, or null when the body is empty or not a JSON object.
     * Callers must treat the server's body as untrusted input and validate
     * every field before use.
     *
     * @return array<string, mixed>|null
     */
    public function json(): ?array
    {
        if (trim($this->body) === '') {
            return null;
        }

        $decoded = json_decode($this->body, true);

        return is_array($decoded) && ! array_is_list($decoded) ? $decoded : null;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function rateLimitRemaining(): ?int
    {
        $value = $this->header('x-ratelimit-remaining');

        return $value === null || ! is_numeric($value) ? null : (int) $value;
    }

    public function retryAfter(): ?int
    {
        $value = $this->header('retry-after');

        return $value === null || ! is_numeric($value) ? null : (int) $value;
    }

    /**
     * Truncated body excerpt, safe to put in an exception message or a debug
     * log: the SDK must never echo the API secret or the licence key, and a
     * response body never contains either.
     */
    public function excerpt(int $limit = 200): string
    {
        $body = trim(preg_replace('/\s+/', ' ', $this->body) ?? $this->body);

        return mb_strlen($body) > $limit ? mb_substr($body, 0, $limit).'…' : $body;
    }
}
