<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Support;

use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\Http\Transport;

/**
 * A transport that replays queued responses and records what was sent, so
 * offline and fail-closed behaviour can be tested with no network at all.
 */
final class FakeTransport implements Transport
{
    /** @var array<int, array{method: string, url: string, headers: array<string, string>, body: string|null}> */
    public array $requests = [];

    /** @var array<int, ApiResponse|NetworkException> */
    private array $queue;

    private ?NetworkException $fallback = null;

    /**
     * @param  array<int, ApiResponse|NetworkException>  $queue
     */
    public function __construct(array $queue = [])
    {
        $this->queue = $queue;
    }

    public static function json(int $status, array $body): self
    {
        return new self([new ApiResponse($status, [], json_encode($body, JSON_THROW_ON_ERROR))]);
    }

    public function push(ApiResponse|NetworkException ...$responses): self
    {
        foreach ($responses as $response) {
            $this->queue[] = $response;
        }

        return $this;
    }

    /**
     * Makes every unqueued request fail, standing in for a server that is down.
     */
    public function alwaysFail(NetworkException $exception): self
    {
        $this->fallback = $exception;

        return $this;
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): ApiResponse
    {
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
        ];

        $next = array_shift($this->queue);

        if ($next instanceof NetworkException) {
            throw $next;
        }

        if ($next instanceof ApiResponse) {
            return $next;
        }

        // An unqueued request with no explicit failure still has to fail: a test
        // that expected a response and did not queue one is a broken test, not a
        // silent success.
        throw $this->fallback
            ?? NetworkException::unreachable($url, 'no response queued for this request');
    }

    public function lastRequest(): ?array
    {
        return $this->requests === [] ? null : $this->requests[array_key_last($this->requests)];
    }

    public function requestCount(): int
    {
        return count($this->requests);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function lastBody(): ?array
    {
        $body = $this->lastRequest()['body'] ?? null;

        if ($body === null) {
            return null;
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : null;
    }
}
