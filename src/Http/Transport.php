<?php

declare(strict_types=1);

namespace Licensify\Client\Http;

use Licensify\Client\Exception\NetworkException;

/**
 * Raw HTTP transport. Deliberately dumb: it moves bytes and knows nothing
 * about licensing, so a different HTTP client can be dropped in without
 * touching any licensing logic.
 *
 * Implementations must throw {@see NetworkException}
 * for connection, TLS and timeout failures — anything else is an HTTP response
 * and must be returned.
 */
interface Transport
{
    /**
     * @param  array<string, string>  $headers
     *
     * @throws NetworkException
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): ApiResponse;
}
