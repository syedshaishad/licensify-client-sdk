<?php

declare(strict_types=1);

namespace Licensify\Client\Http;

use Licensify\Client\Exception\NetworkException;

/**
 * Fallback transport built on PHP streams, used when ext-curl is unavailable.
 *
 * It cannot stream a body incrementally, which is irrelevant here — every SDK
 * request is a small JSON document, and package downloads are the customer's
 * software fetching its own signed URL, not the SDK.
 */
final class StreamTransport implements Transport
{
    public function __construct(
        private readonly float $timeout = 10.0,
        private readonly float $connectTimeout = 5.0,
        private readonly bool $verifySsl = true,
        private readonly string $userAgent = 'licensify-client-sdk',
    ) {}

    public static function isSupported(): bool
    {
        return in_array('http', stream_get_wrappers(), true);
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): ApiResponse
    {
        $context = stream_context_create([
            'http' => [
                'method' => strtoupper($method),
                'header' => $this->formatHeaders($headers),
                'content' => $body ?? '',
                'timeout' => $this->timeout,
                'follow_location' => 0,
                'ignore_errors' => true,
                'user_agent' => $this->userAgent,
                // Without this PHP streams would send the server's certificate
                // verification result nowhere and default to "trusted".
                'protocol_version' => 1.1,
            ],
            'ssl' => [
                'verify_peer' => $this->verifySsl,
                'verify_peer_name' => $this->verifySsl,
                'allow_self_signed' => false,
                'peer_name' => parse_url($url, PHP_URL_HOST) ?: null,
            ],
            'socket' => [
                'tcp_nodelay' => true,
            ],
        ]);

        $handle = @fopen($url, 'rb', false, $context);

        if ($handle === false) {
            throw NetworkException::unreachable($url, error_get_last()['message'] ?? 'connection failed');
        }

        $meta = stream_get_meta_data($handle);
        $raw = stream_get_contents($handle);

        fclose($handle);

        if ($raw === false) {
            throw NetworkException::unreachable($url, 'response body could not be read');
        }

        [$status, $responseHeaders] = $this->parseHeaders($meta['wrapper_data'] ?? []);

        return new ApiResponse($status, $responseHeaders, $raw);
    }

    /**
     * @param  array<int, string>  $wrapperData
     * @return array{0: int, 1: array<string, string>}
     */
    private function parseHeaders(array $wrapperData): array
    {
        $status = 0;
        $headers = [];

        foreach ($wrapperData as $line) {
            if (! is_string($line)) {
                continue;
            }

            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $matches) === 1) {
                // A redirect chain would report several status lines; the last
                // one belongs to the response actually read.
                $status = (int) $matches[1];
                $headers = [];

                continue;
            }

            $separator = strpos($line, ':');

            if ($separator !== false) {
                $headers[strtolower(trim(substr($line, 0, $separator)))] = trim(substr($line, $separator + 1));
            }
        }

        return [$status, $headers];
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<int, string>
     */
    private function formatHeaders(array $headers): array
    {
        $formatted = [];

        foreach ($headers as $name => $value) {
            if (str_contains($value, "\r") || str_contains($value, "\n")) {
                throw NetworkException::malformedResponse($name, 'illegal characters in a request header');
            }

            $formatted[] = $name.': '.$value;
        }

        return $formatted;
    }
}
