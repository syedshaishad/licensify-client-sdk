<?php

declare(strict_types=1);

namespace Licensify\Client\Http;

use Licensify\Client\Exception\NetworkException;

/**
 * cURL transport. The SDK has no Guzzle/HTTPlug dependency on purpose — the
 * customer's software is already the thing we are protecting, so every moving
 * part it pulls in is attack surface.
 */
final class CurlTransport implements Transport
{
    public function __construct(
        private readonly float $timeout = 10.0,
        private readonly float $connectTimeout = 5.0,
        private readonly bool $verifySsl = true,
        private readonly string $userAgent = 'licensify-client-sdk',
    ) {}

    public static function isSupported(): bool
    {
        return function_exists('curl_init');
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): ApiResponse
    {
        $handle = curl_init();

        if ($handle === false) {
            throw NetworkException::unreachable($url, 'curl could not be initialised');
        }

        $responseHeaders = [];

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => (int) round($this->timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) round($this->connectTimeout * 1000),
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => $this->formatHeaders($headers),
            CURLOPT_HEADERFUNCTION => function ($_handle, string $line) use (&$responseHeaders): int {
                $length = strlen($line);
                $separator = strpos($line, ':');

                if ($separator !== false) {
                    $responseHeaders[strtolower(trim(substr($line, 0, $separator)))] = trim(substr($line, $separator + 1));
                }

                return $length;
            },
        ]);

        if ($body !== null && $body !== '') {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $raw = curl_exec($handle);

        if ($raw === false) {
            $message = curl_error($handle);
            $code = curl_errno($handle);

            curl_close($handle);

            throw NetworkException::unreachable($url, $message !== '' ? $message : 'transport failure', $code);
        }

        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        curl_close($handle);

        return new ApiResponse($status, $responseHeaders, (string) $raw);
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
                // Header injection: never forward a value that could terminate
                // the header block and append attacker-chosen headers.
                throw NetworkException::malformedResponse($name, 'illegal characters in a request header');
            }

            $formatted[] = $name.': '.$value;
        }

        return $formatted;
    }
}
