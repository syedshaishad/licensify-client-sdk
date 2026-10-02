<?php

declare(strict_types=1);

namespace Licensify\Client\Http;

use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\RequestSigner;
use Licensify\Client\Support\Configuration;

/**
 * Talks the licensing API (contract §4): signs the request, sends it, and
 * unwraps the response envelope.
 *
 * This class deliberately does no licensing *decisions*. It turns HTTP and
 * envelope shape into either a data array or an exception, and leaves the
 * "does this licence permit operation?" judgement to {@see LicenseManager}.
 */
final class LicenseClient
{
    /** Compact Ed25519 token proving a licence, valid for the grace window. */
    public const ENDPOINT_ACTIVATE = '/api/v1/license/activate';

    public const ENDPOINT_VALIDATE = '/api/v1/license/validate';

    public const ENDPOINT_DEACTIVATE = '/api/v1/license/deactivate';

    public const ENDPOINT_STATUS = '/api/v1/license/status';

    public const ENDPOINT_UPDATES = '/api/v1/updates/check';

    public const ENDPOINT_PUBLIC_KEY = '/api/v1/products/%s/public-key';

    public const ENDPOINT_PING = '/api/v1/ping';

    /**
     * `$signer` exists so a caller can pre-build one; when omitted it is derived
     * from the configuration, which yields no authentication headers at all if
     * no API credentials are set.
     */
    public function __construct(
        private readonly Configuration $config,
        private readonly Transport $transport,
        private readonly ?RequestSigner $signer = null,
        private readonly string $userAgent = 'licensify-client-sdk/1.0.0',
    ) {}

    /**
     * Activates this installation. A repeat activation for the same
     * installation is a success, not an error (contract §7.7).
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function activate(array $payload): array
    {
        $data = $this->post(self::ENDPOINT_ACTIVATE, $payload);

        if (($data['already_activated'] ?? false) === true) {
            // Idempotent by contract: surfacing this as a failure would push
            // every installer to write a retry loop around it.
            return $data + ['activated' => true, 'idempotent' => true];
        }

        return $data;
    }

    /**
     * Validates a licence. The response is the flat §1.3 body, not an envelope.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function validate(array $payload): array
    {
        return $this->post(self::ENDPOINT_VALIDATE, $payload, envelope: false);
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function deactivate(array $payload): array
    {
        return $this->post(self::ENDPOINT_DEACTIVATE, $payload);
    }

    /**
     * Licence-level state only — no installation, no certificate (contract §4).
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function status(array $payload): array
    {
        return $this->post(self::ENDPOINT_STATUS, $payload);
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function checkUpdates(array $payload): array
    {
        return $this->post(self::ENDPOINT_UPDATES, $payload);
    }

    /**
     * Active and retired public keys, so an SDK can bootstrap trust without a
     * hardcoded copy (contract §5.1).
     *
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function publicKeyring(): array
    {
        $path = sprintf(self::ENDPOINT_PUBLIC_KEY, rawurlencode($this->config->productCode));
        $data = $this->get($path);

        return $data;
    }

    /**
     * Liveness probe plus server time, for clock-skew correction.
     *
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    public function ping(): array
    {
        return $this->get(self::ENDPOINT_PING);
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    private function post(string $path, array $payload, bool $envelope = true): array
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($body === false) {
            throw new LicenseException('The request payload could not be encoded as JSON.', 'REQUEST_NOT_ENCODABLE');
        }

        return $this->send('POST', $path, $body, $envelope);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    private function get(string $path): array
    {
        return $this->send('GET', $path, null, envelope: false);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws LicenseException
     */
    private function send(string $method, string $path, ?string $body, bool $envelope): array
    {
        $url = $this->config->endpoint($path);

        $headers = [
            'Accept' => 'application/json',
            'User-Agent' => $this->userAgent,
        ];

        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
        }

        if ($this->signer !== null) {
            $headers += $this->signer->headers($method, $path, [], $body);
        }

        self::assertHeadersAreSafe($headers);

        $response = $this->transport->request($method, $url, $headers, $body);

        $decoded = $response->json();

        if ($decoded === null) {
            throw NetworkException::malformedResponse(
                $url,
                sprintf('HTTP %d with a non-JSON body: %s', $response->status, $response->excerpt()),
            );
        }

        if (! $response->isSuccessful()) {
            throw $this->errorFrom($response->status, $decoded, $url);
        }

        // A §1.2 error envelope can arrive with a 200 when a proxy rewrites the
        // status; the envelope is the authority, not the status line.
        if (array_key_exists('success', $decoded) && ($decoded['success'] ?? true) === false) {
            throw $this->errorFrom($response->status, $decoded, $url);
        }

        if (! $envelope) {
            return $decoded;
        }

        // A §1.1 envelope always carries `data`. Absent entirely means the server sent
        // something else, and guessing that an empty result is acceptable would
        // turn a malformed response into a silent no-op.
        if (! array_key_exists('data', $decoded) || ! is_array($decoded['data']) || array_is_list($decoded['data'])) {
            throw NetworkException::malformedResponse($url, 'the envelope has no usable "data" object');
        }

        return $decoded['data'];
    }

    /**
     * Configuration values reach the header block, so a value containing CR/LF
     * would let an attacker append headers of their own. The transports refuse
     * it too; checking here means it never depends on which transport is wired.
     *
     * @param  array<string, string>  $headers
     *
     * @throws NetworkException
     */
    private static function assertHeadersAreSafe(array $headers): void
    {
        foreach ($headers as $name => $value) {
            if (str_contains($value, "\r") || str_contains($value, "\n")) {
                throw NetworkException::malformedResponse(
                    $name,
                    'the value contains a line break and cannot be sent as a header',
                );
            }
        }
    }

    /**
     * @param  array<string, mixed>  $decoded
     *
     * @throws LicenseException
     */
    private function errorFrom(int $status, array $decoded, string $url): LicenseException
    {
        $error = is_array($decoded['error'] ?? null) ? $decoded['error'] : [];

        $code = is_string($error['code'] ?? null) ? $error['code'] : $this->fallbackCode($status);

        // The server's message is included because it is what the operator reads
        // in a log, but it never carries a secret: the SDK never puts the licence
        // key or the API secret in a request it would not echo.
        $message = is_string($error['message'] ?? null) && trim($error['message']) !== ''
            ? $error['message']
            : sprintf('HTTP %d from %s.', $status, $url);

        $details = is_array($error['details'] ?? null) ? $error['details'] : [];

        return LicenseException::withErrorCode($code, $message, $details);
    }

    private function fallbackCode(int $status): string
    {
        return match ($status) {
            401 => 'INVALID_API_KEY',
            403 => 'DOWNLOAD_NOT_AUTHORIZED',
            404 => 'NOT_FOUND',
            409 => 'PRODUCT_MISMATCH',
            422 => 'VALIDATION_FAILED',
            429 => 'RATE_LIMIT_EXCEEDED',
            default => $status >= 500 ? 'SERVER_ERROR' : 'NOT_FOUND',
        };
    }
}
