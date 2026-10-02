<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Feature;

use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\Http\LicenseClient;
use Licensify\Client\Security\RequestSigner;
use Licensify\Client\Support\AuthScheme;
use Licensify\Client\Support\Configuration;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Wire-level behaviour: the endpoints of contract §4, the envelope of §1, and
 * the HMAC headers of §3.2.
 */
final class LicenseClientTest extends TestCase
{
    private FakeTransport $transport;

    private LicenseClient $client;

    protected function setUp(): void
    {
        $this->transport = new FakeTransport;
        $this->client = self::client($this->transport);
    }

    private static function client(FakeTransport $transport, array $configuration = []): LicenseClient
    {
        $config = ManagerFactory::configuration($configuration);

        return new LicenseClient($config, $transport, self::signerFor($config));
    }

    private static function signerFor(Configuration $config): ?RequestSigner
    {
        if (! $config->hasApiCredentials()) {
            return null;
        }

        return RequestSigner::fromCredentials(
            (string) $config->apiKey,
            (string) $config->apiSecret,
            $config->authScheme,
        );
    }

    private function respond(int $status, array|string $body): void
    {
        $this->transport->push(new ApiResponse(
            $status,
            [],
            is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR),
        ));
    }

    public function test_validate_posts_to_the_contract_path_with_hmac_headers(): void
    {
        $this->respond(200, ['success' => true, 'valid' => true, 'status' => 'active']);

        $this->client->validate(['license_key' => 'k', 'product_code' => 'MYCRM']);

        $request = $this->transport->lastRequest();

        $this->assertSame('POST', $request['method']);
        $this->assertSame('https://licensing.test/api/v1/license/validate', $request['url']);
        $this->assertSame('application/json', $request['headers']['Content-Type']);
        $this->assertSame('lk_test', $request['headers']['X-License-Key']);
        $this->assertArrayHasKey('X-License-Signature', $request['headers']);
        $this->assertArrayHasKey('X-License-Nonce', $request['headers']);
        $this->assertArrayHasKey('X-License-Timestamp', $request['headers']);
        $this->assertStringContainsString('licensify-client-sdk', $request['headers']['User-Agent']);
    }

    public function test_the_signature_covers_the_exact_bytes_sent(): void
    {
        $this->respond(200, ['valid' => true]);

        $payload = ['license_key' => 'k', 'product_code' => 'MYCRM', 'domain' => 'example.com'];
        $this->client->validate($payload);

        $request = $this->transport->lastRequest();

        $canonical = RequestSigner::canonicalString(
            'POST',
            '/api/v1/license/validate',
            '',
            $request['body'],
            (int) $request['headers']['X-License-Timestamp'],
            $request['headers']['X-License-Nonce'],
        );

        $this->assertTrue(
            RequestSigner::verify('cs_test_secret', $canonical, $request['headers']['X-License-Signature']),
            'the server must be able to reproduce the signature from what it received',
        );

        $this->assertSame($payload, json_decode((string) $request['body'], true, 512, JSON_THROW_ON_ERROR));
    }

    public function test_validate_unwraps_the_flat_response_body(): void
    {
        $this->respond(200, ['success' => true, 'valid' => true, 'status' => 'active', 'certificate' => 'a.b.c']);

        $data = $this->client->validate([]);

        $this->assertSame('a.b.c', $data['certificate']);
        $this->assertTrue($data['valid']);
    }

    public function test_activate_unwraps_the_data_envelope(): void
    {
        $this->respond(200, ManagerFactory::envelope([
            'activation' => ['id' => 1],
            'certificate' => 'a.b.c',
            'public_key_id' => 'key_2026_01',
        ]));

        $data = $this->client->activate([]);

        $this->assertSame('a.b.c', $data['certificate']);
        $this->assertSame('key_2026_01', $data['public_key_id']);
        $this->assertSame('https://licensing.test/api/v1/license/activate', $this->transport->lastRequest()['url']);
    }

    public function test_a_repeat_activation_is_a_success(): void
    {
        // Contract §7.7: ALREADY_ACTIVATED is HTTP 200 and non-fatal.
        $this->respond(200, ManagerFactory::envelope(['already_activated' => true, 'certificate' => 'a.b.c']));

        $data = $this->client->activate([]);

        $this->assertTrue($data['activated']);
        $this->assertTrue($data['idempotent']);
    }

    public function test_deactivate_returns_the_server_decision(): void
    {
        $this->respond(200, ManagerFactory::envelope(['deactivated' => true, 'remaining_activations' => 2]));

        $this->assertTrue($this->client->deactivate([])['deactivated']);
        $this->assertSame('https://licensing.test/api/v1/license/deactivate', $this->transport->lastRequest()['url']);
    }

    public function test_status_takes_no_installation_id(): void
    {
        $this->respond(200, ManagerFactory::envelope(['status' => 'active']));

        $this->client->status(['license_key' => 'k', 'product_code' => 'MYCRM']);

        $body = $this->transport->lastBody();

        $this->assertArrayNotHasKey('installation_id', $body);
        $this->assertSame('https://licensing.test/api/v1/license/status', $this->transport->lastRequest()['url']);
    }

    public function test_updates_check_posts_the_running_version(): void
    {
        $this->respond(200, ManagerFactory::envelope(['update_available' => true, 'latest_version' => '2.5.0']));

        $this->client->checkUpdates(['current_version' => '2.4.1']);

        $this->assertSame('https://licensing.test/api/v1/updates/check', $this->transport->lastRequest()['url']);
        $this->assertSame('2.4.1', $this->transport->lastBody()['current_version']);
    }

    public function test_the_public_key_endpoint_is_get_and_product_scoped(): void
    {
        $this->respond(200, [
            'algorithm' => 'ed25519',
            'active_kid' => 'key_2026_01',
            'keys' => [['kid' => 'key_2026_01', 'public_key' => 'x']],
        ]);

        $data = $this->client->publicKeyring();

        $this->assertSame('GET', $this->transport->lastRequest()['method']);
        $this->assertSame('https://licensing.test/api/v1/products/MYCRM/public-key', $this->transport->lastRequest()['url']);
        $this->assertSame('key_2026_01', $data['active_kid']);
        $this->assertNull($this->transport->lastRequest()['body']);
    }

    public function test_a_product_code_is_percent_encoded_into_the_path(): void
    {
        $this->respond(200, ['keys' => []]);

        $client = self::client($this->transport, ['product_code' => 'my crm/prod']);
        $client->publicKeyring();

        $this->assertStringContainsString('/api/v1/products/my%20crm%2Fprod/public-key', $this->transport->lastRequest()['url']);
    }

    public function test_ping_reads_the_flat_body(): void
    {
        $this->respond(200, ['status' => 'ok', 'server_time' => '2026-10-03T12:00:00Z', 'server_unix' => 1_799_000_000]);

        $data = $this->client->ping();

        $this->assertSame('ok', $data['status']);
        $this->assertSame('https://licensing.test/api/v1/ping', $this->transport->lastRequest()['url']);
    }

    #[DataProvider('errorCases')]
    public function test_error_envelopes_become_exceptions_with_their_code(int $status, string $code): void
    {
        $this->respond($status, [
            'success' => false,
            'error' => ['code' => $code, 'message' => 'Refused.', 'details' => ['x' => 1]],
        ]);

        try {
            $this->client->activate([]);
            $this->fail('An error envelope must raise.');
        } catch (LicenseException $e) {
            $this->assertSame($code, $e->errorCode());
            $this->assertSame('Refused.', $e->getMessage());
            $this->assertSame(['x' => 1], $e->details());
            $this->assertTrue($e->hasErrorCode($code));
            $this->assertFalse($e->hasErrorCode('SOMETHING_ELSE'));
        }
    }

    /**
     * @return array<string, array{0: int, 1: string}>
     */
    public static function errorCases(): array
    {
        return [
            'bad credentials' => [401, 'INVALID_API_KEY'],
            'rate limited' => [429, 'RATE_LIMIT_EXCEEDED'],
            'malformed body' => [422, 'VALIDATION_FAILED'],
            'product missing' => [404, 'PRODUCT_NOT_FOUND'],
        ];
    }

    public function test_an_error_envelope_returned_with_a_200_is_still_an_error(): void
    {
        // A proxy rewriting the status must not turn a refusal into a grant.
        $this->respond(200, ['success' => false, 'error' => ['code' => 'LICENSE_REVOKED', 'message' => 'Gone.']]);

        try {
            $this->client->activate([]);
            $this->fail('A success:false envelope must raise even on HTTP 200.');
        } catch (LicenseException $e) {
            $this->assertSame('LICENSE_REVOKED', $e->errorCode());
            $this->assertSame('Gone.', $e->getMessage());
        }
    }

    public function test_an_error_body_without_a_code_falls_back_to_the_status(): void
    {
        $this->respond(429, ['success' => false, 'error' => ['message' => 'Slow down.']]);

        try {
            $this->client->activate([]);
            $this->fail('Expected an exception.');
        } catch (LicenseException $e) {
            $this->assertSame('RATE_LIMIT_EXCEEDED', $e->errorCode());
            $this->assertSame('Slow down.', $e->getMessage());
        }
    }

    public function test_a_non_json_body_is_a_network_failure(): void
    {
        $this->respond(502, '<html>bad gateway</html>');

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessageMatches('/non-JSON body/');

        $this->client->activate([]);
    }

    public function test_an_envelope_without_data_is_rejected(): void
    {
        $this->respond(200, ['success' => true]);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessageMatches('/"data"/');

        $this->client->activate([]);
    }

    public function test_no_credentials_means_no_authentication_headers(): void
    {
        // A licence key is never authentication (contract §3), so a deployment
        // without API credentials must send no malformed auth header at all.
        $client = self::client($this->transport, ['api_key' => null, 'api_secret' => null]);

        $this->respond(200, ['valid' => true]);
        $client->validate([]);

        $headers = $this->transport->lastRequest()['headers'];

        $this->assertArrayNotHasKey('X-License-Signature', $headers);
        $this->assertArrayNotHasKey('Authorization', $headers);
    }

    public function test_the_bearer_scheme_can_be_selected(): void
    {
        $client = self::client($this->transport, ['auth_scheme' => AuthScheme::Bearer]);

        $this->respond(200, ['valid' => true]);
        $client->validate([]);

        $this->assertSame('Bearer lk_test.cs_test_secret', $this->transport->lastRequest()['headers']['Authorization']);
    }

    public function test_a_header_injection_attempt_is_refused_before_sending(): void
    {
        $client = self::client($this->transport, ['api_key' => "lk_test\r\nX-Injected: yes"]);

        $this->respond(200, ['valid' => true]);

        try {
            $client->validate([]);
            $this->fail('Header injection must not reach the transport.');
        } catch (LicenseException) {
            $this->assertSame(0, $this->transport->requestCount());
        }
    }

    public function test_a_product_code_with_traversal_characters_cannot_rewrite_the_path(): void
    {
        $config = Configuration::fromArray([
            'server_url' => 'https://licensing.test',
            'product_code' => 'CRM',
            'license_key' => 'k',
        ]);

        $this->assertSame('https://licensing.test/api/v1/license/validate', $config->endpoint(LicenseClient::ENDPOINT_VALIDATE));
        $this->assertStringNotContainsString('..', $config->endpoint(LicenseClient::ENDPOINT_VALIDATE));
    }
}
