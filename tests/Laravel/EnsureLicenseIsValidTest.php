<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel;

use Illuminate\Http\Request;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\Laravel\Http\Middleware\EnsureLicenseIsValid;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Tests\Support\CertificateFactory;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\FrozenClock;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * The middleware is the part of the bridge that decides whether a customer
 * gets in.
 *
 * It must never let a request through on a licence that cannot be proven, and
 * it must say why in a form a customer's application can act on.
 */
final class EnsureLicenseIsValidTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const GRACE = 259200;

    private string $secretKey;

    private string $publicKeyB64;

    private FrozenClock $clock;

    private FakeTransport $transport;

    protected function setUp(): void
    {
        parent::setUp();

        [$this->secretKey, $this->publicKeyB64] = CertificateFactory::keypair();
        $this->clock = new FrozenClock(self::ISSUED_AT + 10);
        $this->transport = new FakeTransport;
    }

    private function manager(): LicenseManager
    {
        return ManagerFactory::make(
            $this->transport,
            $this->clock,
            [],
            Keyring::bootstrap()->add('key_2026_01', $this->publicKeyB64),
        );
    }

    private function certificate(): string
    {
        return CertificateFactory::mint($this->secretKey, 'key_2026_01', self::ISSUED_AT, self::GRACE);
    }

    private function queueValidAnswer(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));
    }

    public function test_a_valid_licence_lets_the_request_through(): void
    {
        $this->queueValidAnswer();

        $reached = false;

        $response = (new EnsureLicenseIsValid($this->manager()))->handle(
            Request::create('/reports', 'GET'),
            function (Request $request) use (&$reached): Response {
                $reached = true;

                return new Response('the report', 200);
            },
        );

        $this->assertTrue($reached, 'the request never reached the application');
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('the report', $response->getContent());
    }

    public function test_a_licence_the_server_refuses_is_a_forbidden_json_response(): void
    {
        // The documented shape for a recoverable licence-state outcome: the
        // transport worked, the licence did not.
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate(), ['valid' => false, 'status' => 'expired']),
            JSON_THROW_ON_ERROR,
        )));

        $reached = false;

        $response = (new EnsureLicenseIsValid($this->manager()))->handle(
            Request::create('/reports', 'GET'),
            function (Request $request) use (&$reached): Response {
                $reached = true;

                return new Response('the report', 200);
            },
        );

        $this->assertFalse($reached, 'the request reached the application without a valid licence');
        $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());

        $body = json_decode((string) $response->getContent(), true);

        $this->assertIsArray($body);
        $this->assertFalse($body['success']);
        $this->assertArrayHasKey('code', $body['error']);
        $this->assertArrayHasKey('message', $body['error']);
    }

    public function test_an_unreachable_server_with_no_certificate_is_refused(): void
    {
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $reached = false;

        $response = (new EnsureLicenseIsValid($this->manager()))->handle(
            Request::create('/reports', 'GET'),
            function (Request $request) use (&$reached): Response {
                $reached = true;

                return new Response('the report', 200);
            },
        );

        $this->assertFalse($reached, 'an unreachable server read as a valid licence');
        $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());

        $body = json_decode((string) $response->getContent(), true);

        $this->assertFalse($body['success']);
        $this->assertSame('NO_VALID_CERTIFICATE', $body['error']['code']);
        $this->assertTrue($body['error']['grace_expired'], 'the operator should be told the grace is gone');
    }

    public function test_the_denial_message_tells_the_operator_what_to_do(): void
    {
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $response = (new EnsureLicenseIsValid($this->manager()))->handle(
            Request::create('/reports', 'GET'),
            fn (Request $request): Response => new Response('the report', 200),
        );

        $body = json_decode((string) $response->getContent(), true);

        $this->assertStringContainsString('licensing server', $body['error']['message']);
    }

    public function test_a_forced_check_ignores_the_cached_certificate(): void
    {
        $this->queueValidAnswer();

        $manager = $this->manager();
        $manager->validate();

        $this->assertSame(1, $this->transport->requestCount());

        // The server goes away.
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $request = Request::create('/reports', 'GET', ['license_force_refresh' => '1']);

        $response = (new EnsureLicenseIsValid($manager))->handle(
            $request,
            fn (Request $request): Response => new Response('the report', 200),
        );

        $this->assertSame(2, $this->transport->requestCount(), 'a forced check did not contact the server');
        $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
    }

    public function test_the_status_method_answers_without_throwing(): void
    {
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $middleware = new EnsureLicenseIsValid($this->manager());

        $this->assertNull($middleware->status(), 'an unprovable licence reported a status');
    }
}
