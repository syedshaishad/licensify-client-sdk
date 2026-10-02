<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Feature;

use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Exception\GraceExpiredException;
use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Exception\VerificationException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\License;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Support\Configuration;
use Licensify\Client\Tests\Support\CertificateFactory;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\FrozenClock;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * The behaviour that makes the licensing real: no access without a verifiable
 * certificate (contract §5.2, §15, §53).
 */
final class FailClosedTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private string $secretKey;

    private string $publicKeyB64;

    private FrozenClock $clock;

    private FakeTransport $transport;

    protected function setUp(): void
    {
        [$this->secretKey, $this->publicKeyB64] = CertificateFactory::keypair();
        $this->clock = new FrozenClock(self::ISSUED_AT + 10);
        $this->transport = new FakeTransport;

        License::swap(null);
    }

    protected function tearDown(): void
    {
        License::swap(null);
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

    private function certificate(array $overrides = []): string
    {
        return CertificateFactory::mint($this->secretKey, 'key_2026_01', self::ISSUED_AT, 259200, $overrides);
    }

    private function unreachable(): NetworkException
    {
        return NetworkException::unreachable('https://licensing.test', 'connection refused');
    }

    /**
     * @param  array<string, mixed>  $body
     */
    private function respond(int $status, array $body): void
    {
        $this->transport->push(new ApiResponse($status, [], json_encode($body, JSON_THROW_ON_ERROR)));
    }

    public function test_an_unreachable_server_with_no_certificate_refuses_access(): void
    {
        $this->transport->alwaysFail($this->unreachable());
        $manager = $this->manager();

        $this->expectException(GraceExpiredException::class);
        $this->expectExceptionMessageMatches('/no verifiable license certificate/i');

        $manager->validate();
    }

    public function test_valid_is_false_when_there_is_no_certificate_and_no_server(): void
    {
        $this->transport->alwaysFail($this->unreachable());
        $manager = $this->manager();

        $this->assertFalse($manager->valid(), 'no certificate and no server must be false, never true');
        $this->assertNull($manager->certificate());
        $this->assertNull($manager->graceExpiresAt());
        $this->assertSame(0, $manager->offlineDaysRemaining());
    }

    public function test_deleting_the_cache_does_not_grant_access(): void
    {
        // Establish a valid licence first.
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();

        $this->assertTrue($manager->validate()->isValid());

        // The operator wipes the cache, then the server goes away. Deleting the
        // cache must cost access, never grant it (contract §5.2.2).
        $manager->expireCache();
        $this->assertNull($manager->certificate());

        $this->transport->alwaysFail($this->unreachable());

        $this->assertFalse($manager->valid());
        $this->assertSame(2, $this->transport->requestCount(), 'the deleted cache must force re-validation');
    }

    public function test_deleting_the_cache_and_coming_back_online_restores_access(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $manager->validate();
        $manager->expireCache();

        $this->respond(200, ManagerFactory::validateResponse($this->certificate(['rev' => 2])));

        $this->assertTrue($manager->valid(), 'with the server reachable, re-validation restores access');
    }

    public function test_a_server_refusal_denies_access_and_destroys_the_certificate(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $manager->validate();

        // The server now reports the licence as revoked (HTTP 200 with
        // `valid:false`, per contract §1.3).
        $this->respond(200, [
            'success' => true,
            'valid' => false,
            'status' => 'revoked',
            'error_code' => 'LICENSE_REVOKED',
            'message' => 'The license has been revoked.',
        ]);

        $status = $manager->validate(force: true);

        $this->assertFalse($status->isValid());
        $this->assertSame('LICENSE_REVOKED', $status->errorCode);
        $this->assertNull($manager->certificate(), 'a revoked licence must not keep its certificate');
        $this->assertFalse($manager->valid());
    }

    public function test_a_protocol_failure_surfaces_as_an_exception_not_a_grant(): void
    {
        $this->respond(401, [
            'success' => false,
            'error' => ['code' => 'INVALID_API_KEY', 'message' => 'Bad API key.'],
        ]);

        $manager = $this->manager();

        try {
            $manager->validate();
            $this->fail('A 401 must not be swallowed into a valid status.');
        } catch (LicenseException $e) {
            $this->assertSame('INVALID_API_KEY', $e->errorCode());
            $this->assertNull($manager->certificate());
        }
    }

    public function test_a_certificate_signed_by_an_untrusted_key_is_never_cached(): void
    {
        [$otherSecret] = CertificateFactory::keypair();

        $this->respond(200, ManagerFactory::validateResponse(
            CertificateFactory::mint($otherSecret, 'key_2026_01', self::ISSUED_AT),
        ));

        $manager = $this->manager();

        try {
            $manager->validate(force: true);
            $this->fail('An untrusted certificate must not be accepted.');
        } catch (VerificationException) {
            $this->assertNull($manager->certificate());
        }
    }

    public function test_an_unusable_response_body_never_counts_as_a_valid_answer(): void
    {
        // A body that is not JSON cannot be trusted, so the call falls through to
        // the offline path — which has no certificate and therefore refuses.
        $this->transport->push(new ApiResponse(200, [], 'not json at all'));
        $manager = $this->manager();

        $this->assertFalse($manager->valid());

        $this->expectException(GraceExpiredException::class);

        $manager->validate();
    }

    public function test_a_response_without_a_certificate_denies_the_next_offline_call(): void
    {
        // With no certificate there is nothing to verify, so an unreachable server
        // afterwards must still deny.
        $this->respond(200, ManagerFactory::validateResponse(''));
        $manager = $this->manager();

        $status = $manager->validate(force: true);

        $this->assertTrue($status->isValid());
        $this->assertNull($manager->certificate());

        $this->transport->alwaysFail($this->unreachable());

        $this->assertFalse($manager->valid());
    }

    public function test_last_error_explains_why_valid_was_false(): void
    {
        $this->transport->alwaysFail($this->unreachable());
        $manager = $this->manager();

        $this->assertFalse($manager->valid());

        $error = $manager->lastError();

        $this->assertInstanceOf(GraceExpiredException::class, $error);
        $this->assertSame('NO_VALID_CERTIFICATE', $error?->errorCode());
    }

    public function test_clear_all_forces_a_full_rebuild(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $id = $manager->installationId();
        $manager->validate();

        $manager->clearAll();

        $this->assertNull($manager->certificate());
        $this->assertNotSame($id, $manager->installationId(), 'a full clear must mint a new installation id');
    }

    public function test_the_static_facade_delegates_to_the_swapped_manager(): void
    {
        $this->transport->alwaysFail($this->unreachable());
        $manager = $this->manager();

        License::swap($manager);

        $this->assertFalse(License::valid());
        $this->assertNull(License::certificate());
        $this->assertNull(License::graceExpiresAt());
        $this->assertSame(0, License::offlineDaysRemaining());

        $this->expectException(GraceExpiredException::class);

        License::validate();
    }

    public function test_deactivation_destroys_the_cached_certificate(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $manager->validate();
        $this->assertNotNull($manager->certificate());

        $this->respond(200, ManagerFactory::envelope(['deactivated' => true, 'remaining_activations' => 0]));

        $this->assertTrue($manager->deactivate('moving to a new host'));
        $this->assertNull($manager->certificate());
        $this->assertFalse($manager->valid());
    }

    public function test_a_refused_deactivation_reports_false_and_keeps_the_certificate(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $manager->validate();

        $this->respond(200, ManagerFactory::envelope(['deactivated' => false]));

        $this->assertFalse($manager->deactivate(null));
        $this->assertNotNull($manager->certificate());
    }

    public function test_an_expired_certificate_is_never_usable(): void
    {
        // A certificate minted already-expired is refused at the door, and nothing
        // is cached that could keep working later.
        $this->respond(200, ManagerFactory::validateResponse($this->certificate([
            'iat' => self::ISSUED_AT - 100_000,
            'nbf' => self::ISSUED_AT - 100_000,
            'exp' => self::ISSUED_AT - 40_000,
        ])));
        $manager = $this->manager();

        try {
            $manager->validate(force: true);
        } catch (GraceExpiredException) {
            // Expected: the window closed before this call.
        }

        $this->assertFalse($manager->valid());
    }

    public function test_a_hand_edited_cache_cannot_mint_a_certificate(): void
    {
        $this->respond(200, ManagerFactory::validateResponse($this->certificate()));
        $manager = $this->manager();
        $manager->validate();

        // Someone writes a plausible-looking token into the cache by hand. The
        // signature will not verify, which is the entire point (contract §5.2).
        $forged = Base64Url::encode('{"alg":"ed25519","kid":"key_2026_01","typ":"LIC","v":1}')
            .'.'.Base64Url::encode('{"pcode":"MYCRM","rev":1,"exp":9999999999}')
            .'.'.Base64Url::encode(str_repeat('s', 64));

        $manager->cache()->put($manager->cache()->key('certificate'), $forged);

        $this->transport->alwaysFail($this->unreachable());

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/signature does not verify/');

        $manager->validate();
    }

    public function test_an_unconfigured_sdk_refuses_rather_than_assuming_a_licence(): void
    {
        $this->expectException(ConfigurationException::class);

        new LicenseManager(Configuration::fromArray([
            'server_url' => '',
            'product_code' => '',
            'license_key' => '',
        ]));
    }

    public function test_a_plaintext_server_url_is_refused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/must use https/');

        new LicenseManager(Configuration::fromArray([
            'server_url' => 'http://licensing.example.com',
            'product_code' => 'MYCRM',
            'license_key' => 'AAAA',
        ]));
    }

    public function test_a_loopback_server_url_is_allowed_for_development(): void
    {
        $manager = new LicenseManager(Configuration::fromArray([
            'server_url' => 'http://127.0.0.1:8080',
            'product_code' => 'MYCRM',
            'license_key' => 'AAAA',
        ]));

        $this->assertSame('http://127.0.0.1:8080', $manager->config()->baseUrl());
    }

    public function test_the_configuration_never_exposes_a_secret(): void
    {
        $array = ManagerFactory::configuration()->toArray();

        $this->assertSame('(set)', $array['license_key']);
        $this->assertSame('(set)', $array['api_secret']);
        $this->assertSame('(set)', $array['api_key']);
        $this->assertStringNotContainsString('cs_test_secret', json_encode($array, JSON_THROW_ON_ERROR));
    }
}
