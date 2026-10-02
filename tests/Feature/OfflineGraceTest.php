<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Feature;

use Licensify\Client\Exception\GraceExpiredException;
use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Exception\VerificationException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Tests\Support\CertificateFactory;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\FrozenClock;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * The offline grace window, end to end with no network at all.
 *
 * These are the tests that matter most: they prove that access survives a server
 * outage for exactly as long as the signed certificate allows, and not a moment
 * longer.
 */
final class OfflineGraceTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const GRACE = 259200;

    private string $secretKey;

    private string $publicKeyB64;

    private FrozenClock $clock;

    private FakeTransport $transport;

    protected function setUp(): void
    {
        [$this->secretKey, $this->publicKeyB64] = CertificateFactory::keypair();
        $this->clock = new FrozenClock(self::ISSUED_AT + 10);
        $this->transport = new FakeTransport;
    }

    private function keyring(): Keyring
    {
        return Keyring::bootstrap()->add('key_2026_01', $this->publicKeyB64);
    }

    private function certificate(array $overrides = []): string
    {
        return CertificateFactory::mint($this->secretKey, 'key_2026_01', self::ISSUED_AT, self::GRACE, $overrides);
    }

    private function manager(array $configuration = []): LicenseManager
    {
        return ManagerFactory::make($this->transport, $this->clock, $configuration, $this->keyring());
    }

    public function test_a_successful_validation_caches_the_certificate(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $status = $manager->validate();

        $this->assertTrue($status->isValid());
        $this->assertFalse($status->offline, 'the first call is a live server answer');
        $this->assertNotNull($manager->certificate());
        $this->assertSame(1, $manager->cache()->get($manager->cache()->key('rev-floor')));
    }

    public function test_a_cached_certificate_serves_the_licence_while_the_server_is_down(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        // The server goes away entirely.
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $this->clock->advance(3600);
        $status = $manager->validate();

        $this->assertTrue($status->isValid());
        $this->assertTrue($status->offline);
        $this->assertSame(self::ISSUED_AT + self::GRACE, $status->graceExpiresAt?->getTimestamp());
        $this->assertSame(1, $this->transport->requestCount(), 'a valid cached certificate needs no request');
    }

    public function test_offline_status_carries_the_remaining_grace(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));
        $this->clock->advance(86400);

        $status = $manager->validate();

        // 259200 s of grace, 24 h and 10 s of which have now elapsed.
        $this->assertSame(172790, $status->graceSecondsRemaining);
        $this->assertSame(1, $status->offlineDaysRemaining(), 'a partial day is not a whole day');
        $this->assertSame('1d 23h', $status->graceExpiresIn());
    }

    public function test_the_grace_window_closes_and_access_is_refused(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        // Step past `exp` plus the leeway the manager allows for clock drift.
        $this->clock->set(self::ISSUED_AT + self::GRACE + 120);

        $this->expectException(GraceExpiredException::class);
        $this->expectExceptionMessageMatches('/grace window closed/i');

        $manager->validate();
    }

    public function test_valid_is_false_once_the_grace_window_has_closed(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));
        $this->clock->set(self::ISSUED_AT + self::GRACE + 120);

        // valid() must never throw: it is the boolean gate product software uses.
        $this->assertFalse($manager->valid());
    }

    public function test_a_force_check_skips_the_cached_certificate(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        // A forced check must surface the outage rather than quietly serving the
        // cache the caller asked it to bypass.
        $this->expectException(NetworkException::class);

        $manager->validate(force: true);
    }

    public function test_a_revoked_licence_is_refused_offline(): void
    {
        // rev is bumped on suspend/revoke/domain change (contract §5.2), so a
        // certificate carrying the old counter is refused once a newer one has
        // been seen.
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate(['rev' => 7])),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $manager->cache()->put($manager->cache()->key('certificate'), $this->certificate(['rev' => 3]));
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/rev 3.*rev 7/');

        $manager->validate();
    }

    public function test_a_certificate_that_is_not_yet_valid_is_refused(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate(['nbf' => self::ISSUED_AT + 7200])),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/not valid before/');

        $manager->validate(force: true);
    }

    public function test_the_revocation_floor_never_moves_backwards(): void
    {
        $this->transport->push(
            new ApiResponse(200, [], json_encode(ManagerFactory::validateResponse($this->certificate(['rev' => 9])), JSON_THROW_ON_ERROR)),
            new ApiResponse(200, [], json_encode(ManagerFactory::validateResponse($this->certificate(['rev' => 2])), JSON_THROW_ON_ERROR)),
        );

        $manager = $this->manager();

        $manager->validate();
        $this->assertSame(9, $manager->cache()->get($manager->cache()->key('rev-floor')));
        $this->assertSame($this->certificate(['rev' => 9]), $manager->certificate());

        // A lower `rev` is refused outright: accepting it would let a replayed
        // old token roll trust backwards past a suspension.
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/rev 2.*rev 9/');

        $manager->validate(force: true);
    }

    public function test_a_tampered_cached_certificate_is_refused_offline(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        // Someone edits the cache file to make a suspended licence read active.
        $token = (string) $manager->certificate();
        [$header, , $signature] = explode('.', $token);
        $forged = json_decode(Base64Url::decode(explode('.', $token)[1]), true);
        $forged['status'] = 'active';

        $manager->cache()->put(
            $manager->cache()->key('certificate'),
            $header.'.'.Base64Url::encode(json_encode($forged, JSON_THROW_ON_ERROR)).'.'.$signature,
        );

        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/signature does not verify/');

        $manager->validate();
    }

    public function test_a_certificate_for_another_installation_is_refused(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate([
                'inst' => 'inst_ffffffffffffffffffffffffffffffff',
                'sub' => 'inst_ffffffffffffffffffffffffffffffff',
            ])),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/bound to a different installation/');

        $manager->validate(force: true);
    }

    public function test_a_certificate_for_another_product_is_refused(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate(['pcode' => 'OTHERPRODUCT'])),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/bound to a different product/');

        $manager->validate(force: true);
    }

    public function test_an_unknown_signing_key_triggers_a_keyring_bootstrap(): void
    {
        // The operator has pinned nothing, so the SDK discovers the published key
        // from the server and then verifies the certificate (contract §5.1).
        $manager = ManagerFactory::make($this->transport, $this->clock, [], Keyring::bootstrap());

        $this->transport->push(
            new ApiResponse(200, [], json_encode(ManagerFactory::validateResponse($this->certificate()), JSON_THROW_ON_ERROR)),
            new ApiResponse(200, [], json_encode([
                'algorithm' => 'ed25519',
                'active_kid' => 'key_2026_01',
                'keys' => [['kid' => 'key_2026_01', 'public_key' => $this->publicKeyB64]],
            ], JSON_THROW_ON_ERROR)),
        );

        $status = $manager->validate(force: true);

        $this->assertTrue($status->isValid());
        $this->assertTrue($manager->keyring()->has('key_2026_01'));
    }

    public function test_grace_expiry_and_installation_id_are_readable_without_a_request(): void
    {
        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($this->certificate()),
            JSON_THROW_ON_ERROR,
        )));

        $manager = $this->manager();
        $manager->validate();

        $before = $this->transport->requestCount();

        $this->assertSame(self::ISSUED_AT + self::GRACE, $manager->graceExpiresAt()?->getTimestamp());

        // 10 seconds of a 3-day window have elapsed, and whole days are rounded
        // down, so the honest answer is 2 rather than a reassuring 3.
        $this->assertSame(2, $manager->offlineDaysRemaining());
        $this->assertSame(ManagerFactory::INSTALLATION_ID, $manager->installationId());
        $this->assertSame($before, $this->transport->requestCount());
    }
}
