<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\LicenseStatus;
use Licensify\Client\Security\Certificate;
use Licensify\Client\Tests\Support\CertificateFactory;
use Licensify\Client\UpdateInfo;
use PHPUnit\Framework\TestCase;

final class LicenseStatusTest extends TestCase
{
    public function test_it_parses_the_flat_contract_response(): void
    {
        $status = LicenseStatus::fromApiResponse([
            'success' => true,
            'valid' => true,
            'status' => 'active',
            'product' => 'MYCRM',
            'license_type' => 'subscription',
            'expires_at' => '2027-12-31',
            'installation_id' => 'inst_abc',
            'domain' => 'example.com',
            'update_available' => true,
            'latest_version' => '2.5.0',
            'offline_until' => '2026-10-06T12:00:00Z',
            'grace_expires_in' => 259200,
            'certificate' => 'a.b.c',
            'public_key_id' => 'key_2026_01',
        ], 1_800_000_000);

        $this->assertTrue($status->isValid());
        $this->assertSame('active', $status->status);
        $this->assertSame('MYCRM', $status->productCode);
        $this->assertSame('subscription', $status->licenseType);
        $this->assertSame('inst_abc', $status->installationId);
        $this->assertSame('example.com', $status->domain);
        $this->assertTrue($status->updateAvailable);
        $this->assertSame('2.5.0', $status->latestVersion);
        $this->assertSame(259200, $status->graceSecondsRemaining);
        $this->assertSame('a.b.c', $status->certificate);
        $this->assertSame('key_2026_01', $status->publicKeyId);
        $this->assertSame('2027-12-31', $status->expiresAt?->format('Y-m-d'));
        $this->assertSame('2026-10-06T12:00:00+00:00', $status->graceExpiresAt?->format(DATE_ATOM));
    }

    public function test_an_invalid_response_carries_its_error_code(): void
    {
        $status = LicenseStatus::fromApiResponse([
            'valid' => false,
            'status' => 'suspended',
            'error_code' => 'LICENSE_SUSPENDED',
            'message' => 'The license is suspended.',
            'details' => ['reason' => 'payment'],
        ]);

        $this->assertFalse($status->isValid());
        $this->assertSame('suspended', $status->status);
        $this->assertSame('LICENSE_SUSPENDED', $status->errorCode);
        $this->assertSame('The license is suspended.', $status->message);
    }

    public function test_absent_optional_fields_degrade_to_null(): void
    {
        $status = LicenseStatus::fromApiResponse(['valid' => true, 'status' => 'active']);

        $this->assertNull($status->licenseType);
        $this->assertNull($status->expiresAt);
        $this->assertNull($status->installationId);
        $this->assertNull($status->latestVersion);
        $this->assertSame(0, $status->graceSecondsRemaining);
    }

    public function test_malformed_types_are_ignored_rather_than_fatal(): void
    {
        // The response is untrusted input, so a string where a number belongs
        // must not blow up the caller.
        $status = LicenseStatus::fromApiResponse([
            'valid' => true,
            'status' => 'active',
            'grace_expires_in' => 'not a number',
            'expires_at' => 'not a date',
            'update_available' => 'yes',
            'certificate' => 42,
        ]);

        $this->assertSame(0, $status->graceSecondsRemaining);
        $this->assertNull($status->expiresAt);
        $this->assertFalse($status->updateAvailable);
        $this->assertNull($status->certificate);
    }

    public function test_a_certificate_backed_status_is_flagged_offline(): void
    {
        $issuedAt = 1_800_000_000;
        [$secret] = CertificateFactory::keypair();

        $certificate = Certificate::parse(CertificateFactory::mint($secret, 'key_2026_01', $issuedAt));

        $status = LicenseStatus::fromCertificate($certificate, 'MYCRM', now: $issuedAt + 60);

        $this->assertTrue($status->isValid());
        $this->assertTrue($status->offline);
        $this->assertSame('active', $status->status);
        $this->assertSame('key_2026_01', $status->publicKeyId);
        $this->assertSame(259140, $status->graceSecondsRemaining);
        $this->assertSame(1, $status->revocationCounter);
        $this->assertSame($issuedAt + 259200, $status->graceExpiresAt?->getTimestamp());
    }

    public function test_a_purely_local_status_takes_no_certificate_token(): void
    {
        // Returning a token from a locally derived status would invite callers to
        // treat it as proof; the token stays where it is.
        [$secret] = CertificateFactory::keypair();
        $certificate = Certificate::parse(CertificateFactory::mint($secret, 'key_2026_01', 1_800_000_000));

        $status = LicenseStatus::fromCertificate($certificate, 'MYCRM', now: 1_800_000_000);

        $this->assertNull($status->certificate);
    }

    public function test_offline_days_remaining_rounds_down(): void
    {
        $status = LicenseStatus::fromApiResponse([
            'valid' => true,
            'grace_expires_in' => (3 * 86400) + 3600,
        ]);

        $this->assertSame(3, $status->offlineDaysRemaining());
    }

    public function test_grace_expires_in_is_human_readable(): void
    {
        $status = LicenseStatus::fromApiResponse(['valid' => true, 'grace_expires_in' => (2 * 86400) + (3 * 3600) + 120]);

        $this->assertSame('2d 3h', $status->graceExpiresIn());
        $this->assertSame('3h 2m', LicenseStatus::fromApiResponse(['valid' => true, 'grace_expires_in' => (3 * 3600) + 120])->graceExpiresIn());
        $this->assertSame('45m', LicenseStatus::fromApiResponse(['valid' => true, 'grace_expires_in' => 2700])->graceExpiresIn());
        $this->assertSame('expired', LicenseStatus::fromApiResponse(['valid' => true, 'grace_expires_in' => 0])->graceExpiresIn());
    }

    public function test_invalid_builds_a_refusal_status(): void
    {
        $status = LicenseStatus::invalid('revoked', 'LICENSE_REVOKED', 'Revoked by an operator.', ['by' => 1]);

        $this->assertFalse($status->isValid());
        $this->assertSame('revoked', $status->status);
        $this->assertSame('LICENSE_REVOKED', $status->errorCode);
        $this->assertSame(['by' => 1], $status->details);
        $this->assertSame(0, $status->graceSecondsRemaining);
    }

    public function test_it_serialises_to_the_contract_field_names(): void
    {
        $status = LicenseStatus::fromApiResponse([
            'valid' => true,
            'status' => 'active',
            'product' => 'MYCRM',
            'certificate' => 'a.b.c',
        ], 1_800_000_000);

        $array = $status->toArray();

        $this->assertTrue($array['valid']);
        $this->assertSame('MYCRM', $array['product']);
        $this->assertFalse($array['offline']);
        $this->assertArrayHasKey('grace_expires_in', $array);
        $this->assertArrayHasKey('revocation_counter', $array);
    }

    public function test_update_info_uses_semver_not_string_comparison(): void
    {
        $update = UpdateInfo::fromArray([
            'update_available' => true,
            'latest_version' => '2.10.0',
        ], '2.9.0');

        $this->assertTrue($update->updateAvailable);
        $this->assertSame('2.10.0', $update->latestVersion);

        $this->assertFalse(UpdateInfo::fromArray(['latest_version' => '2.9.0'], '2.10.0')->updateAvailable);
    }

    public function test_a_pre_release_never_counts_as_newer_than_its_release(): void
    {
        $this->assertFalse(UpdateInfo::fromArray(['latest_version' => '2.5.0-beta.1'], '2.5.0')->updateAvailable);
        $this->assertTrue(UpdateInfo::fromArray(['latest_version' => '2.5.0'], '2.5.0-beta.1')->updateAvailable);
    }

    public function test_update_info_carries_the_release_metadata(): void
    {
        $update = UpdateInfo::fromArray([
            'latest_version' => '3.0.0',
            'release_type' => 'major',
            'release_notes' => 'Notes',
            'published_at' => '2026-09-01T10:00:00Z',
            'download_available' => true,
            'minimum_php_version' => '8.3',
            'minimum_laravel_version' => '11.0',
            'changelog_url' => 'https://licensing.test/changelog',
            'requires_full_download' => true,
        ], '2.9.9');

        $this->assertTrue($update->updateAvailable);
        $this->assertTrue($update->downloadAvailable);
        $this->assertTrue($update->requiresFullDownload);
        $this->assertSame('major', $update->releaseType);
        $this->assertSame('2026-09-01T10:00:00+00:00', $update->publishedAt?->format(DATE_ATOM));
        $this->assertTrue($update->isCompatibleWith('8.5', '12.0'));
        $this->assertFalse($update->isCompatibleWith('8.2', '12.0'));
        $this->assertFalse($update->isCompatibleWith('8.5', '10.0'));
    }
}
