<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Feature;

use Licensify\Client\Exception\LicenseException;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\FrozenClock;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * The update delivery path the installed software follows: check for a newer
 * published release, ask for the package, verify the bytes.
 */
final class UpdatePackageTest extends TestCase
{
    public function test_no_update_is_returned_as_null_and_no_download_is_requested(): void
    {
        $transport = new FakeTransport([
            // The flat response the API serves.
            new \Licensify\Client\Http\ApiResponse(200, [], json_encode([
                'success' => true,
                'update_available' => false,
                'current_version' => '2.4.1',
            ])),
        ]);

        $manager = ManagerFactory::make($transport, new FrozenClock(1));

        $this->assertNull($manager->updatePackage());
        $this->assertSame(1, $transport->requestCount());
        $this->assertSame('/api/v1/updates/check', $this->pathOf($transport->lastRequest()['url']));
    }

    public function test_an_available_update_returns_the_package_grant(): void
    {
        $transport = new FakeTransport([
            // Raw (flat) update check response as served by the API.
            new \Licensify\Client\Http\ApiResponse(200, [], json_encode([
                'success' => true,
                'update_available' => true,
                'latest_version' => '2.5.0',
                'download_available' => true,
            ])),
            // Raw (flat) download grant response as served by the API.
            new \Licensify\Client\Http\ApiResponse(200, [], json_encode([
                'success' => true,
                'url' => 'https://licensing.test/api/v1/downloads/abc123',
                'version' => '2.5.0',
                'filename' => 'MYCRM-2.5.0.zip',
                'expires_at' => '2027-01-01T00:00:00+00:00',
                'size_bytes' => 18453220,
                'checksum_algorithm' => 'sha256',
                'checksum' => 'sha256:'.str_repeat('a', 64),
            ])),
        ]);

        $manager = ManagerFactory::make($transport, new FrozenClock(1));

        $package = $manager->updatePackage();

        $this->assertNotNull($package);
        $this->assertSame('2.5.0', $package->version);
        $this->assertSame('MYCRM-2.5.0.zip', $package->filename);
        $this->assertSame(18453220, $package->sizeBytes);
        $this->assertSame('https://licensing.test/api/v1/downloads/abc123', $package->url);
        $this->assertSame(str_repeat('a', 64), $package->sha256);

        $downloaded = $transport->requests[1];
        $this->assertSame('POST', $downloaded['method']);
        $this->assertSame('https://licensing.test/api/v1/downloads/request', $downloaded['url']);
        $this->assertSame('2.5.0', json_decode((string) $downloaded['body'], true)['version']);
    }

    public function test_the_package_is_rejected_when_the_grant_is_incomplete(): void
    {
        $transport = new FakeTransport([
            new \Licensify\Client\Http\ApiResponse(200, [], json_encode([
                'success' => true,
                'update_available' => true,
                'latest_version' => '2.5.0',
                'download_available' => true,
            ])),
            new \Licensify\Client\Http\ApiResponse(200, [], json_encode([
                'success' => true,
                'filename' => 'MYCRM-2.5.0.zip',
                'checksum' => 'sha256:'.str_repeat('b', 64),
            ])),
        ]);

        $manager = ManagerFactory::make($transport, new FrozenClock(1));

        $this->expectException(LicenseException::class);
        $this->expectExceptionMessage('complete download grant');

        $manager->updatePackage();
    }

    public function test_the_package_verifies_only_matching_bytes(): void
    {
        $bytes = 'the release bytes';

        $file = tempnam(sys_get_temp_dir(), 'pkg').'.zip';
        file_put_contents($file, $bytes);

        $good = new \Licensify\Client\UpdatePackage(
            url: 'https://example.test/pkg.zip',
            version: '2.5.0',
            filename: 'pkg.zip',
            sizeBytes: strlen($bytes),
            expiresAt: null,
            sha256: hash_file('sha256', $file),
        );

        $bad = new \Licensify\Client\UpdatePackage(
            url: 'https://example.test/pkg.zip',
            version: '2.5.0',
            filename: 'pkg.zip',
            sizeBytes: strlen($bytes),
            expiresAt: null,
            sha256: str_repeat('0', 64),
        );

        $this->assertTrue($good->verify($file));
        $this->assertFalse($bad->verify($file));

        unlink($file);
    }

    public function test_the_package_reports_a_missing_file_clearly(): void
    {
        $package = new \Licensify\Client\UpdatePackage(
            url: 'https://example.test/pkg.zip',
            version: '2.5.0',
            filename: 'pkg.zip',
            sizeBytes: 123,
            expiresAt: null,
            sha256: str_repeat('c', 64),
        );

        $this->expectException(LicenseException::class);
        $this->expectExceptionMessage('could not be read');

        $package->verify(sys_get_temp_dir().'/definitely-does-not-exist.zip');
    }

    private function pathOf(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH);

        return is_string($path) ? $path : $url;
    }
}
