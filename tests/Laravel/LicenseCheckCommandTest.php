<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Laravel;

use Licensify\Client\Exception\NetworkException;
use Licensify\Client\Http\ApiResponse;
use Licensify\Client\Laravel\Console\LicenseCheckCommand;
use Licensify\Client\LicenseManager;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Tests\Laravel\Support\TestApplication;
use Licensify\Client\Tests\Support\CertificateFactory;
use Licensify\Client\Tests\Support\FakeTransport;
use Licensify\Client\Tests\Support\FrozenClock;
use Licensify\Client\Tests\Support\ManagerFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * `php artisan license:check` is what an operator runs when a customer says
 * "it says my licence is invalid".
 *
 * The exit code matters as much as the wording: it is usable as a deployment
 * gate or a monitoring probe, and a licence that cannot be proven has to exit
 * non-zero.
 */
final class LicenseCheckCommandTest extends TestCase
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

    /**
     * @param  array<string, mixed>  $arguments
     * @return array{0: int, 1: string}
     */
    private function execute(array $arguments = []): array
    {
        $app = new TestApplication;

        $manager = ManagerFactory::make(
            $this->transport,
            $this->clock,
            [],
            Keyring::bootstrap()->add('key_2026_01', $this->publicKeyB64),
        );

        $app->instance(LicenseManager::class, $manager);

        $command = new LicenseCheckCommand;
        $command->setLaravel($app);

        $output = new BufferedOutput;
        $exit = $command->run(new ArrayInput($arguments), $output);

        return [$exit, $output->fetch()];
    }

    private function queueValidAnswer(): void
    {
        $certificate = CertificateFactory::mint($this->secretKey, 'key_2026_01', self::ISSUED_AT, self::GRACE);

        $this->transport->push(new ApiResponse(200, [], json_encode(
            ManagerFactory::validateResponse($certificate),
            JSON_THROW_ON_ERROR,
        )));
    }

    public function test_a_valid_licence_exits_zero(): void
    {
        $this->queueValidAnswer();

        [$exit, $output] = $this->execute();

        $this->assertSame(0, $exit);
        $this->assertStringContainsString('Licence is valid.', $output);
    }

    public function test_a_refused_licence_exits_non_zero(): void
    {
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        [$exit, $output] = $this->execute();

        $this->assertSame(1, $exit, 'an unprovable licence passed');
        $this->assertStringContainsString('Licence is NOT valid.', $output);
    }

    public function test_the_json_output_is_machine_readable(): void
    {
        $this->queueValidAnswer();

        [$exit, $output] = $this->execute(['--json' => true]);

        $this->assertSame(0, $exit);

        $payload = json_decode($output, true);

        $this->assertIsArray($payload, 'the JSON output did not parse');
        $this->assertTrue($payload['valid']);
        $this->assertArrayHasKey('installation_id', $payload);
        $this->assertArrayHasKey('grace_expires_at', $payload);
        $this->assertContains('key_2026_01', $payload['trusted_keys']);
    }

    public function test_the_json_output_of_a_refused_licence_carries_the_reason(): void
    {
        $this->transport->alwaysFail(NetworkException::unreachable('https://licensing.test', 'connection refused'));

        [$exit, $output] = $this->execute(['--json' => true]);

        $this->assertSame(1, $exit);

        $payload = json_decode($output, true);

        $this->assertIsArray($payload);
        $this->assertFalse($payload['valid']);
        $this->assertArrayHasKey('error_code', $payload);
    }

    public function test_the_human_output_leads_with_the_headline(): void
    {
        $this->queueValidAnswer();

        [, $output] = $this->execute();

        $this->assertStringContainsString('valid:', $output);
        $this->assertStringContainsString('installation_id:', $output);
    }
}
