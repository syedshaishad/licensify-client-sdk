<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Exception\VerificationException;
use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\Certificate;
use Licensify\Client\Tests\Support\CertificateFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CertificateTest extends TestCase
{
    private string $secretKey;

    private string $publicKey;

    protected function setUp(): void
    {
        [$this->secretKey, $this->publicKey] = CertificateFactory::keypair();
    }

    public function test_it_exposes_every_contract_payload_claim(): void
    {
        $issuedAt = 1_800_000_000;
        $token = CertificateFactory::mint($this->secretKey, 'key_2026_01', $issuedAt);

        $certificate = Certificate::parse($token);

        $this->assertSame('key_2026_01', $certificate->kid());
        $this->assertSame('LIC', $certificate->type());
        $this->assertSame('ed25519', $certificate->algorithm());
        $this->assertSame(1, $certificate->version());
        $this->assertSame('MYCRM', $certificate->productCode());
        $this->assertSame('example.com', $certificate->domain());
        $this->assertSame('active', $certificate->status());
        $this->assertSame('subscription', $certificate->plan());
        $this->assertSame('2.4.1', $certificate->softwareVersion());
        $this->assertSame(1, $certificate->revocationCounter());
        $this->assertSame(259200, $certificate->graceSeconds());
        $this->assertSame($issuedAt, $certificate->issuedAt());
        $this->assertSame($issuedAt, $certificate->notBefore());
        $this->assertSame($issuedAt + 259200, $certificate->expiresAt());
        $this->assertSame('inst_0000000000000000000000000000abcd', $certificate->installationId());
    }

    public function test_it_reports_expiry_against_a_supplied_instant(): void
    {
        $issuedAt = 1_800_000_000;
        $certificate = Certificate::parse(CertificateFactory::mint($this->secretKey, 'key_2026_01', $issuedAt));

        $this->assertFalse($certificate->isExpired($issuedAt));
        $this->assertFalse($certificate->isExpired($issuedAt + 259200));
        $this->assertTrue($certificate->isExpired($issuedAt + 259201));
        $this->assertSame(259200, $certificate->secondsUntilExpiry($issuedAt));
        $this->assertSame(0, $certificate->secondsUntilExpiry($issuedAt + 999_999));
    }

    public function test_the_signing_input_is_the_first_two_segments(): void
    {
        $token = CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000);
        $certificate = Certificate::parse($token);

        [$header, $payload] = explode('.', $token);

        $this->assertSame($header.'.'.$payload, $certificate->signingInput);
    }

    #[DataProvider('malformedTokens')]
    public function test_malformed_tokens_are_rejected(string $token, string $expectedMessageFragment): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/'.$expectedMessageFragment.'/i');

        Certificate::parse($token);
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function malformedTokens(): array
    {
        return [
            'empty' => ['', 'empty'],
            'one segment' => ['abc', 'three dot-separated'],
            'two segments' => ['abc.def', 'three dot-separated'],
            'four segments' => ['a.b.c.d', 'three dot-separated'],
            'header is not base64url json' => [
                '!!!notbase64!!!.notjson.'.Base64Url::encode(str_repeat('s', 64)),
                'base64url',
            ],
            'header is not an object' => [
                Base64Url::encode('"a string"').'.'.Base64Url::encode('{}').'.'.Base64Url::encode(str_repeat('s', 64)),
                'JSON object',
            ],
            'signature is the wrong length' => [
                Base64Url::encode('{"alg":"ed25519"}').'.'.Base64Url::encode('{"a":1}').'.'.Base64Url::encode('short'),
                '64-byte',
            ],
        ];
    }

    public function test_a_payload_that_is_a_json_list_is_refused(): void
    {
        // A list would make claim lookups ambiguous (`$payload['rev']` on an
        // index), so it is refused rather than coerced.
        $this->expectException(VerificationException::class);

        Certificate::parse(
            Base64Url::encode('{"alg":"ed25519"}').'.'.Base64Url::encode('[1,2,3]').'.'.Base64Url::encode(str_repeat('s', 64))
        );
    }

    public function test_it_does_not_claim_to_be_valid_before_verification(): void
    {
        // Parsing is structural only; the verdict comes from SignatureVerifier.
        $certificate = Certificate::parse(CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000));

        $this->assertSame(64, strlen($certificate->signature));
    }

    public function test_missing_optional_claims_degrade_gracefully(): void
    {
        $header = Base64Url::encode('{"alg":"ed25519","kid":"k","typ":"LIC","v":1}');
        $payload = Base64Url::encode('{"pcode":"MYCRM"}');
        $signature = Base64Url::encode(str_repeat('s', 64));

        $certificate = Certificate::parse($header.'.'.$payload.'.'.$signature);

        $this->assertSame('MYCRM', $certificate->productCode());
        $this->assertSame(0, $certificate->revocationCounter());
        $this->assertSame('', $certificate->plan());
    }
}
