<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Exception\VerificationException;
use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\CanonicalJson;
use Licensify\Client\Security\Certificate;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Security\SignatureVerifier;
use Licensify\Client\Tests\Support\CertificateFactory;
use PHPUnit\Framework\TestCase;

final class SignatureVerifierTest extends TestCase
{
    private string $secretKey;

    private string $publicKeyB64;

    private Keyring $keyring;

    protected function setUp(): void
    {
        [$this->secretKey, $this->publicKeyB64] = CertificateFactory::keypair();

        $this->keyring = Keyring::bootstrap();
        $this->keyring->add('key_2026_01', $this->publicKeyB64);
    }

    public function test_it_accepts_a_genuine_certificate(): void
    {
        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000),
        );

        SignatureVerifier::verify($certificate, $this->keyring);

        $this->assertTrue(SignatureVerifier::isValid($certificate, $this->keyring));
    }

    public function test_it_accepts_the_contract_spelling_of_the_algorithm(): void
    {
        // The contract writes `EdDSA`; the server emits `ed25519`. Both verify.
        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000, algorithm: 'EdDSA'),
        );

        SignatureVerifier::verify($certificate, $this->keyring);

        $this->assertTrue(SignatureVerifier::isValid($certificate, $this->keyring));
    }

    public function test_it_rejects_a_certificate_signed_by_a_different_key(): void
    {
        [$otherSecret] = CertificateFactory::keypair();

        $certificate = Certificate::parse(
            CertificateFactory::mint($otherSecret, 'key_2026_01', 1_800_000_000),
        );

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/signature does not verify/i');

        SignatureVerifier::verify($certificate, $this->keyring);
    }

    public function test_it_rejects_a_tampered_payload(): void
    {
        $token = CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000);

        [$header, $payload, $signature] = explode('.', $token);

        // Escalate a revoked licence to active while keeping the original
        // signature: exactly the local-file attack of contract §5.2.
        $forged = json_decode(Base64Url::decode($payload), true);
        $forged['status'] = 'active';
        $forged['rev'] = 0;

        $tampered = $header.'.'.Base64Url::encode(json_encode($forged, JSON_THROW_ON_ERROR)).'.'.$signature;

        $this->expectException(VerificationException::class);

        SignatureVerifier::verify(Certificate::parse($tampered), $this->keyring);
    }

    public function test_it_rejects_an_unknown_kid(): void
    {
        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, 'key_never_published', 1_800_000_000),
        );

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/no trusted signing key/i');

        SignatureVerifier::verify($certificate, $this->keyring);
    }

    public function test_it_rejects_a_foreign_token_type(): void
    {
        // A token carrying `typ: JWT` must never be accepted here, which is why
        // the SDK never routes certificates through generic JWT middleware.
        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000, type: 'JWT'),
        );

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/token type/i');

        SignatureVerifier::verify($certificate, $this->keyring);
    }

    public function test_it_rejects_an_unsupported_algorithm(): void
    {
        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000, algorithm: 'HS256'),
        );

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/unsupported algorithm/i');

        SignatureVerifier::verify($certificate, $this->keyring);
    }

    public function test_it_rejects_a_certificate_without_a_kid(): void
    {
        $header = Base64Url::encode(CanonicalJson::encode(['alg' => 'ed25519', 'typ' => 'LIC', 'v' => 1]));
        $payload = Base64Url::encode(CanonicalJson::encode(['pcode' => 'MYCRM']));
        $signature = Base64Url::encode(sodium_crypto_sign_detached(
            $header.'.'.$payload,
            $this->secretKey,
        ));

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('/does not name a signing key/i');

        SignatureVerifier::verify(Certificate::parse($header.'.'.$payload.'.'.$signature), $this->keyring);
    }

    public function test_a_rotated_key_verifies_while_the_retired_one_still_works(): void
    {
        // Contract §5.1: certificates already sitting in customer caches must
        // keep verifying after the server rotates its signing key.
        [$newSecret, $newPublic] = CertificateFactory::keypair();

        $old = Certificate::parse(CertificateFactory::mint($this->secretKey, 'key_2026_01', 1_800_000_000));
        $new = Certificate::parse(CertificateFactory::mint($newSecret, 'key_2026_02', 1_800_000_100));

        $this->keyring->add('key_2026_02', $newPublic);

        $this->assertTrue(SignatureVerifier::isValid($old, $this->keyring), 'the retired key must still verify');
        $this->assertTrue(SignatureVerifier::isValid($new, $this->keyring), 'the new key must verify');
    }

    public function test_a_certificate_signed_by_the_shipped_placeholder_is_impossible(): void
    {
        // The bundled bootstrap key exists so the keyring is never empty. Its
        // private half exists nowhere, so no signature can ever verify against
        // it — the fail-closed default when nothing is pinned.
        $placeholderOnly = Keyring::bootstrap();

        $certificate = Certificate::parse(
            CertificateFactory::mint($this->secretKey, Keyring::PLACEHOLDER_KID, 1_800_000_000),
        );

        $this->assertFalse(SignatureVerifier::isValid($certificate, $placeholderOnly));
        $this->assertSame(32, strlen((string) $placeholderOnly->get(Keyring::PLACEHOLDER_KID)));
    }

    public function test_a_key_conflicting_with_an_existing_kid_is_refused(): void
    {
        [, $otherPublic] = CertificateFactory::keypair();

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/refusing to replace/i');

        $this->keyring->add('key_2026_01', $otherPublic);
    }
}
