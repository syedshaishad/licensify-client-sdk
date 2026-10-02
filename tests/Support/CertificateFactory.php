<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Support;

use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\CanonicalJson;

/**
 * Mints certificates the way the server does, for tests only.
 *
 * The SDK itself can never do this — there is no signing code in `src/`, which
 * is the whole point of contract §5.2. This helper exists purely so tests can
 * produce a token a real installation would accept.
 */
final class CertificateFactory
{
    /**
     * @param  array<string, mixed>  $overrides
     */
    public static function mint(
        string $secretKey,
        string $kid,
        int $issuedAt,
        int $graceSeconds = 259200,
        array $overrides = [],
        ?string $algorithm = 'ed25519',
        ?string $type = 'LIC',
    ): string {
        $header = [
            'alg' => $algorithm,
            'kid' => $kid,
            'typ' => $type,
            'v' => 1,
        ];

        $payload = array_merge([
            'iss' => 'https://licensing.test',
            'sub' => 'inst_0000000000000000000000000000abcd',
            'jti' => 'test-certificate',
            'iat' => $issuedAt,
            'nbf' => $issuedAt,
            'exp' => $issuedAt + $graceSeconds,
            'lid' => 'lic_00000000',
            'lkey_fp' => 'sha256:0123456789abcdef',
            'pid' => 'prd_00000000',
            'pcode' => 'MYCRM',
            'dom' => 'example.com',
            'inst' => 'inst_0000000000000000000000000000abcd',
            'status' => 'active',
            'ver' => '2.4.1',
            'plan' => 'subscription',
            'grace' => $graceSeconds,
            'rev' => 1,
        ], $overrides);

        $signingInput = Base64Url::encode(CanonicalJson::encode($header))
            .'.'.Base64Url::encode(CanonicalJson::encode($payload));

        $signature = sodium_crypto_sign_detached($signingInput, $secretKey);

        return $signingInput.'.'.Base64Url::encode($signature);
    }

    /**
     * A fresh Ed25519 keypair, as `[secretKey, base64PublicKey]`.
     *
     * @return array{0: string, 1: string}
     */
    public static function keypair(): array
    {
        $keypair = sodium_crypto_sign_keypair();

        return [
            sodium_crypto_sign_secretkey($keypair),
            base64_encode(sodium_crypto_sign_publickey($keypair)),
        ];
    }
}
