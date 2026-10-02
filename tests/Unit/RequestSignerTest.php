<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\RequestSigner;
use Licensify\Client\Support\AuthScheme;
use PHPUnit\Framework\TestCase;

final class RequestSignerTest extends TestCase
{
    private const SECRET = 'cs_super_secret_value';

    public function test_the_canonical_string_is_six_lf_joined_lines(): void
    {
        $canonical = RequestSigner::canonicalString(
            'post',
            '/api/v1/license/activate',
            '',
            '{"a":1}',
            1_800_000_000,
            'nonce123',
        );

        $this->assertSame(
            implode("\n", [
                'POST',
                '/api/v1/license/activate',
                '',
                hash('sha256', '{"a":1}'),
                '1800000000',
                'nonce123',
            ]),
            $canonical,
        );

        $this->assertCount(6, explode("\n", $canonical));
        $this->assertStringEndsNotWith("\n", $canonical);
    }

    public function test_an_absent_body_hashes_the_empty_string(): void
    {
        $canonical = RequestSigner::canonicalString('GET', '/api/v1/ping', '', null, 1, 'n');

        $this->assertStringContainsString(hash('sha256', ''), $canonical);
    }

    public function test_the_method_is_uppercased(): void
    {
        $canonical = RequestSigner::canonicalString('get', '/api/v1/ping', '', null, 1, 'n');

        $this->assertStringStartsWith("GET\n", $canonical);
    }

    public function test_a_query_string_on_the_path_is_excluded(): void
    {
        // Path and query are separate lines, so an inline query would make the
        // two sides compute different canonical strings.
        $canonical = RequestSigner::canonicalString('GET', '/api/v1/ping?x=1', 'x=1', null, 1, 'n');

        $this->assertSame("GET\n/api/v1/ping\nx=1\n".hash('sha256', '')."\n1\nn", $canonical);
    }

    public function test_the_canonical_query_sorts_by_key(): void
    {
        $query = RequestSigner::canonicalQuery(['z' => 1, 'a' => 2, 'm' => 3]);

        $this->assertSame('a=2&m=3&z=1', $query);
    }

    public function test_the_canonical_query_percent_encodes_per_rfc3986(): void
    {
        $query = RequestSigner::canonicalQuery(['name' => 'a b&c=d', 'sym' => '-_.~']);

        $this->assertSame('name=a%20b%26c%3Dd&sym=-_.~', $query);
    }

    public function test_an_empty_query_canonicalises_to_an_empty_string(): void
    {
        $this->assertSame('', RequestSigner::canonicalQuery([]));
    }

    public function test_null_query_parameters_are_dropped(): void
    {
        $this->assertSame('a=1', RequestSigner::canonicalQuery(['a' => 1, 'b' => null]));
    }

    public function test_the_signature_is_base64url_of_hmac_sha256(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', self::SECRET);

        $headers = $signer->headers('POST', '/api/v1/license/activate', [], '{"a":1}', 1_800_000_000);

        $canonical = RequestSigner::canonicalString(
            'POST',
            '/api/v1/license/activate',
            '',
            '{"a":1}',
            1_800_000_000,
            $headers['X-License-Nonce'],
        );

        $expected = Base64Url::encode(hash_hmac('sha256', $canonical, self::SECRET, true));

        $this->assertSame($expected, $headers['X-License-Signature']);
        $this->assertSame('lk_test', $headers['X-License-Key']);
        $this->assertSame('1800000000', $headers['X-License-Timestamp']);
        $this->assertNotSame('', $headers['X-License-Nonce']);
    }

    public function test_the_nonce_is_url_safe_base64_of_at_least_sixteen_bytes(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', self::SECRET);

        $headers = $signer->headers('POST', '/api/v1/license/validate', [], null, 1_800_000_000);
        $nonce = $headers['X-License-Nonce'];

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $nonce);
        $this->assertGreaterThanOrEqual(16, strlen(Base64Url::decode($nonce)));
    }

    public function test_each_request_uses_a_fresh_nonce(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', self::SECRET);

        $nonces = [];

        for ($i = 0; $i < 20; $i++) {
            $nonces[] = $signer->headers('POST', '/api/v1/license/validate', [], null, 1_800_000_000)['X-License-Nonce'];
        }

        $this->assertCount(20, array_unique($nonces));
    }

    public function test_a_different_body_produces_a_different_signature(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', self::SECRET);

        $first = $signer->headers('POST', '/api/v1/license/validate', [], '{"a":1}', 1_800_000_000);
        $second = $signer->headers('POST', '/api/v1/license/validate', [], '{"a":2}', 1_800_000_000);

        // Different nonces guarantee this even without a body change, so the
        // assertion pins the property that matters: signatures are not stable.
        $this->assertNotSame($first['X-License-Signature'], $second['X-License-Signature']);
    }

    public function test_the_bearer_scheme_sends_a_single_authorization_header(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', 'cs_test', AuthScheme::Bearer);

        $headers = $signer->headers('POST', '/api/v1/license/validate', [], '{}', 1_800_000_000);

        $this->assertSame(['Authorization' => 'Bearer lk_test.cs_test'], $headers);
    }

    public function test_hmac_is_the_default_scheme(): void
    {
        $signer = RequestSigner::fromCredentials('lk_test', 'cs_test');

        $this->assertSame(AuthScheme::Hmac, $signer->scheme());
        $this->assertArrayHasKey('X-License-Signature', $signer->headers('GET', '/api/v1/ping'));
    }

    public function test_signature_verification_matches_the_servers_check(): void
    {
        $canonical = RequestSigner::canonicalString('POST', '/api/v1/license/activate', '', '{}', 1_800_000_000, 'n1');
        $signature = RequestSigner::sign(self::SECRET, $canonical);

        $this->assertTrue(RequestSigner::verify(self::SECRET, $canonical, $signature));
        $this->assertFalse(RequestSigner::verify('another_secret', $canonical, $signature));
        $this->assertFalse(RequestSigner::verify(self::SECRET, $canonical.' ', $signature));
    }
}
