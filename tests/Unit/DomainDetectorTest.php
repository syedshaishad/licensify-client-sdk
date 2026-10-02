<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Support\DomainDetector;
use Licensify\Client\Support\DomainEnvironment;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DomainDetectorTest extends TestCase
{
    private DomainDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new DomainDetector;
    }

    #[DataProvider('normalisationCases')]
    public function test_it_normalises_the_forms_of_one_domain_to_a_single_value(string $input, string $expected): void
    {
        $this->assertSame($expected, $this->detector->normalize($input));
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function normalisationCases(): array
    {
        return [
            'plain host' => ['example.com', 'example.com'],
            'trailing whitespace' => ['  example.com  ', 'example.com'],
            'uppercase' => ['EXAMPLE.COM', 'example.com'],
            'www prefix is stripped' => ['www.example.com', 'example.com'],
            'fqdn root dot is stripped' => ['example.com.', 'example.com'],
            'https scheme' => ['https://example.com', 'example.com'],
            'http scheme' => ['http://example.com', 'example.com'],
            'protocol relative' => ['//example.com', 'example.com'],
            'path is dropped' => ['https://example.com/admin/panel?x=1', 'example.com'],
            'fragment is dropped' => ['https://example.com/page#top', 'example.com'],
            'port is dropped' => ['https://example.com:8443', 'example.com'],
            'userinfo is dropped' => ['https://user:pass@example.com', 'example.com'],
            'scheme userinfo and port together' => ['https://u:p@example.com:8443/app', 'example.com'],
            'zero width space is removed' => ["exam\xE2\x80\x8Bple.com", 'example.com'],
            'control characters are removed' => ["exam\x07ple.com", 'example.com'],
            'byte order mark is removed' => ["\xEF\xBB\xBFexample.com", 'example.com'],
            'loopback ipv4' => ['127.0.0.1:8000', '127.0.0.1'],
            'ipv6 literal' => ['[::1]:8000', '::1'],
            'ipv4-mapped ipv6 unwraps' => ['[::ffff:1.2.3.4]', '1.2.3.4'],
            'www is only stripped when a domain remains' => ['www.com', 'www.com'],
        ];
    }

    #[DataProvider('classificationCases')]
    public function test_it_classifies_the_environment(string $input, DomainEnvironment $expected): void
    {
        $this->assertSame($expected, $this->detector->describe($input)->environment);
    }

    /**
     * @return array<string, array{0: string, 1: DomainEnvironment}>
     */
    public static function classificationCases(): array
    {
        return [
            'apex production host' => ['example.com', DomainEnvironment::Production],
            'subdomain' => ['app.example.com', DomainEnvironment::Subdomain],
            'localhost' => ['localhost', DomainEnvironment::Localhost],
            'localhost subdomain' => ['api.localhost', DomainEnvironment::Localhost],
            'loopback ip' => ['127.0.0.1', DomainEnvironment::Localhost],
            'routable ip' => ['8.8.8.8', DomainEnvironment::IpAddress],
            'dot local' => ['myapp.local', DomainEnvironment::Development],
            'dot test' => ['myapp.test', DomainEnvironment::Development],
            'dot dev' => ['myapp.dev', DomainEnvironment::Development],
            'staging prefix' => ['stg.example.com', DomainEnvironment::Development],
            'dev prefix' => ['dev.example.com', DomainEnvironment::Development],
        ];
    }

    public function test_strip_www_can_be_disabled(): void
    {
        $detector = new DomainDetector(stripWww: false);

        $this->assertSame('www.example.com', $detector->normalize('www.example.com'));
    }

    public function test_ipv6_is_reported_as_an_ip_address(): void
    {
        $described = $this->detector->describe('[2001:0db8:0000:0000:0000:0000:0000:0001]');

        $this->assertTrue($described->isIpAddress);
        $this->assertSame('2001:db8::1', $described->domain);
        $this->assertSame(DomainEnvironment::IpAddress, $described->environment);
    }

    #[DataProvider('undetectableDomains')]
    public function test_unusable_domains_are_refused(string $input): void
    {
        $this->expectException(ConfigurationException::class);

        $this->detector->normalize($input);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function undetectableDomains(): array
    {
        return [
            'empty' => [''],
            'whitespace only' => ['   '],
            'no label characters' => ['exa mple.com'],
            'empty label' => ['example..com'],
            'only a scheme' => ['https://'],
        ];
    }

    public function test_detection_prefers_http_host(): void
    {
        $domain = $this->detector->detect(null, [
            'HTTP_HOST' => 'www.example.com:8443',
            'SERVER_NAME' => 'other.example.com',
            'SERVER_ADDR' => '10.0.0.1',
        ]);

        $this->assertSame('example.com', $domain);
    }

    public function test_detection_falls_back_through_server_name_and_addr(): void
    {
        $this->assertSame('example.com', $this->detector->detect(null, ['SERVER_NAME' => 'example.com']));

        // SERVER_ADDR is an IP, so it normalises as one rather than as a domain.
        $this->assertSame('192.0.2.10', $this->detector->detect(null, ['SERVER_ADDR' => '192.0.2.10']));
    }

    public function test_an_explicit_override_wins_over_detection(): void
    {
        $domain = $this->detector->detect('https://override.example.org/app', ['HTTP_HOST' => 'example.com']);

        $this->assertSame('override.example.org', $domain);
    }

    public function test_detection_fails_loudly_when_there_is_no_host(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/LICENSE_DOMAIN/');

        $this->detector->detect(null, []);
    }

    public function test_development_hosts_are_refused_unless_locally_allowed(): void
    {
        $described = $this->detector->describe('myapp.test');

        $this->assertFalse($this->detector->isLocallyAcceptable($described, allowLocalhost: false));
        $this->assertTrue($this->detector->isLocallyAcceptable($described, allowLocalhost: true));
    }

    public function test_production_hosts_never_need_the_localhost_opt_in(): void
    {
        $described = $this->detector->describe('example.com');

        $this->assertTrue($this->detector->isLocallyAcceptable($described, allowLocalhost: false));
    }

    public function test_wildcard_matching_respects_the_depth_limit(): void
    {
        $this->assertTrue($this->detector->matchesPattern('a.example.com', '*.example.com'));
        $this->assertFalse($this->detector->matchesPattern('a.b.example.com', '*.example.com'));
        $this->assertTrue($this->detector->matchesPattern('a.b.example.com', '*.example.com', depth: 2));
    }

    public function test_wildcards_do_not_match_the_apex_by_default(): void
    {
        $this->assertFalse($this->detector->matchesPattern('example.com', '*.example.com'));
        $this->assertTrue($this->detector->matchesPattern('example.com', '*.example.com', includeApex: true));
    }

    public function test_exact_patterns_only_match_exactly(): void
    {
        $this->assertTrue($this->detector->matchesPattern('example.com', 'example.com'));
        $this->assertFalse($this->detector->matchesPattern('sub.example.com', 'example.com'));
    }

    public function test_registrable_domain_handles_two_part_public_suffixes(): void
    {
        $this->assertSame('example.com', $this->detector->registrableDomain('shop.example.com'));
        $this->assertSame('example.co.uk', $this->detector->registrableDomain('shop.example.co.uk'));
        $this->assertSame('localhost', $this->detector->registrableDomain('localhost'));
    }
}
