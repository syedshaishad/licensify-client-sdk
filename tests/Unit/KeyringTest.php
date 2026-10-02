<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Exception\ConfigurationException;
use Licensify\Client\Security\Base64Url;
use Licensify\Client\Security\Keyring;
use Licensify\Client\Tests\Support\CertificateFactory;
use PHPUnit\Framework\TestCase;

final class KeyringTest extends TestCase
{
    public function test_bootstrap_ships_one_usable_looking_placeholder_key(): void
    {
        $keyring = Keyring::bootstrap();

        $this->assertTrue($keyring->has(Keyring::PLACEHOLDER_KID));
        $this->assertSame(32, strlen((string) $keyring->get(Keyring::PLACEHOLDER_KID)));
    }

    public function test_it_accepts_standard_and_url_safe_base64_keys(): void
    {
        [$secret, $standard] = CertificateFactory::keypair();
        $urlSafe = Base64Url::encode(base64_decode($standard, true));

        $keyring = new Keyring;
        $keyring->add('key_a', $standard);
        $keyring->add('key_b', $urlSafe);

        $this->assertSame(base64_decode($standard, true), $keyring->get('key_a'));
        $this->assertSame(base64_decode($standard, true), $keyring->get('key_b'));
        $this->assertNotNull($secret);
    }

    public function test_it_refuses_keys_of_the_wrong_length(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/32 raw bytes/');

        (new Keyring)->add('key_short', base64_encode(str_repeat('a', 16)));
    }

    public function test_it_refuses_undecodable_material(): void
    {
        $this->expectException(ConfigurationException::class);

        (new Keyring)->add('key_bad', '!!!!not base64!!!!');
    }

    public function test_it_refuses_an_empty_kid(): void
    {
        $this->expectException(ConfigurationException::class);

        (new Keyring)->add('   ', base64_encode(str_repeat('a', 32)));
    }

    public function test_re_adding_identical_material_is_idempotent(): void
    {
        [, $public] = CertificateFactory::keypair();
        $keyring = new Keyring;

        $keyring->add('key_a', $public);
        $keyring->add('key_a', $public);

        $this->assertCount(1, $keyring->all());
    }

    public function test_a_keyring_survives_a_base64_round_trip(): void
    {
        [, $first] = CertificateFactory::keypair();
        [, $second] = CertificateFactory::keypair();

        $keyring = (new Keyring)->add('key_a', $first)->add('key_b', $second);

        $restored = Keyring::fromBase64Array($keyring->toBase64Array());

        $this->assertSame($keyring->all(), $restored->all());
    }

    public function test_it_merges_a_server_published_keyring(): void
    {
        [$active, $activePublic] = CertificateFactory::keypair();
        [, $retiredPublic] = CertificateFactory::keypair();

        $keyring = Keyring::bootstrap();
        $keyring->mergeFromServer([
            'algorithm' => 'ed25519',
            'active_kid' => 'key_2026_02',
            'keys' => [
                ['kid' => 'key_2026_02', 'public_key' => $activePublic, 'is_active' => true],
                ['kid' => 'key_2026_01', 'public_key' => $retiredPublic, 'is_active' => false],
            ],
        ]);

        $this->assertTrue($keyring->has('key_2026_02'));
        $this->assertTrue($keyring->has('key_2026_01'));
        $this->assertSame($activePublic, base64_encode((string) $keyring->get('key_2026_02')));
    }

    public function test_it_merges_a_flat_kid_to_key_map(): void
    {
        [, $public] = CertificateFactory::keypair();

        $keyring = (new Keyring)->mergeFromServer(['keys' => ['key_flat' => $public]]);

        $this->assertSame(base64_decode($public, true), $keyring->get('key_flat'));
    }

    public function test_it_ignores_a_payload_with_no_key_member(): void
    {
        // A response without a `keys` member must add nothing; scanning the whole
        // payload would try to read unrelated fields as key material.
        [, $public] = CertificateFactory::keypair();

        $keyring = (new Keyring)->mergeFromServer([
            'algorithm' => 'ed25519',
            'active_kid' => $public,
            'product' => 'MYCRM',
        ]);

        $this->assertSame([], $keyring->all());
    }

    public function test_merging_an_empty_payload_changes_nothing(): void
    {
        $keyring = Keyring::bootstrap();
        $before = $keyring->all();

        $keyring->mergeFromServer([]);
        $keyring->mergeFromServer(['keys' => []]);

        $this->assertSame($before, $keyring->all());
    }

    public function test_merge_ignores_entries_without_usable_material(): void
    {
        [, $public] = CertificateFactory::keypair();

        $keyring = (new Keyring)->mergeFromServer([
            'keys' => [
                ['kid' => 'key_ok', 'public_key' => $public],
                ['kid' => 'key_no_material'],
                ['public_key' => $public],
                'garbage' => ['not-a-key'],
            ],
        ]);

        $this->assertSame(['key_ok'], array_keys($keyring->all()));
    }

    public function test_a_key_can_be_retired_and_removed(): void
    {
        [, $public] = CertificateFactory::keypair();

        $keyring = (new Keyring)->add('key_a', $public);
        $this->assertTrue($keyring->has('key_a'));

        $keyring->forget('key_a');

        $this->assertFalse($keyring->has('key_a'));
        $this->assertNull($keyring->get('key_a'));
        $this->assertSame([], $keyring->all());
    }

    public function test_replace_supersedes_the_whole_keyring(): void
    {
        [, $oldPublic] = CertificateFactory::keypair();
        [, $newPublic] = CertificateFactory::keypair();

        $keyring = (new Keyring)->add('key_old', $oldPublic);
        $keyring->replace(['key_new' => $newPublic]);

        $this->assertSame(['key_new'], array_keys($keyring->all()));
    }

    public function test_the_keyring_keeps_several_keys_for_rotation(): void
    {
        $keys = [];

        for ($i = 1; $i <= 4; $i++) {
            [, $public] = CertificateFactory::keypair();
            $keys['key_2026_0'.$i] = $public;
        }

        $keyring = new Keyring($keys);

        $this->assertCount(4, $keyring->all());

        foreach ($keys as $kid => $public) {
            $this->assertSame(base64_decode($public, true), $keyring->get($kid));
        }
    }
}
