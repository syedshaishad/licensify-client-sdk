<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Security\CanonicalJson;
use PHPUnit\Framework\TestCase;

final class CanonicalJsonTest extends TestCase
{
    public function test_object_keys_are_sorted(): void
    {
        $this->assertSame('{"a":1,"b":2,"z":3}', CanonicalJson::encode(['z' => 3, 'a' => 1, 'b' => 2]));
    }

    public function test_nested_objects_are_sorted_too(): void
    {
        $encoded = CanonicalJson::encode([
            'zulu' => ['y' => 2, 'x' => 1],
            'alpha' => 1,
        ]);

        $this->assertSame('{"alpha":1,"zulu":{"x":1,"y":2}}', $encoded);
    }

    public function test_deeply_nested_keys_are_sorted_at_every_level(): void
    {
        $encoded = CanonicalJson::encode([
            'b' => ['d' => ['z' => 1, 'a' => 2], 'c' => 3],
            'a' => 1,
        ]);

        $this->assertSame('{"a":1,"b":{"c":3,"d":{"a":2,"z":1}}}', $encoded);
    }

    public function test_list_order_is_preserved(): void
    {
        // A list is ordered data, not a map; sorting it would change meaning.
        $this->assertSame('["c","a","b"]', CanonicalJson::encode(['c', 'a', 'b']));
    }

    public function test_lists_of_objects_keep_their_order_but_sort_their_keys(): void
    {
        $encoded = CanonicalJson::encode([
            ['b' => 1, 'a' => 2],
            ['d' => 3, 'c' => 4],
        ]);

        $this->assertSame('[{"a":2,"b":1},{"c":4,"d":3}]', $encoded);
    }

    public function test_slashes_and_unicode_are_not_escaped(): void
    {
        $encoded = CanonicalJson::encode(['url' => 'https://example.com/a', 'name' => 'Ünïcøde ✓']);

        $this->assertSame('{"name":"Ünïcøde ✓","url":"https://example.com/a"}', $encoded);
    }

    public function test_encoding_is_deterministic_regardless_of_insertion_order(): void
    {
        $first = CanonicalJson::encode(['rev' => 7, 'pcode' => 'MYCRM', 'dom' => 'example.com']);
        $second = CanonicalJson::encode(['dom' => 'example.com', 'pcode' => 'MYCRM', 'rev' => 7]);

        $this->assertSame($first, $second);
    }

    public function test_scalar_values_are_returned_unchanged(): void
    {
        $this->assertSame('7', CanonicalJson::encode(7));
        $this->assertSame('true', CanonicalJson::encode(true));
        $this->assertSame('null', CanonicalJson::encode(null));
        $this->assertSame('"text"', CanonicalJson::encode('text'));
    }

    public function test_numeric_string_keys_sort_lexicographically(): void
    {
        // PHP casts numeric-looking string keys to integers; SORT_STRING keeps
        // the ordering stable regardless.
        $this->assertSame('{"10":1,"2":2}', CanonicalJson::encode([2 => 2, 10 => 1]));
    }

    public function test_an_unencodable_value_throws_rather_than_returning_false(): void
    {
        $this->expectException(\JsonException::class);

        CanonicalJson::encode(['bad' => NAN]);
    }
}
