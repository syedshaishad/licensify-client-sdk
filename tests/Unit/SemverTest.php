<?php

declare(strict_types=1);

namespace Licensify\Client\Tests\Unit;

use Licensify\Client\Support\Semver;
use Licensify\Client\Support\VersionDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SemverTest extends TestCase
{
    #[DataProvider('comparisonCases')]
    public function test_it_compares_versions_correctly(string $left, string $right, int $expected): void
    {
        $this->assertSame($expected, Semver::compare($left, $right));
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: int}>
     */
    public static function comparisonCases(): array
    {
        return [
            'double digit minor beats single digit' => ['2.10.0', '2.9.0', 1],
            'equal versions' => ['2.9.0', '2.9.0', 0],
            'patch increments' => ['2.9.1', '2.9.0', 1],
            'major increments' => ['3.0.0', '2.99.99', 1],
            'missing patch is zero' => ['2.9', '2.9.0', 0],
            'missing minor is zero' => ['2', '2.0.0', 0],
            'leading v is ignored' => ['v2.10.0', '2.10.0', 0],
            'build metadata is ignored' => ['2.9.0+build7', '2.9.0', 0],
            'a release outranks its pre-release' => ['2.5.0', '2.5.0-beta.1', 1],
            'pre-release beta one outranks beta two' => ['2.5.0-beta.1', '2.5.0-beta.2', -1],
            'numeric pre-release identifiers sort numerically' => ['2.5.0-beta.2', '2.5.0-beta.10', -1],
            // Semver rule: numeric identifiers always have lower precedence than
            // alphanumeric ones, so `1` sorts below `alpha`.
            'numeric pre-release identifiers rank lowest' => ['2.5.0-1', '2.5.0-alpha', -1],
            'a longer pre-release outranks a shorter prefix' => ['2.5.0-alpha.1', '2.5.0-alpha', 1],
            'alpha outranks beta' => ['2.5.0-alpha', '2.5.0-beta', -1],
            'whitespace is tolerated' => [' 2.9.0 ', '2.9.0', 0],
        ];
    }

    public function test_is_newer_is_strict(): void
    {
        $this->assertTrue(Semver::isNewer('2.10.0', '2.9.0'));
        $this->assertFalse(Semver::isNewer('2.9.0', '2.9.0'));
        $this->assertFalse(Semver::isNewer('2.9.0', '2.10.0'));
    }

    public function test_string_comparison_would_have_been_wrong(): void
    {
        // Lexicographic comparison gets `2.10.0` vs `2.9.0` backwards, which is
        // why `Semver` exists rather than a `strcmp` in the update checker.
        $this->assertTrue(Semver::isNewer('2.10.0', '2.9.0'));
        $this->assertTrue('2.10.0' < '2.9.0', 'the string comparison this replaces really is wrong');
    }

    #[DataProvider('constraintCases')]
    public function test_it_evaluates_constraints(string $version, string $constraint, bool $expected): void
    {
        $this->assertSame($expected, Semver::satisfies($version, $constraint));
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: bool}>
     */
    public static function constraintCases(): array
    {
        return [
            'at least' => ['2.10.0', '>=2.9.0', true],
            'below' => ['2.9.0', '>=2.10.0', false],
            'greater than' => ['2.10.0', '>2.9.0', true],
            'less than or equal' => ['2.9.0', '<=2.9.0', true],
            'not equal' => ['2.9.0', '!=2.9.0', false],
            'caret stays inside the major' => ['2.10.0', '^2.9.0', true],
            'caret blocks the next major' => ['3.0.0', '^2.9.0', false],
            'tilde allows patch drift' => ['2.9.5', '~2.9.0', true],
            'tilde blocks a minor bump' => ['2.10.0', '~2.9.0', false],
            'wildcard matches anything' => ['1.2.3', '*', true],
            'comma separated constraints are conjunctive' => ['2.10.0', '>=2.9.0,<3.0.0', true],
            'comma separated can fail on one term' => ['3.1.0', '>=2.9.0,<3.0.0', false],
        ];
    }

    public function test_the_detector_compares_through_semver(): void
    {
        $detector = new VersionDetector('/nonexistent');

        $this->assertTrue($detector->isNewer('2.10.0', '2.9.0'));
        $this->assertFalse($detector->isNewer('2.9.0', '2.9.0'));
    }

    public function test_the_detector_refuses_to_guess_when_a_version_is_unknown(): void
    {
        $detector = new VersionDetector('/nonexistent');

        // An empty version on either side means "unknown", which must never be
        // read as "newer".
        $this->assertFalse($detector->isNewer('', '2.9.0'));
        $this->assertFalse($detector->isNewer('2.9.0', ''));
        $this->assertSame('', $detector->detect(null, []));
    }

    public function test_an_explicit_version_overrides_detection(): void
    {
        $detector = new VersionDetector('/nonexistent');

        $this->assertSame('3.1.4', $detector->detect('3.1.4', ['APP_VERSION' => '9.9.9']));
    }

    public function test_it_reads_a_version_constant_from_the_environment(): void
    {
        $detector = new VersionDetector('/nonexistent');

        $this->assertSame('4.2.0', $detector->detect(null, ['APP_VERSION' => '4.2.0']));
    }

    public function test_it_reads_the_version_from_composer_json(): void
    {
        $path = sys_get_temp_dir().'/licensify-version-'.bin2hex(random_bytes(5));
        mkdir($path);

        file_put_contents($path.'/composer.json', json_encode([
            'name' => 'acme/app',
            'extra' => ['licensify' => ['version' => '5.6.7']],
        ], JSON_THROW_ON_ERROR));

        try {
            $this->assertSame('5.6.7', (new VersionDetector($path))->detect(null, []));
        } finally {
            @unlink($path.'/composer.json');
            @rmdir($path);
        }
    }

    public function test_a_composer_json_without_a_version_yields_an_empty_string(): void
    {
        $path = sys_get_temp_dir().'/licensify-version-'.bin2hex(random_bytes(5));
        mkdir($path);

        file_put_contents($path.'/composer.json', json_encode([
            'name' => 'acme/app',
            'extra' => ['laravel' => ['dont-discover' => []]],
        ], JSON_THROW_ON_ERROR));

        try {
            $this->assertSame('', (new VersionDetector($path))->detect(null, []));
        } finally {
            @unlink($path.'/composer.json');
            @rmdir($path);
        }
    }
}
