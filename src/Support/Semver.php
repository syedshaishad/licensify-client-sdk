<?php

declare(strict_types=1);

namespace Licensify\Client\Support;

/**
 * Semantic-version comparison.
 *
 * Numeric comparison (`version_compare`) gets `2.10.0` vs `2.9.0` wrong, and
 * naive string comparison gets pre-releases wrong in the other direction, so
 * releases are compared field by field with pre-release ordering rules from
 * semver.org.
 */
final class Semver
{
    /**
     * @return int -1 when $a < $b, 0 when equal, 1 when $a > $b.
     */
    public static function compare(string $a, string $b): int
    {
        $left = self::parse($a);
        $right = self::parse($b);

        foreach ([0, 1, 2] as $index) {
            if ($left['core'][$index] !== $right['core'][$index]) {
                return $left['core'][$index] <=> $right['core'][$index];
            }
        }

        return self::comparePreRelease($left['pre'], $right['pre']);
    }

    public static function isNewer(string $candidate, string $current): bool
    {
        return self::compare($candidate, $current) > 0;
    }

    public static function satisfies(string $version, string $constraint): bool
    {
        foreach (explode(',', $constraint) as $part) {
            if (! self::satisfiesSingle($version, trim($part))) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array{core: array{0: int, 1: int, 2: int}, pre: array<int, string>}
     */
    private static function parse(string $version): array
    {
        $version = ltrim(trim($version), 'v=');
        $withoutBuild = explode('+', $version, 2)[0];

        $core = $withoutBuild;
        $pre = [];

        if (str_contains($withoutBuild, '-')) {
            [$core, $preRelease] = explode('-', $withoutBuild, 2);
            $pre = $preRelease === '' ? [] : explode('.', $preRelease);
        }

        $segments = explode('.', $core);

        return [
            'core' => [
                (int) ($segments[0] ?? 0),
                (int) ($segments[1] ?? 0),
                (int) ($segments[2] ?? 0),
            ],
            'pre' => $pre,
        ];
    }

    /**
     * A version with a pre-release sorts *below* the same release without one;
     * numeric pre-release identifiers sort below alphanumeric ones.
     *
     * @param  array<int, string>  $left
     * @param  array<int, string>  $right
     */
    private static function comparePreRelease(array $left, array $right): int
    {
        if ($left === [] && $right === []) {
            return 0;
        }

        if ($left === []) {
            return 1;
        }

        if ($right === []) {
            return -1;
        }

        $length = max(count($left), count($right));

        for ($index = 0; $index < $length; $index++) {
            $a = $left[$index] ?? null;
            $b = $right[$index] ?? null;

            if ($a === null) {
                return -1;
            }

            if ($b === null) {
                return 1;
            }

            $aNumeric = ctype_digit($a);
            $bNumeric = ctype_digit($b);

            if ($aNumeric && $bNumeric) {
                $result = (int) $a <=> (int) $b;
            } elseif ($aNumeric !== $bNumeric) {
                $result = $aNumeric ? -1 : 1;
            } else {
                $result = strcmp($a, $b);
            }

            if ($result !== 0) {
                return $result <=> 0;
            }
        }

        return 0;
    }

    private static function satisfiesSingle(string $version, string $constraint): bool
    {
        if ($constraint === '' || $constraint === '*') {
            return true;
        }

        $operator = '=';

        foreach (['>=', '<=', '!=', '>', '<', '=', '^', '~'] as $candidate) {
            if (str_starts_with($constraint, $candidate)) {
                $operator = $candidate;
                $constraint = substr($constraint, strlen($candidate));

                break;
            }
        }

        $comparison = self::compare($version, $constraint);

        return match ($operator) {
            '>=', '=' => $comparison >= 0,
            '>' => $comparison > 0,
            '<=' => $comparison <= 0,
            '<' => $comparison < 0,
            '!=' => $comparison !== 0,
            '^' => $comparison >= 0 && self::sameMajor($version, $constraint),
            '~' => $comparison >= 0 && self::withinTilde($version, $constraint),
            default => false,
        };
    }

    private static function sameMajor(string $a, string $b): bool
    {
        return self::parse($a)['core'][0] === self::parse($b)['core'][0];
    }

    /**
     * `~2.9.0` allows patch drift but not a minor bump, while `~2.9` allows
     * anything inside 2.x. The precision of the constraint sets the boundary:
     * everything below its last stated segment must match exactly.
     */
    private static function withinTilde(string $version, string $constraint): bool
    {
        $precision = self::precision($constraint);

        $left = self::parse($version)['core'];
        $right = self::parse($constraint)['core'];

        for ($index = 0; $index < max(0, $precision - 1) && $index < 2; $index++) {
            if ($left[$index] !== $right[$index]) {
                return false;
            }
        }

        return true;
    }

    /**
     * How many numeric segments the constraint states.
     */
    private static function precision(string $version): int
    {
        $core = explode('-', explode('+', ltrim(trim($version), 'v='))[0], 2)[0];

        return count(array_filter(explode('.', $core), static fn (string $segment): bool => $segment !== ''));
    }
}
