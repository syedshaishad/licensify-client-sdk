<?php

declare(strict_types=1);

namespace Licensify\Client\Security;

use JsonException;

/**
 * Deterministic JSON encoding: object keys are sorted recursively so the same
 * logical payload always produces byte-identical output.
 *
 * Byte-identity is what lets a signature survive being re-encoded on either
 * side of the wire, which is the whole basis of the certificate format
 * (contract §5).
 */
final class CanonicalJson
{
    public const FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    /**
     * @throws JsonException
     */
    public static function encode(mixed $value): string
    {
        return json_encode(self::sortRecursive($value), self::FLAGS);
    }

    /**
     * Recursively sorts associative arrays by key while leaving list order
     * untouched — a list is ordered data, not a map.
     */
    public static function sortRecursive(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        $isList = array_is_list($value);
        $sorted = [];

        foreach ($value as $key => $item) {
            $sorted[$key] = self::sortRecursive($item);
        }

        if (! $isList) {
            ksort($sorted, SORT_STRING);
        }

        return $sorted;
    }
}
