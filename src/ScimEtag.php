<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim;

use Yiisoft\Http\Header;
use Psr\Http\Message\ServerRequestInterface;

/** Creates stable opaque versions for SCIM resources and evaluates If-Match. */
final class ScimEtag
{
    /** @return array */
    public static function withVersion(array $resource): array
    {
        $version = self::version($resource);
        /** @var mixed $rawMeta */
        $rawMeta = $resource['meta'] ?? [];
        if (is_array($rawMeta)) {
            /** @var array<string, mixed> $meta */
            $meta = $rawMeta;
        } else {
            $meta = [];
        }
        $meta['version'] = $version;
        $resource['meta'] = $meta;
        return $resource;
    }

    /** @param array $resource */
    public static function header(array $resource): string
    {
        /** @var mixed $rawMeta */
        $rawMeta = $resource['meta'] ?? [];
        /** @var array<string, mixed> $meta */
        $meta = is_array($rawMeta) ? $rawMeta : [];
        /** @psalm-suppress MixedArgument */
        $version = isset($meta['version']) ? strval($meta['version']) : self::version($resource);
        return sprintf('"%s"', $version);
    }

    /** @param array $resource */
    public static function matches(ServerRequestInterface $request, array $resource): bool
    {
        $ifMatch = trim($request->getHeaderLine(Header::IF_MATCH));
        if ($ifMatch === '' || $ifMatch === '*') {
            return true;
        }
        $current = self::header($resource);
        foreach (explode(',', $ifMatch) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate === $current || preg_replace('/^W\//', '', $candidate) === $current) {
                return true;
            }
        }
        return false;
    }

    /** @param array $resource */
    public static function matchesNone(ServerRequestInterface $request, array $resource): bool
    {
        $ifNoneMatch = trim($request->getHeaderLine('If-None-Match'));
        if ($ifNoneMatch !== '') {
            if ($ifNoneMatch === '*') {
                return true;
            }
            $current = self::header($resource);
            foreach (explode(',', $ifNoneMatch) as $candidate) {
                $candidate = trim($candidate);
                if ($candidate === $current || preg_replace('/^W\//', '', $candidate) === $current) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @param array $resource */
    private static function version(array $resource): string
    {
        if (isset($resource['meta']) && is_array($resource['meta'])) {
            unset($resource['meta']['version']);
        }
        return hash('sha256', serialize($resource));
    }
}
