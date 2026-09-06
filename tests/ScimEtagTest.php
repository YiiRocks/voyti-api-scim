<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use YiiRocks\Voyti\Api\Scim\ScimEtag;
use Psr\Http\Message\ServerRequestInterface;

final class ScimEtagTest extends TestCase
{
    public function testVersionIsStableAndIfMatchAcceptsIt(): void
    {
        $resource = ScimEtag::withVersion([
            'id' => '42',
            'meta' => ['resourceType' => 'User'],
        ]);
        $request = (new Psr17Factory())->createServerRequest('PATCH', '/v2/Users/42')
            ->withHeader('If-Match', ScimEtag::header($resource));

        self::assertSame(64, strlen((string) $resource['meta']['version']));
        self::assertTrue(ScimEtag::matches($request, $resource));
        self::assertArrayHasKey('version', ScimEtag::withVersion(['id' => '43', 'meta' => 'invalid'])['meta']);
    }

    public function testStaleIfMatchIsRejected(): void
    {
        $resource = ScimEtag::withVersion(['id' => '42']);
        $request = (new Psr17Factory())->createServerRequest('PATCH', '/v2/Users/42')
            ->withHeader('If-Match', '"stale"');

        self::assertFalse(ScimEtag::matches($request, $resource));
        self::assertSame('"abc"', ScimEtag::header(['meta' => ['version' => 'abc']]));
        self::assertSame('"' . ScimEtag::withVersion(['id' => 'missing-meta'])['meta']['version'] . '"', ScimEtag::header(['id' => 'missing-meta']));
    }

    public function testIfNoneMatchAcceptsCurrentVersion(): void
    {
        $resource = ScimEtag::withVersion(['id' => '42']);
        $request = (new Psr17Factory())->createServerRequest('GET', '/v2/Users/42')
            ->withHeader('If-None-Match', ScimEtag::header($resource));

        self::assertTrue(ScimEtag::matchesNone($request, $resource));
    }

    public function testEmptyAndWildcardValidators(): void
    {
        $resource = ScimEtag::withVersion(['id' => '42']);
        $factory = new Psr17Factory();

        self::assertTrue(ScimEtag::matches($factory->createServerRequest('GET', '/'), $resource));
        self::assertTrue(ScimEtag::matches($factory->createServerRequest('GET', '/')->withHeader('If-Match', '*'), $resource));
        self::assertTrue(ScimEtag::matchesNone($factory->createServerRequest('GET', '/')->withHeader('If-None-Match', '*'), $resource));
        self::assertFalse(ScimEtag::matchesNone($factory->createServerRequest('GET', '/'), $resource));
        self::assertFalse(ScimEtag::matchesNone($factory->createServerRequest('GET', '/')->withHeader('If-None-Match', '"stale"'), $resource));
        $spaced = $this->createStub(ServerRequestInterface::class);
        $spaced->method('getHeaderLine')->willReturn('  *  ');
        self::assertTrue(ScimEtag::matches($spaced, $resource));
        self::assertTrue(ScimEtag::matchesNone($spaced, $resource));
        self::assertFalse(ScimEtag::matchesNone($factory->createServerRequest('GET', '/')->withHeader('If-None-Match', '   '), $resource));
    }

    public function testWeakAndMultipleValidatorsAreAccepted(): void
    {
        $resource = ScimEtag::withVersion(['id' => '42']);
        $etag = ScimEtag::header($resource);
        $factory = new Psr17Factory();

        self::assertTrue(ScimEtag::matches($factory->createServerRequest('GET', '/')->withHeader('If-Match', '"other", W/' . $etag), $resource));
        self::assertTrue(ScimEtag::matchesNone($factory->createServerRequest('GET', '/')->withHeader('If-None-Match', '"other", W/' . $etag), $resource));
    }
}
