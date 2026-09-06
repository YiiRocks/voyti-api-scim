<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests;

use PHPUnit\Framework\TestCase;
use YiiRocks\Voyti\Api\Scim\OpenApi\ScimOpenApiSpecContributor;

final class OpenApiSpecContributorTest extends TestCase
{
    public function testAllScimRoutesHaveMethodSpecs(): void
    {
        $contributor = new ScimOpenApiSpecContributor();
        $routes = [
            ['voyti/api-scim-v2-service-provider-config', 'get'],
            ['voyti/api-scim-v2-resource-types', 'get'],
            ['voyti/api-scim-v2-schemas', 'get'],
            ['voyti/api-scim-v2-schema', 'get'],
            ['voyti/api-scim-v2-bulk', 'post'],
            ['voyti/api-scim-v2-users-index', 'get'],
            ['voyti/api-scim-v2-users-create', 'post'],
            ['voyti/api-scim-v2-users-search', 'post'],
            ['voyti/api-scim-v2-users-view', 'get'],
            ['voyti/api-scim-v2-users-replace', 'put'],
            ['voyti/api-scim-v2-users-patch', 'patch'],
            ['voyti/api-scim-v2-users-delete', 'delete'],
            ['voyti/api-scim-v2-groups-index', 'get'],
            ['voyti/api-scim-v2-groups-create', 'post'],
            ['voyti/api-scim-v2-groups-search', 'post'],
            ['voyti/api-scim-v2-groups-view', 'get'],
            ['voyti/api-scim-v2-groups-replace', 'put'],
            ['voyti/api-scim-v2-groups-patch', 'patch'],
            ['voyti/api-scim-v2-groups-delete', 'delete'],
        ];
        foreach ($routes as [$route, $method]) {
            $spec = $contributor->getMethodSpec($route, $method);
            self::assertIsArray($spec);
            self::assertNotSame('', $spec['operationId']);
            self::assertCount(1, $spec['tags']);
            self::assertSame(['200' => ['description' => 'SCIM response'], '201' => ['description' => 'SCIM resource created'], '204' => ['description' => 'Resource deleted'], '400' => ['description' => 'SCIM validation error'], '409' => ['description' => 'Resource conflict'], '401' => ['description' => 'Authentication required'], '404' => ['description' => 'Resource not found'], '412' => ['description' => 'SCIM version conflict'], '413' => ['description' => 'Bulk payload too large']], $spec['responses']);
        }

        self::assertNull($contributor->getMethodSpec('unknown', 'get'));
        self::assertNull($contributor->getMethodSpec($routes[0][0], 'post'));
    }

    public function testSchemasAreExposed(): void
    {
        $schemas = (new ScimOpenApiSpecContributor())->schemas();

        self::assertSame(['type' => 'object', 'required' => ['schemas', 'id', 'userName', 'emails'], 'properties' => ['schemas' => ['type' => 'array', 'items' => ['type' => 'string']], 'id' => ['type' => 'string'], 'userName' => ['type' => 'string'], 'active' => ['type' => 'boolean'], 'password' => ['type' => 'string', 'writeOnly' => true], 'emails' => ['type' => 'array', 'items' => ['type' => 'object']], 'meta' => ['type' => 'object']]], $schemas['ScimUser']);
        self::assertSame(['type' => 'object', 'required' => ['schemas', 'id', 'displayName'], 'properties' => ['schemas' => ['type' => 'array', 'items' => ['type' => 'string']], 'id' => ['type' => 'string'], 'displayName' => ['type' => 'string'], 'members' => ['type' => 'array', 'items' => ['type' => 'object']], 'meta' => ['type' => 'object']]], $schemas['ScimGroup']);
        self::assertSame(['type' => 'object', 'required' => ['schemas', 'totalResults', 'startIndex', 'itemsPerPage', 'Resources'], 'properties' => ['schemas' => ['type' => 'array', 'items' => ['type' => 'string']], 'totalResults' => ['type' => 'integer'], 'startIndex' => ['type' => 'integer'], 'itemsPerPage' => ['type' => 'integer'], 'Resources' => ['type' => 'array', 'items' => ['type' => 'object']]]], $schemas['ScimListResponse']);
        self::assertSame(['type' => 'object', 'required' => ['schemas', 'detail', 'status'], 'properties' => ['schemas' => ['type' => 'array', 'items' => ['type' => 'string']], 'detail' => ['type' => 'string'], 'status' => ['type' => 'string'], 'scimType' => ['type' => 'string']]], $schemas['ScimError']);
    }
}
