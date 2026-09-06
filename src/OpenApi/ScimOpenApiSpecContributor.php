<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\OpenApi;

use Override;
use YiiRocks\Voyti\Api\OpenApi\OpenApiSpecContributorInterface;

final readonly class ScimOpenApiSpecContributor implements OpenApiSpecContributorInterface
{
    #[Override]
    public function getMethodSpec(string $routeName, string $method): ?array
    {
        $operations = [
            'voyti/api-scim-v2-service-provider-config' => ['get', 'serviceProviderConfig', 'Get SCIM service-provider capabilities', 'Discovery'],
            'voyti/api-scim-v2-resource-types' => ['get', 'listResourceTypes', 'List SCIM resource types', 'Discovery'],
            'voyti/api-scim-v2-schemas' => ['get', 'listSchemas', 'List SCIM schemas', 'Discovery'],
            'voyti/api-scim-v2-schema' => ['get', 'getSchema', 'Get a SCIM schema', 'Discovery'],
            'voyti/api-scim-v2-bulk' => ['post', 'bulk', 'Process SCIM bulk operations', 'Bulk'],
            'voyti/api-scim-v2-users-index' => ['get', 'listUsers', 'List SCIM users', 'Users'],
            'voyti/api-scim-v2-users-create' => ['post', 'createUser', 'Create a SCIM user', 'Users'],
            'voyti/api-scim-v2-users-search' => ['post', 'searchUsers', 'Search SCIM users', 'Users'],
            'voyti/api-scim-v2-users-view' => ['get', 'getUser', 'Get a SCIM user', 'Users'],
            'voyti/api-scim-v2-users-replace' => ['put', 'replaceUser', 'Replace a SCIM user', 'Users'],
            'voyti/api-scim-v2-users-patch' => ['patch', 'patchUser', 'Patch a SCIM user', 'Users'],
            'voyti/api-scim-v2-users-delete' => ['delete', 'deleteUser', 'Delete a SCIM user', 'Users'],
            'voyti/api-scim-v2-groups-index' => ['get', 'listGroups', 'List SCIM groups', 'Groups'],
            'voyti/api-scim-v2-groups-create' => ['post', 'createGroup', 'Create a SCIM group', 'Groups'],
            'voyti/api-scim-v2-groups-search' => ['post', 'searchGroups', 'Search SCIM groups', 'Groups'],
            'voyti/api-scim-v2-groups-view' => ['get', 'getGroup', 'Get a SCIM group', 'Groups'],
            'voyti/api-scim-v2-groups-replace' => ['put', 'replaceGroup', 'Replace a SCIM group', 'Groups'],
            'voyti/api-scim-v2-groups-patch' => ['patch', 'patchGroup', 'Patch a SCIM group', 'Groups'],
            'voyti/api-scim-v2-groups-delete' => ['delete', 'deleteGroup', 'Delete a SCIM group', 'Groups'],
        ];
        if (!isset($operations[$routeName]) || $operations[$routeName][0] !== $method) {
            return null;
        }

        [, $operationId, $summary, $tag] = $operations[$routeName];
        return [
            'operationId' => $operationId,
            'summary' => $summary,
            'tags' => [$tag],
            'responses' => [
                '200' => ['description' => 'SCIM response'],
                '201' => ['description' => 'SCIM resource created'],
                '204' => ['description' => 'Resource deleted'],
                '400' => ['description' => 'SCIM validation error'],
                '409' => ['description' => 'Resource conflict'],
                '401' => ['description' => 'Authentication required'],
                '404' => ['description' => 'Resource not found'],
                '412' => ['description' => 'SCIM version conflict'],
                '413' => ['description' => 'Bulk payload too large'],
            ],
        ];
    }

    #[Override]
    public function schemas(): array
    {
        return [
            'ScimUser' => ['type' => 'object', 'required' => ['schemas', 'id', 'userName', 'emails'], 'properties' => [
                'schemas' => ['type' => 'array', 'items' => ['type' => 'string']],
                'id' => ['type' => 'string'],
                'userName' => ['type' => 'string'],
                'active' => ['type' => 'boolean'],
                'password' => ['type' => 'string', 'writeOnly' => true],
                'emails' => ['type' => 'array', 'items' => ['type' => 'object']],
                'meta' => ['type' => 'object'],
            ]],
            'ScimGroup' => ['type' => 'object', 'required' => ['schemas', 'id', 'displayName'], 'properties' => [
                'schemas' => ['type' => 'array', 'items' => ['type' => 'string']],
                'id' => ['type' => 'string'],
                'displayName' => ['type' => 'string'],
                'members' => ['type' => 'array', 'items' => ['type' => 'object']],
                'meta' => ['type' => 'object'],
            ]],
            'ScimListResponse' => ['type' => 'object', 'required' => ['schemas', 'totalResults', 'startIndex', 'itemsPerPage', 'Resources'], 'properties' => [
                'schemas' => ['type' => 'array', 'items' => ['type' => 'string']],
                'totalResults' => ['type' => 'integer'],
                'startIndex' => ['type' => 'integer'],
                'itemsPerPage' => ['type' => 'integer'],
                'Resources' => ['type' => 'array', 'items' => ['type' => 'object']],
            ]],
            'ScimError' => ['type' => 'object', 'required' => ['schemas', 'detail', 'status'], 'properties' => [
                'schemas' => ['type' => 'array', 'items' => ['type' => 'string']],
                'detail' => ['type' => 'string'],
                'status' => ['type' => 'string'],
                'scimType' => ['type' => 'string'],
            ]],
        ];
    }
}
