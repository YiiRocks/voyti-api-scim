<?php

declare(strict_types=1);
use YiiRocks\Voyti\Api\Scim\OpenApi\ScimOpenApiSpecContributor;

/** @var array $params */

return [
    ScimOpenApiSpecContributor::class => [
        'class' => ScimOpenApiSpecContributor::class,
        'tags' => ['voyti-api.openapi-contributor'],
    ],
];
