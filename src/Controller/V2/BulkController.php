<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\Controller\V2;

use Psr\Http\Message\ResponseInterface;
use Yiisoft\DataResponse\DataStream\DataStream;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactoryInterface;
use Yiisoft\Http\Header;
use Yiisoft\Http\Status;
use Yiisoft\RequestProvider\RequestProviderInterface;

/** Processes SCIM bulk operations sequentially and returns one result per operation. */
final readonly class BulkController
{
    private const string BULK_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest';
    private const string BULK_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:BulkResponse';
    private const string PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    private const int MAX_OPERATIONS = 100;
    private const int MAX_PAYLOAD_SIZE = 1_048_576;

    public function __construct(
        private DataResponseFactoryInterface $responseFactory,
        private GroupController $groups,
        private RequestProviderInterface $requestProvider,
        private ScimController $users,
    ) {}

    public function process(): ResponseInterface
    {
        $request = $this->requestProvider->get();
        $size = $request->getBody()->getSize();
        if ($size !== null && $size > self::MAX_PAYLOAD_SIZE) {
            return $this->error('The bulk request exceeds the maxPayloadSize limit of 1048576 bytes', Status::PAYLOAD_TOO_LARGE, 'tooMany');
        }
        $body = $request->getParsedBody();
        if (!is_array($body) || !isset($body['Operations']) || !is_array($body['Operations'])) {
            return $this->error('Operations is required', Status::BAD_REQUEST);
        }
        if (!in_array(self::BULK_SCHEMA, $this->schemas($body), true)) {
            return $this->error('The request must declare the SCIM BulkRequest schema', Status::BAD_REQUEST, 'invalidSyntax');
        }
        if (count($body['Operations']) > self::MAX_OPERATIONS) {
            return $this->error('The bulk request exceeds the maximum operation count', Status::BAD_REQUEST, 'tooMany');
        }
        $failOnErrors = null;
        if (array_key_exists('failOnErrors', $body)) {
            $candidate = $body['failOnErrors'];
            if (!is_int($candidate) || $candidate < 1) {
                return $this->error('failOnErrors must be a positive integer', Status::BAD_REQUEST, 'invalidValue');
            }
            $failOnErrors = $candidate;
        }

        /** @var list<mixed> $rawOperations */
        $rawOperations = $body['Operations'];
        /** @var list<array<string, mixed>> $operations */
        $operations = [];
        /** @var array<string, string> $references */
        $references = [];
        $errors = 0;
        /** @psalm-suppress MixedAssignment */
        foreach ($rawOperations as $operation) {
            /** @psalm-suppress MixedArgumentTypeCoercion */
            $result = $this->processOperation(is_array($operation) ? $operation : [], $references);
            $operations[] = $result;
            if ($result['status'] >= '400') {
                ++$errors;
                if ($failOnErrors !== null && $errors >= $failOnErrors) {
                    break;
                }
            }
        }

        return $this->response([
            'schemas' => [self::BULK_RESPONSE_SCHEMA],
            'Operations' => $operations,
        ]);
    }

    /** @param array<string, mixed> $operation @return array<string, mixed> */
    private function processOperation(array $operation, array &$references): array
    {
        $method = strtoupper((string) ($operation['method'] ?? ''));
        /** @psalm-suppress MixedArgument */
        $path = strval($operation['path'] ?? '');
        $result = ['method' => $method, 'status' => '400'];
        if (isset($operation['bulkId']) && is_string($operation['bulkId'])) {
            $result['bulkId'] = $operation['bulkId'];
        }
        if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $result['response'] = $this->errorData('Unsupported bulk operation method', 'invalidSyntax');
            return $result;
        }
        if (preg_match('~^/?v2/(Users|Groups)(?:/([^/]+))?$~i', $path, $matches) !== 1) {
            $result['response'] = $this->errorData('Unsupported bulk operation path', 'invalidPath');
            return $result;
        }

        $resource = strtolower($matches[1]);
        $id = $matches[2] ?? null;
        if ($id !== null && str_starts_with($id, 'bulkId:')) {
            $reference = substr($id, 7);
            if (!isset($references[$reference])) {
                $result['response'] = $this->errorData('Referenced bulkId does not exist', 'invalidPath');
                return $result;
            }
            /** @psalm-suppress MixedArgument */
            $id = strval($references[$reference]);
        }
        if ($method === 'POST' && $id !== null || $method !== 'POST' && $id === null) {
            $result['response'] = $this->errorData('The bulk operation path does not match its method', 'invalidPath');
            return $result;
        }
        if ($method === 'POST' && (!isset($operation['bulkId']) || !is_string($operation['bulkId']) || $operation['bulkId'] === '')) {
            $result['response'] = $this->errorData('bulkId is required for POST operations', 'invalidValue');
            return $result;
        }
        /** @var mixed $rawData */
        $rawData = $operation['data'] ?? [];
        /** @var array<string, mixed> $data */
        $data = [];
        if (is_array($rawData)) {
            /** @psalm-suppress MixedAssignment */
            foreach ($rawData as $key => $value) {
                if (is_string($key)) {
                    $data[$key] = $value;
                }
            }
            $data = $this->resolveReferences($data, $references);
        }
        /** @var mixed $rawSchemas */
        $rawSchemas = $data['schemas'] ?? [];
        /** @var list<string> $schemas */
        $schemas = [];
        if (is_array($rawSchemas)) {
            /** @psalm-suppress MixedAssignment */
            foreach ($rawSchemas as $schema) {
                if (is_string($schema)) {
                    $schemas[] = $schema;
                }
            }
        }
        if ($method === 'PATCH' && !in_array(self::PATCH_SCHEMA, $schemas, true)) {
            $result['response'] = $this->errorData('The request must declare the SCIM PatchOp schema', 'invalidSyntax');
            return $result;
        }
        $resourceId = $id ?? '';

        /** @psalm-suppress MixedArgumentTypeCoercion */
        $response = match ([$resource, $method]) {
            ['users', 'POST'] => $this->users->createResource($data),
            ['users', 'PUT'] => $this->users->replaceResource((int) $resourceId, $data),
            ['users', 'PATCH'] => $this->users->patchResource((int) $resourceId, $data),
            ['users', 'DELETE'] => $this->users->deleteResource((int) $resourceId),
            ['groups', 'POST'] => $this->groups->createResource($data),
            ['groups', 'PUT'] => $this->groups->replaceResource($resourceId, $data),
            ['groups', 'PATCH'] => $this->groups->patchResource($resourceId, $data),
            ['groups', 'DELETE'] => $this->groups->deleteResource($resourceId),
        };
        $result['status'] = (string) $response->getStatusCode();
        $responseData = $this->responseData($response);
        if ($responseData !== null && $response->getStatusCode() !== Status::NO_CONTENT) {
            $result['response'] = $responseData;
        }
        if (is_array($responseData) && isset($responseData['id'])) {
            /** @psalm-suppress MixedArgument */
            $result['location'] = sprintf('/v2/%s/%s', $resource === 'users' ? 'Users' : 'Groups', $responseData['id']);
            if (isset($operation['bulkId']) && is_string($operation['bulkId'])) {
                /** @psalm-suppress MixedArgument */
                $references[$operation['bulkId']] = strval($responseData['id']);
            }
        } elseif ($response->getStatusCode() < 400 && $id !== null) {
            $result['location'] = sprintf('/v2/%s/%s', $resource === 'users' ? 'Users' : 'Groups', $id);
        }
        return $result;
    }

    /** @param array<array-key, mixed> $data @param array<string, string> $references @return array<string, mixed> */
    private function resolveReferences(array $data, array $references): array
    {
        /** @psalm-suppress MixedAssignment */
        foreach ($data as $key => $value) {
            if (!is_string($key)) {
                continue;
            }
            if (is_string($value) && str_starts_with($value, 'bulkId:')) {
                $data[$key] = $references[substr($value, 7)] ?? $value;
            } elseif (is_array($value)) {
                $data[$key] = $this->resolveReferences($value, $references);
            }
        }
        return $data;
    }

    /** @param array<array-key, mixed> $data @return list<string> */
    private function schemas(array $data): array
    {
        $rawSchemas = $data['schemas'] ?? [];
        if (!is_array($rawSchemas)) {
            return [];
        }
        $schemas = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($rawSchemas as $schema) {
            if (is_string($schema)) {
                $schemas[] = $schema;
            }
        }
        return $schemas;
    }

    /** @return array<string, mixed>|null */
    private function responseData(ResponseInterface $response): ?array
    {
        $body = $response->getBody();
        if (!$body instanceof DataStream) {
            return null;
        }
        /** @var mixed $data */
        $data = $body->getData();
        if (is_array($data)) {
            /** @var array<string, mixed> $data */
            return $data;
        }
        return null;
    }

    /** @return array<string, mixed> */
    private function errorData(string $detail, string $scimType): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'detail' => $detail,
            'status' => '400',
            'scimType' => $scimType,
        ];
    }

    /** @param array<string, mixed> $data */
    private function response(array $data): ResponseInterface
    {
        return $this->responseFactory->createResponse($data)->withHeader(Header::CONTENT_TYPE, 'application/scim+json');
    }

    private function error(string $detail, int $status, string $scimType = ''): ResponseInterface
    {
        $data = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'detail' => $detail,
            'status' => (string) $status,
        ];
        if ($scimType !== '') {
            $data['scimType'] = $scimType;
        }
        return $this->responseFactory->createResponse($data, $status)->withHeader(Header::CONTENT_TYPE, 'application/scim+json');
    }
}
