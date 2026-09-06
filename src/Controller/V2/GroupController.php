<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\Controller\V2;

use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\Api\Scim\ScimEtag;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactoryInterface;
use Yiisoft\Http\Header;
use Yiisoft\Http\Status;
use Yiisoft\RequestProvider\RequestProviderInterface;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Role;
use Yiisoft\Router\HydratorAttribute\RouteArgument;
use ArrayIterator;

/**
 * Exposes Voyti RBAC roles as SCIM Group resources. This makes the mapping explicit: a SCIM group
 * is a role, and group membership is a role assignment to a Voyti user. Permissions are never
 * exposed as groups.
 */
final readonly class GroupController
{
    private const string SEARCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';
    private const string PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    private const string GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    private const int FIRST_INDEX = 1;
    private const int MAX_COUNT = 100;

    public function __construct(
        private AssignmentsStorageInterface $assignmentsStorage,
        private DataResponseFactoryInterface $responseFactory,
        private ItemsStorageInterface $itemsStorage,
        private ManagerInterface $manager,
        private RequestProviderInterface $requestProvider,
    ) {}

    public function index(): ResponseInterface
    {
        /** @psalm-suppress MixedArgumentTypeCoercion */
        return $this->list($this->requestProvider->get()->getQueryParams());
    }

    public function search(): ResponseInterface
    {
        $body = $this->body();
        /** @var mixed $rawSchemas */
        $rawSchemas = $body['schemas'] ?? [];
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
        if (!in_array(self::SEARCH_SCHEMA, $schemas, true)) {
            return $this->error('The request must declare the SCIM SearchRequest schema', Status::BAD_REQUEST, 'invalidSyntax');
        }
        return $this->list($body);
    }

    public function view(#[RouteArgument] string $id): ResponseInterface
    {
        $role = $this->itemsStorage->getRole($id);
        if ($role === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $resource = $this->selectAttributes($this->resource($role), $this->queryParams());
        return ScimEtag::matchesNone($this->requestProvider->get(), $resource) ? $this->notModified($resource) : $this->resourceResponse($resource);
    }

    public function create(): ResponseInterface
    {
        return $this->createResource($this->body());
    }

    /** @param array<string, mixed> $body */
    public function createResource(array $body): ResponseInterface
    {
        $name = trim((string) ($body['displayName'] ?? ''));
        if ($name === '') {
            return $this->error('displayName is required', Status::BAD_REQUEST);
        }
        if ($this->itemsStorage->exists($name)) {
            return $this->error('Group already exists', Status::CONFLICT);
        }

        $members = $this->memberIds($body['members'] ?? []);
        $missing = $this->missingUsers($members);
        if ($missing !== []) {
            return $this->error('One or more group members do not exist: ' . implode(', ', $missing), Status::BAD_REQUEST);
        }

        try {
            $this->manager->addRole(new Role($name));
            $this->syncMembers($name, $members);
        } catch (InvalidArgumentException $exception) {
            return $this->error($exception->getMessage(), Status::BAD_REQUEST);
        }

        return $this->resourceResponse($this->resource($this->itemsStorage->getRole($name)), Status::CREATED);
    }

    public function replace(#[RouteArgument] string $id): ResponseInterface
    {
        return $this->replaceResource($id, $this->body());
    }

    /** @param array<string, mixed> $body */
    public function replaceResource(string $id, array $body): ResponseInterface
    {
        $role = $this->itemsStorage->getRole($id);
        if ($role === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $name = trim((string) ($body['displayName'] ?? $id));
        return $this->update($id, $name, $body['members'] ?? []);
    }

    public function patch(#[RouteArgument] string $id): ResponseInterface
    {
        $body = $this->body();
        /** @var mixed $rawSchemas */
        $rawSchemas = $body['schemas'] ?? [];
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
        if (!in_array(self::PATCH_SCHEMA, $schemas, true)) {
            return $this->error('The request must declare the SCIM PatchOp schema', Status::BAD_REQUEST, 'invalidSyntax');
        }
        return $this->patchResource($id, $body);
    }

    /** @param array<string, mixed> $body */
    public function patchResource(string $id, array $body): ResponseInterface
    {
        if ($this->itemsStorage->getRole($id) === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $name = $id;
        $members = null;
        $invalidOperation = false;
        /** @var list<mixed> $operations */
        $operations = $body['Operations'] ?? [];
        /** @psalm-suppress MixedAssignment */
        foreach ($operations as $operation) {
            if (!is_array($operation)) {
                $invalidOperation = true;
            } else {
                $op = strtolower((string) ($operation['op'] ?? ''));
                if (!in_array($op, ['add', 'replace', 'remove'], true)) {
                    $invalidOperation = true;
                } else {
                    $path = strtolower((string) ($operation['path'] ?? ''));
                    /** @var mixed $value */
                    $value = $operation['value'] ?? null;
                    if ($path === 'displayname' && is_scalar($value)) {
                        $name = trim((string) $value);
                    } elseif ($path === 'members' && $op === 'remove') {
                        $members = [];
                    } elseif ($path === 'members' && is_array($value)) {
                        $members = $value;
                    } elseif ($path === '' && is_array($value)) {
                        if (isset($value['displayName'])) {
                            if (is_scalar($value['displayName'])) {
                                $name = trim((string) $value['displayName']);
                            }
                        }
                        if (isset($value['members'])) {
                            /** @var list<mixed> $memberValue */
                            $memberValue = $value['members'];
                            $members = match (get_debug_type($value['members'])) {
                                'array' => $memberValue,
                                default => $members,
                            };
                        }
                    } else {
                        return $this->error('Unsupported PATCH path', Status::BAD_REQUEST);
                    }
                }
            }
        }

        return $invalidOperation ? $this->error('Invalid PATCH operation', Status::BAD_REQUEST) : $this->update($id, $name, $members);
    }

    public function delete(#[RouteArgument] string $id): ResponseInterface
    {
        return $this->deleteResource($id);
    }

    public function deleteResource(string $id): ResponseInterface
    {
        if ($this->itemsStorage->getRole($id) === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $resource = $this->resource($this->itemsStorage->getRole($id));
        if (!ScimEtag::matches($this->requestProvider->get(), $resource)) {
            return $this->error('The resource has changed since it was retrieved', Status::PRECONDITION_FAILED, 'invalidVers');
        }
        $this->manager->removeRole($id);
        return $this->responseFactory->createResponse(null, Status::NO_CONTENT);
    }

    /** @param array<string, mixed> $query */
    private function list(array $query): ResponseInterface
    {
        $roles = $this->itemsStorage->getRoles();
        if (isset($query['filter']) && is_string($query['filter']) && preg_match('/^displayName\s+(eq|co|sw)\s+"([^"]+)"$/i', $query['filter'], $matches) !== 1) {
            return $this->error('The filter expression is not supported', Status::BAD_REQUEST, 'invalidFilter');
        }
        if (isset($matches)) {
            /** @var array{1: string, 2: string} $matches */
            $operator = strtolower($matches[1]);
            $needle = $operator === 'eq' ? strtolower($matches[2]) : $matches[2];
            $roles = array_filter($roles, static function (Role $role) use ($operator, $needle): bool {
                $name = $role->getName();
                return match ($operator) {
                    'eq' => strtolower($name) === $needle,
                    'co' => stripos($name, $needle) !== false,
                    'sw' => strncasecmp($name, $needle, strlen($needle)) === 0,
                };
            });
        }

        $sortBy = strtolower((string) ($query['sortBy'] ?? 'displayName'));
        if ($sortBy !== 'displayname') {
            return $this->error('The sortBy attribute is not supported', Status::BAD_REQUEST, 'invalidValue');
        }
        usort($roles, static fn(Role $left, Role $right): int => strcasecmp($left->getName(), $right->getName()));
        if (($query['sortOrder'] ?? 'ascending') === 'descending') {
            $roles = array_reverse($roles);
        }
        $total = count($roles);
        $start = max(self::FIRST_INDEX, (int) ($query['startIndex'] ?? self::FIRST_INDEX));
        $count = min(max(0, (int) ($query['count'] ?? 25)), self::MAX_COUNT);
        $resources = array_map(
            fn(Role $role): array => $this->selectAttributes($this->resource($role), $query),
            array_slice($roles, $start - 1, $count),
        );

        $response = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => $total,
            'startIndex' => $start,
            'itemsPerPage' => count($resources),
            'Resources' => $resources,
        ];
        return $this->conditionalCollectionResponse($response);
    }

    /** @param array<string, mixed> $resource @param array<string, mixed> $query @return array<string, mixed> */
    private function selectAttributes(array $resource, array $query): array
    {
        $attributes = $this->attributeList($query['attributes'] ?? null);
        $excluded = $this->attributeList($query['excludedAttributes'] ?? null);
        if ($attributes === [] && $excluded === []) {
            return $resource;
        }

        $selected = ['schemas' => $resource['schemas'], 'id' => $resource['id'], 'meta' => $resource['meta']];
        /** @psalm-suppress MixedAssignment */
        foreach ($resource as $name => $value) {
            if (($attributes === [] || in_array(strtolower($name), $attributes, true)) && !in_array(strtolower($name), $excluded, true)) {
                $selected[$name] = $value;
            }
        }
        return $selected;
    }

    /** @return list<string> */
    private function attributeList(mixed $value): array
    {
        if (!is_string($value)) {
            return [];
        }
        return array_values(array_filter(array_map(static fn(string $item): string => strtolower(trim($item)), explode(',', $value))));
    }

    /** @return array<string, mixed> */
    private function queryParams(): array
    {
        $params = $this->requestProvider->get()->getQueryParams();
        /** @var array<string, mixed> $params */
        return $params;
    }

    /** @return array<string, string> */
    private function memberIds(mixed $rawMembers): array
    {
        if (!is_array($rawMembers)) {
            return [];
        }
        $ids = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($rawMembers as $member) {
            if (is_array($member)) {
                if (isset($member['value'])) {
                    if (is_scalar($member['value'])) {
                        $value = $member['value'];
                        $stringValue = strval($value);
                        $ids[$stringValue] = $stringValue;
                    }
                }
            }
        }
        return $ids;
    }

    /**
     * @param array<string, string> $ids
     * @return list<string>
     */
    private function missingUsers(array $ids): array
    {
        $missing = [];
        foreach ($ids as $id) {
            if (User::findById((int) $id)?->getId() !== $id) {
                $missing[] = $id;
            }
        }
        return $missing;
    }

    /** @param array<string, string> $members */
    private function syncMembers(string $name, array $members): void
    {
        $wanted = array_fill_keys($members, true);
        foreach ($this->assignmentsStorage->getByItemNames([$name]) as $assignment) {
            $id = $assignment->getUserId();
            if (!isset($wanted[$id])) {
                $this->assignmentsStorage->remove($name, $id);
            }
            unset($wanted[$id]);
        }
        foreach (array_keys($wanted) as $id) {
            $this->manager->assign($name, $id);
        }
    }

    /** @param mixed $rawMembers */
    private function update(string $oldName, string $newName, mixed $rawMembers): ResponseInterface
    {
        $currentRole = $this->itemsStorage->getRole($oldName);
        if ($currentRole === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        if (!ScimEtag::matches($this->requestProvider->get(), $this->resource($currentRole))) {
            return $this->error('The resource has changed since it was retrieved', Status::PRECONDITION_FAILED, 'invalidVers');
        }
        if ($newName === '') {
            return $this->error('displayName is required', Status::BAD_REQUEST);
        }
        if ($newName !== $oldName && $this->itemsStorage->exists($newName)) {
            return $this->error('Group already exists', Status::CONFLICT);
        }
        $members = $rawMembers === null ? null : $this->memberIds($rawMembers);
        if ($members !== null && ($missing = $this->missingUsers($members)) !== []) {
            return $this->error('One or more group members do not exist: ' . implode(', ', $missing), Status::BAD_REQUEST);
        }
        if ($newName !== $oldName) {
            $this->manager->updateRole($oldName, $currentRole->withName($newName));
            $this->assignmentsStorage->renameItem($oldName, $newName);
        }
        if ($members !== null) {
            $this->syncMembers($newName, $members);
        }
        return $this->resourceResponse($this->resource($this->itemsStorage->getRole($newName)));
    }

    /** @return array<string, mixed> */
    private function body(): array
    {
        $body = $this->requestProvider->get()->getParsedBody();
        if (!is_array($body)) {
            return [];
        }

        /** @var array<string, mixed> $body */
        /** @var array<string, mixed> $result */
        $result = iterator_to_array(new ArrayIterator($body));
        return $result;
    }

    /** @return array<string, mixed> */
    private function resource(?Role $role): array
    {
        if ($role === null) {
            return [];
        }
        $members = [];
        foreach ($this->assignmentsStorage->getByItemNames([$role->getName()]) as $assignment) {
            $user = User::findById((int) $assignment->getUserId());
            if ($user !== null) {
                $members[] = [
                    'value' => $user->getId(),
                    '$ref' => sprintf('/v2/Users/%d', $user->getIdOrZero()),
                    'display' => $user->getUsername(),
                    'type' => 'User',
                ];
            }
        }
        $created = $role->getCreatedAt() ?? time();
        $updated = $role->getUpdatedAt() ?? $created;
        $data = [
            'schemas' => [self::GROUP_SCHEMA],
            'id' => $role->getName(),
            'displayName' => $role->getName(),
            'members' => $members,
            'meta' => [
                'resourceType' => 'Group',
                'created' => gmdate('c', $created),
                'lastModified' => gmdate('c', $updated),
                'location' => $this->location('Groups', $role->getName()),
            ],
        ];
        /** @var array<string, mixed> $data */
        /** @var array<string, mixed> $result */
        $result = ScimEtag::withVersion($data);
        return $result;
    }

    /** @param array $data */
    private function scimResponse(array $data, int $status = Status::OK): ResponseInterface
    {
        return $this->responseFactory->createResponse($data, $status)->withHeader(Header::CONTENT_TYPE, 'application/scim+json');
    }

    /** @param array $data */
    private function resourceResponse(array $data, int $status = Status::OK): ResponseInterface
    {
        $data = ScimEtag::withVersion($data);
        return $this->scimResponse($data, $status)
            ->withHeader(Header::ETAG, ScimEtag::header($data))
            ->withHeader(Header::LOCATION, (string) ($data['meta']['location'] ?? ''));
    }

    /** @param array $data */
    private function conditionalCollectionResponse(array $data): ResponseInterface
    {
        if (ScimEtag::matchesNone($this->requestProvider->get(), $data)) {
            return $this->notModified($data);
        }
        return $this->scimResponse($data)->withHeader(Header::ETAG, ScimEtag::header($data));
    }

    /** @param array $data */
    private function notModified(array $data): ResponseInterface
    {
        return $this->responseFactory->createResponse(null, Status::NOT_MODIFIED)
            ->withHeader(Header::ETAG, ScimEtag::header($data));
    }

    private function error(string $message, int $status, string $scimType = ''): ResponseInterface
    {
        $data = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'detail' => $message,
            'status' => (string) $status,
        ];
        if ($scimType !== '') {
            $data['scimType'] = $scimType;
        }
        return $this->scimResponse($data, $status);
    }

    private function location(string $resource, string $id): string
    {
        $uri = $this->requestProvider->get()->getUri();
        return (string) $uri->withPath('/v2/' . $resource . '/' . rawurlencode($id))->withQuery('')->withFragment('');
    }
}
