<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\Controller\V2;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use YiiRocks\Voyti\Api\Scim\ScimEtag;
use RuntimeException;
use YiiRocks\Voyti\Exception\PasswordPolicyViolationException;
use YiiRocks\Voyti\Event\User\UserEvent;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\Service\Password\PasswordGeneratorInterface;
use YiiRocks\Voyti\Service\Password\PasswordHistoryService;
use YiiRocks\Voyti\Service\User\UserCreationHelper;
use YiiRocks\Voyti\Service\User\UserUpdateHelper;
use Yiisoft\Data\Db\QueryDataReader;
use Yiisoft\ActiveRecord\ActiveQueryInterface;
use Yiisoft\Data\Paginator\OffsetPaginator;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactoryInterface;
use Yiisoft\Db\QueryBuilder\Condition\Like;
use Yiisoft\Db\QueryBuilder\Condition\LikeMode;
use Yiisoft\Http\Header;
use Yiisoft\Http\Status;
use Yiisoft\RequestProvider\RequestProviderInterface;
use Yiisoft\Router\HydratorAttribute\RouteArgument;

/**
 * SCIM 2.0 discovery and User resource endpoints.
 *
 * The routes are contributed to voyti-api and therefore use its bearer-token and admin-access
 * middleware. Group provisioning is exposed by GroupController through an explicit RBAC mapping.
 */
final readonly class ScimController
{
    private const string SEARCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';
    private const string PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    private const string USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
    private const string GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    private const int MAX_COUNT = 100;

    public function __construct(
        private DataResponseFactoryInterface $responseFactory,
        private RequestProviderInterface $requestProvider,
        private PasswordGeneratorInterface $passwordGenerator,
        private PasswordHistoryService $passwordHistoryService,
        private UserCreationHelper $userCreationHelper,
        private UserUpdateHelper $userUpdateHelper,
        private EventDispatcherInterface $eventDispatcher,
    ) {}

    public function serviceProviderConfig(): ResponseInterface
    {
        return $this->scimResponse([
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'documentationUri' => 'https://www.yii.rocks/voyti/api-scim/',
            'patch' => ['supported' => true],
            'bulk' => ['supported' => true, 'maxOperations' => 100, 'maxPayloadSize' => 1048576],
            'filter' => ['supported' => true, 'maxResults' => self::MAX_COUNT],
            'changePassword' => ['supported' => true],
            'sort' => ['supported' => true],
            'etag' => ['supported' => true],
            'authenticationSchemes' => [[
                'name' => 'oauthbearertoken',
                'description' => 'Voyti API bearer token',
                'specUri' => 'https://www.rfc-editor.org/rfc/rfc6750',
                'type' => 'oauth2',
                'primary' => true,
            ]],
        ]);
    }

    public function resourceTypes(): ResponseInterface
    {
        return $this->scimResponse([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => 2,
            'startIndex' => 1,
            'itemsPerPage' => 2,
            'Resources' => [
                $this->resourceType('User', '/v2/Users', self::USER_SCHEMA, 'Voyti users'),
                $this->resourceType('Group', '/v2/Groups', self::GROUP_SCHEMA, 'Voyti RBAC roles'),
            ],
        ]);
    }

    public function schemas(): ResponseInterface
    {
        return $this->scimResponse([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => 2,
            'startIndex' => 1,
            'itemsPerPage' => 2,
            'Resources' => [$this->userSchema(), $this->groupSchema()],
        ]);
    }

    public function schema(#[RouteArgument] string $schema): ResponseInterface
    {
        if ($schema === self::GROUP_SCHEMA) {
            return $this->scimResponse($this->groupSchema());
        }
        if ($schema !== self::USER_SCHEMA) {
            return $this->error('Schema not found', Status::NOT_FOUND);
        }

        return $this->scimResponse($this->userSchema());
    }

    public function index(): ResponseInterface
    {
        return $this->list($this->queryParams());
    }

    public function search(): ResponseInterface
    {
        $body = $this->body();
        /** @var mixed $rawSchemas */
        $rawSchemas = $body['schemas'] ?? [];
        if (!is_array($rawSchemas) || !in_array(self::SEARCH_SCHEMA, $rawSchemas, true)) {
            return $this->error('The request must declare the SCIM SearchRequest schema', Status::BAD_REQUEST, 'invalidSyntax');
        }
        return $this->list($body);
    }

    public function view(#[RouteArgument] int $id): ResponseInterface
    {
        $user = User::findById($id);
        if ($user === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $resource = $this->selectAttributes($this->resource($user), $this->queryParams());
        if (ScimEtag::matchesNone($this->requestProvider->get(), $resource)) {
            return $this->notModified($resource);
        }
        return $this->resourceResponse($resource);
    }

    public function create(): ResponseInterface
    {
        return $this->createResource($this->body());
    }

    /** @param array<string, mixed> $body */
    public function createResource(array $body): ResponseInterface
    {
        $username = (string) ($body['userName'] ?? '');
        $email = $this->emailFromBody($body);
        if ($username === '' || $email === '') {
            return $this->error('userName and emails[0].value are required', Status::BAD_REQUEST);
        }

        try {
            $user = $this->userCreationHelper->buildUser(
                $email,
                $username,
                (string) ($body['password'] ?? $this->passwordGenerator->generate(20)),
            );
            $this->userCreationHelper->persistAndNotifySkippingConfirmation($user);
        } catch (PasswordPolicyViolationException $exception) {
            return $this->error(implode(' ', $exception->getErrors()), Status::BAD_REQUEST, 'invalidValue');
        } catch (RuntimeException $exception) {
            return $this->error($exception->getMessage(), Status::CONFLICT);
        }

        return $this->resourceResponse($this->resource($user), Status::CREATED);
    }

    public function replace(#[RouteArgument] int $id): ResponseInterface
    {
        return $this->replaceResource($id, $this->body());
    }

    /** @param array<string, mixed> $body */
    public function replaceResource(int $id, array $body): ResponseInterface
    {
        return $this->applyChanges($id, $body);
    }

    public function patch(#[RouteArgument] int $id): ResponseInterface
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
    public function patchResource(int $id, array $body): ResponseInterface
    {
        foreach (($body['Operations'] ?? []) as $operation) {
            if (!is_array($operation) || !isset($operation['op'])) {
                return $this->error('Invalid PATCH operation', Status::BAD_REQUEST);
            }
            $op = strtolower((string) $operation['op']);
            if (!in_array($op, ['add', 'replace', 'remove'], true)) {
                return $this->error('Unsupported PATCH operation', Status::BAD_REQUEST);
            }
            $path = strtolower((string) ($operation['path'] ?? ''));
            /** @var mixed $value */
            $value = $operation['value'] ?? null;
            if ($path === 'active') {
                /** @psalm-suppress MixedAssignment */
                $body['active'] = $op === 'remove' ? true : $value;
            } elseif ($path === 'username' && is_scalar($value)) {
                $body['userName'] = $value;
            } elseif ($path === 'emails' && is_array($value)) {
                $body['emails'] = $value;
            } else {
                return $this->error('Unsupported PATCH path', Status::BAD_REQUEST);
            }
        }

        return $this->applyChanges($id, $body);
    }

    public function delete(#[RouteArgument] int $id): ResponseInterface
    {
        return $this->deleteResource($id);
    }

    public function deleteResource(int $id): ResponseInterface
    {
        $user = User::findById($id);
        if ($user === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        $resource = $this->resource($user);
        if (!ScimEtag::matches($this->requestProvider->get(), $resource)) {
            return $this->error('The resource has changed since it was retrieved', Status::PRECONDITION_FAILED, 'invalidVers');
        }
        $user->delete();
        $this->eventDispatcher->dispatch(new UserEvent($user, UserEvent::DELETE));
        return $this->responseFactory->createResponse(null, Status::NO_CONTENT);
    }

    /** @param array<string, mixed> $queryParams */
    private function list(array $queryParams): ResponseInterface
    {
        $filter = null;
        if (isset($queryParams['filter']) && is_string($queryParams['filter'])) {
            $filter = $queryParams['filter'];
        }
        $filterMatches = [];
        /** @var array<int, string> $filterMatches */
        if ($filter !== null && preg_match('/^(userName|emails\.value)\s+(eq|co|sw)\s+"([^"]+)"$/i', $filter, $filterMatches) !== 1) {
            return $this->error('The filter expression is not supported', Status::BAD_REQUEST, 'invalidFilter');
        }
        /** @psalm-suppress MixedArgumentTypeCoercion */
        $query = $this->queryFromFilter($filter, $filterMatches);
        $sortBy = strtolower((string) ($queryParams['sortBy'] ?? 'userName'));
        $sortField = match ($sortBy) {
            'emails.value' => 'email',
            'meta.created' => 'created_at',
            default => 'username',
        };
        $sortDirection = strtolower((string) ($queryParams['sortOrder'] ?? 'ascending')) === 'descending' ? SORT_DESC : SORT_ASC;
        $query = $query->orderBy([$sortField => $sortDirection]);
        $startIndex = 1;
        if (isset($queryParams['startIndex'])) {
            $startIndex = (int) $queryParams['startIndex'];
        }
        $startIndex = max(1, $startIndex);
        $count = min(max(0, (int) ($queryParams['count'] ?? 25)), self::MAX_COUNT);
        $currentPage = (int) ceil($startIndex / max(1, $count));
        $paginator = new OffsetPaginator(new QueryDataReader($query));
        if ($count > 0) {
            $paginator = $paginator->withPageSize($count);
        }
        /** @psalm-suppress ArgumentTypeCoercion */
        $paginator = $paginator->withCurrentPage($currentPage);
        /** @var list<User> $users */
        $users = $count === 0 ? [] : iterator_to_array($paginator->read());
        $resources = array_map(fn(User $user): array => $this->selectAttributes($this->resource($user), $queryParams), $users);

        $response = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => $paginator->getTotalItems(),
            'startIndex' => $startIndex,
            'itemsPerPage' => count($resources),
            'Resources' => $resources,
        ];
        return $this->conditionalCollectionResponse($response);
    }

    /** @return array<string, mixed> */
    private function resourceType(string $id, string $endpoint, string $schema, string $description): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id' => $id,
            'name' => $id,
            'endpoint' => $endpoint,
            'description' => $description,
            'schema' => $schema,
            'meta' => ['resourceType' => 'ResourceType'],
        ];
    }

    /** @return array<string, mixed> */
    private function userSchema(): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => self::USER_SCHEMA,
            'name' => 'User',
            'description' => 'Voyti user account',
            'attributes' => [
                ['name' => 'userName', 'type' => 'string', 'multiValued' => false, 'required' => true, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'server'],
                ['name' => 'active', 'type' => 'boolean', 'multiValued' => false, 'required' => false, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'none'],
                ['name' => 'password', 'type' => 'string', 'multiValued' => false, 'required' => false, 'caseExact' => true, 'mutability' => 'writeOnly', 'returned' => 'never'],
                ['name' => 'emails', 'type' => 'complex', 'multiValued' => true, 'required' => true, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [
                    ['name' => 'value', 'type' => 'string', 'multiValued' => false, 'required' => true],
                    ['name' => 'type', 'type' => 'string', 'multiValued' => false, 'required' => false],
                    ['name' => 'primary', 'type' => 'boolean', 'multiValued' => false, 'required' => false],
                ]],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function groupSchema(): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => self::GROUP_SCHEMA,
            'name' => 'Group',
            'description' => 'Voyti RBAC role group',
            'attributes' => [
                ['name' => 'displayName', 'type' => 'string', 'multiValued' => false, 'required' => true, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'server'],
                ['name' => 'members', 'type' => 'complex', 'multiValued' => true, 'required' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [
                    ['name' => 'value', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
                    ['name' => '$ref', 'type' => 'reference', 'referenceTypes' => ['User'], 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
                    ['name' => 'display', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'readOnly'],
                    ['name' => 'type', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
                ]],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function body(): array
    {
        $body = $this->requestProvider->get()->getParsedBody();
        if (!is_array($body)) {
            return [];
        }

        /** @var array<string, mixed> $body */
        return $body;
    }

    /** @param array<string, mixed> $body */
    private function applyChanges(int $id, array $body): ResponseInterface
    {
        $user = User::findById($id);
        if ($user === null) {
            return $this->error('Resource not found', Status::NOT_FOUND);
        }
        if (!ScimEtag::matches($this->requestProvider->get(), $this->resource($user))) {
            return $this->error('The resource has changed since it was retrieved', Status::PRECONDITION_FAILED, 'invalidVers');
        }
        $username = array_key_exists('userName', $body) ? (string) $body['userName'] : null;
        $email = array_key_exists('emails', $body) ? $this->emailFromBody($body) : null;
        $password = array_key_exists('password', $body) ? (string) $body['password'] : '';
        $active = array_key_exists('active', $body) ? boolval($body['active']) : null;
        if ($email === '') {
            return $this->error('emails[0].value is required', Status::BAD_REQUEST);
        }
        if ($password !== '' && $this->passwordHistoryService->wasUsedRecently($user, $password)) {
            return $this->error('Password has been used recently', Status::BAD_REQUEST);
        }

        try {
            $changedFields = $this->userUpdateHelper->changedFields($user, $username, $email, $password);
            $activeChanged = match ($active) {
                true => $user->isBlocked(),
                false => !$user->isBlocked(),
                default => false,
            };
            if ($activeChanged) {
                $changedFields[] = 'active';
            }
            $this->userUpdateHelper->apply($user, $changedFields, static function (User $user) use ($username, $email, $active): void {
                if ($username !== null) {
                    $user->setUsername($username);
                }
                if ($email !== null) {
                    $user->setEmail($email);
                }
                if ($active !== null) {
                    $user->setBlockedAt($active ? null : time());
                }
            }, $password);
        } catch (PasswordPolicyViolationException $exception) {
            return $this->error(implode(' ', $exception->getErrors()), Status::BAD_REQUEST, 'invalidValue');
        } catch (RuntimeException $exception) {
            return $this->error($exception->getMessage(), Status::BAD_REQUEST);
        }

        return $this->resourceResponse($this->resource($user));
    }

    /** @param array<string, mixed> $body */
    private function emailFromBody(array $body): string
    {
        $emails = $body['emails'] ?? [];
        if (!is_array($emails) || !isset($emails[0]) || !is_array($emails[0])) {
            return '';
        }

        if (!array_key_exists('value', $emails[0]) || !is_scalar($emails[0]['value'])) {
            return '';
        }

        return (string) $emails[0]['value'];
    }

    /** @param array<int, string> $matches */
    private function queryFromFilter(?string $filter, array $matches = []): ActiveQueryInterface
    {
        if ($filter === null) {
            return User::searchQuery();
        }
        $field = strtolower($matches[1]) === 'username' ? 'username' : 'email';
        $value = $matches[3];
        $operator = strtolower($matches[2]);
        if ($operator === 'eq') {
            return User::query()->andWhere([$field => $value]);
        }
        return User::query()->andWhere(new Like(
            $field,
            $value,
            mode: $operator === 'sw' ? LikeMode::StartsWith : LikeMode::Contains,
        ));
    }

    /** @return array<string, mixed> */
    private function resource(User $user): array
    {
        $timestamp = static fn(int $value): string => gmdate('c', $value);
        return [
            'schemas' => [self::USER_SCHEMA],
            'id' => $user->getId(),
            'userName' => $user->getUsername(),
            'active' => !$user->isBlocked(),
            'emails' => [['value' => $user->getEmail(), 'primary' => true]],
            'meta' => [
                'resourceType' => 'User',
                'created' => $timestamp($user->getCreatedAt()),
                'lastModified' => $timestamp($user->getUpdatedAt()),
                'location' => $this->location('Users', (string) $user->getId()),
            ],
        ];
    }

    /**
     * @param array<string, mixed> $resource
     * @param array<string, mixed> $query
     * @return array<string, mixed>
     */
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

    /** @return array<string, mixed> */
    private function queryParams(): array
    {
        $params = $this->requestProvider->get()->getQueryParams();
        /** @var array<string, mixed> $params */
        return $params;
    }

    /** @return array<int, string> */
    private function attributeList(mixed $value): array
    {
        if (!is_string($value)) {
            return [];
        }
        return array_filter(array_map(static fn(string $item): string => strtolower(trim($item)), explode(',', $value)));
    }

    /** @param array $data */
    private function scimResponse(array $data, int $status = Status::OK): ResponseInterface
    {
        return $this->responseFactory->createResponse($data, $status)->withHeader(Header::CONTENT_TYPE, 'application/scim+json');
    }

    /** @param array<string, mixed> $data */
    private function resourceResponse(array $data, int $status = Status::OK): ResponseInterface
    {
        $data = ScimEtag::withVersion($data);
        /** @var array<string, mixed> $data */
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

    private function location(string $resource, string|int $id): string
    {
        $uri = $this->requestProvider->get()->getUri();
        return (string) $uri->withPath('/v2/' . $resource . '/' . rawurlencode((string) $id))->withQuery('')->withFragment('');
    }
}
