<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Controller\V2;

use Nyholm\Psr7\Factory\Psr17Factory;
use Composer\InstalledVersions;
use Psr\EventDispatcher\EventDispatcherInterface;
use Yiisoft\Mailer\MailerInterface;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Security\PasswordHasher;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\View\View;
use YiiRocks\Voyti\Clock\SystemClock;
use YiiRocks\Voyti\Api\Scim\Controller\V2\ScimController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\GroupController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\BulkController;
use YiiRocks\Voyti\Service\MailService;
use YiiRocks\Voyti\Service\Password\PasswordHistoryService;
use YiiRocks\Voyti\Service\Password\RandomPasswordGenerator;
use YiiRocks\Voyti\Service\User\UserCreationHelper;
use YiiRocks\Voyti\Service\User\UserUpdateHelper;
use YiiRocks\Voyti\VoytiConfig;
use YiiRocks\Voyti\Api\Scim\tests\TestCase;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactoryInterface;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactory;
use Yiisoft\RequestProvider\RequestProviderInterface;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\DataResponse\DataStream\DataStream;

final class ScimControllerTest extends TestCase
{
    public function testServiceProviderConfigUsesScimContentType(): void
    {
        $response = (new Psr17Factory())->createResponse();
        $factory = $this->createMock(DataResponseFactoryInterface::class);
        $factory->expects(self::once())->method('createResponse')->with(self::callback(static fn(mixed $data): bool => is_array($data) && ($data['etag']['supported'] ?? false) === true), 200)->willReturn($response);

        $result = $this->controller($factory)->serviceProviderConfig();

        self::assertSame('application/scim+json', $result->getHeaderLine('Content-Type'));
        $data = $this->data($this->controller(new DataResponseFactory(new Psr17Factory()))->serviceProviderConfig());
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'], $data['schemas']);
        self::assertSame('https://www.yii.rocks/voyti/api-scim/', $data['documentationUri']);
        self::assertSame(['supported' => true], $data['patch']);
        self::assertSame(['supported' => true, 'maxOperations' => 100, 'maxPayloadSize' => 1048576], $data['bulk']);
        self::assertSame(['supported' => true, 'maxResults' => 100], $data['filter']);
        self::assertSame(['supported' => true], $data['changePassword']);
        self::assertSame(['supported' => true], $data['sort']);
        self::assertSame(['supported' => true], $data['etag']);
        self::assertSame('oauthbearertoken', $data['authenticationSchemes'][0]['name']);
        self::assertSame('Voyti API bearer token', $data['authenticationSchemes'][0]['description']);
        self::assertSame('https://www.rfc-editor.org/rfc/rfc6750', $data['authenticationSchemes'][0]['specUri']);
        self::assertSame('oauth2', $data['authenticationSchemes'][0]['type']);
        self::assertTrue($data['authenticationSchemes'][0]['primary']);
    }

    public function testUnsupportedSchemaReturnsScimNotFoundError(): void
    {
        $response = (new Psr17Factory())->createResponse(404);
        $factory = $this->createMock(DataResponseFactoryInterface::class);
        $factory->expects(self::once())->method('createResponse')->with(self::callback(static fn(mixed $data): bool => is_array($data)), 404)->willReturn($response);

        $result = $this->controller($factory)->schema('unsupported');

        self::assertSame(404, $result->getStatusCode());
        self::assertSame('application/scim+json', $result->getHeaderLine('Content-Type'));
    }

    public function testSearchRequiresSearchRequestSchema(): void
    {
        $controller = $this->controller(new DataResponseFactory(new Psr17Factory()));

        $response = $controller->search();

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalidSyntax', $this->data($response)['scimType']);
        self::assertSame('invalidSyntax', $this->data($controller->patch(1))['scimType']);
    }

    public function testDiscoveryEndpointsAndSchemaResources(): void
    {
        $controller = $this->controller(new DataResponseFactory(new Psr17Factory()));

        $resourceTypes = $this->data($controller->resourceTypes());
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:ListResponse'], $resourceTypes['schemas']);
        self::assertSame(2, $resourceTypes['totalResults']);
        self::assertSame(1, $resourceTypes['startIndex']);
        self::assertSame(2, $resourceTypes['itemsPerPage']);
        self::assertSame(2, count($resourceTypes['Resources']));
        self::assertSame('/v2/Users', $resourceTypes['Resources'][0]['endpoint']);
        self::assertSame('/v2/Groups', $resourceTypes['Resources'][1]['endpoint']);
        self::assertSame(['User', 'Group'], array_column($resourceTypes['Resources'], 'name'));
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], $resourceTypes['Resources'][0]['schemas']);
        self::assertSame('Voyti users', $resourceTypes['Resources'][0]['description']);
        self::assertSame('Voyti RBAC roles', $resourceTypes['Resources'][1]['description']);
        self::assertSame('User', $resourceTypes['Resources'][0]['id']);
        self::assertSame('urn:ietf:params:scim:schemas:core:2.0:User', $resourceTypes['Resources'][0]['schema']);
        self::assertSame(['resourceType' => 'ResourceType'], $resourceTypes['Resources'][0]['meta']);
        self::assertSame('Group', $resourceTypes['Resources'][1]['id']);
        self::assertSame('urn:ietf:params:scim:schemas:core:2.0:Group', $resourceTypes['Resources'][1]['schema']);
        self::assertSame(['resourceType' => 'ResourceType'], $resourceTypes['Resources'][1]['meta']);
        $schemas = $this->data($controller->schemas());
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:ListResponse'], $schemas['schemas']);
        self::assertSame(2, $schemas['totalResults']);
        self::assertSame(1, $schemas['startIndex']);
        self::assertSame(2, $schemas['itemsPerPage']);
        self::assertSame(2, count($schemas['Resources']));
        self::assertSame('urn:ietf:params:scim:schemas:core:2.0:User', $schemas['Resources'][0]['id']);
        self::assertSame('urn:ietf:params:scim:schemas:core:2.0:Group', $schemas['Resources'][1]['id']);
        self::assertSame('User', $this->data($controller->schema('urn:ietf:params:scim:schemas:core:2.0:User'))['name']);
        self::assertSame('Group', $this->data($controller->schema('urn:ietf:params:scim:schemas:core:2.0:Group'))['name']);
        $userSchema = $this->data($controller->schema('urn:ietf:params:scim:schemas:core:2.0:User'));
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:Schema'], $userSchema['schemas']);
        self::assertSame('Voyti user account', $userSchema['description']);
        self::assertSame(['userName', 'active', 'password', 'emails'], array_column($userSchema['attributes'], 'name'));
        self::assertSame(false, $userSchema['attributes'][0]['multiValued']);
        self::assertSame(true, $userSchema['attributes'][0]['required']);
        self::assertSame('server', $userSchema['attributes'][0]['uniqueness']);
        self::assertSame('boolean', $userSchema['attributes'][1]['type']);
        self::assertSame(false, $userSchema['attributes'][1]['required']);
        self::assertSame(['value', 'type', 'primary'], array_column($userSchema['attributes'][3]['subAttributes'], 'name'));
        self::assertSame(true, $userSchema['attributes'][3]['multiValued']);
        self::assertSame(true, $userSchema['attributes'][3]['required']);
        self::assertSame(true, $userSchema['attributes'][3]['subAttributes'][0]['required']);
        self::assertSame(false, $userSchema['attributes'][3]['subAttributes'][1]['required']);
        self::assertSame('boolean', $userSchema['attributes'][3]['subAttributes'][2]['type']);
        self::assertSame([
            ['name' => 'userName', 'type' => 'string', 'multiValued' => false, 'required' => true, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'server'],
            ['name' => 'active', 'type' => 'boolean', 'multiValued' => false, 'required' => false, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'none'],
            ['name' => 'password', 'type' => 'string', 'multiValued' => false, 'required' => false, 'caseExact' => true, 'mutability' => 'writeOnly', 'returned' => 'never'],
            ['name' => 'emails', 'type' => 'complex', 'multiValued' => true, 'required' => true, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [
                ['name' => 'value', 'type' => 'string', 'multiValued' => false, 'required' => true],
                ['name' => 'type', 'type' => 'string', 'multiValued' => false, 'required' => false],
                ['name' => 'primary', 'type' => 'boolean', 'multiValued' => false, 'required' => false],
            ]],
        ], $userSchema['attributes']);
        $groupSchema = $this->data($controller->schema('urn:ietf:params:scim:schemas:core:2.0:Group'));
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:Schema'], $groupSchema['schemas']);
        self::assertSame('Voyti RBAC role group', $groupSchema['description']);
        self::assertSame(['displayName', 'members'], array_column($groupSchema['attributes'], 'name'));
        self::assertSame('server', $groupSchema['attributes'][0]['uniqueness']);
        self::assertSame('readWrite', $groupSchema['attributes'][1]['mutability']);
        self::assertSame(['value', '$ref', 'display', 'type'], array_column($groupSchema['attributes'][1]['subAttributes'], 'name'));
        self::assertSame(['User'], $groupSchema['attributes'][1]['subAttributes'][1]['referenceTypes']);
        self::assertSame('readOnly', $groupSchema['attributes'][1]['subAttributes'][2]['mutability']);
        self::assertSame([
            ['name' => 'displayName', 'type' => 'string', 'multiValued' => false, 'required' => true, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => 'server'],
            ['name' => 'members', 'type' => 'complex', 'multiValued' => true, 'required' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [
                ['name' => 'value', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
                ['name' => '$ref', 'type' => 'reference', 'referenceTypes' => ['User'], 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
                ['name' => 'display', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'readOnly'],
                ['name' => 'type', 'type' => 'string', 'multiValued' => false, 'required' => false, 'mutability' => 'immutable'],
            ]],
        ], $groupSchema['attributes']);
    }

    public function testUserValidationAndPatchErrors(): void
    {
        $controller = $this->controller(new DataResponseFactory(new Psr17Factory()));

        $create = $controller->createResource([]);
        self::assertSame(400, $create->getStatusCode());
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $this->data($create)['schemas']);
        self::assertSame('userName and emails[0].value are required', $this->data($create)['detail']);
        self::assertSame('400', $this->data($create)['status']);
        self::assertSame(400, $controller->patchResource(1, ['Operations' => [[]]])->getStatusCode());
        self::assertSame(400, $controller->patchResource(1, ['Operations' => [['op' => 'remove', 'path' => 'unknown']]])->getStatusCode());
        self::assertSame(400, $controller->patchResource(1, ['Operations' => [['op' => 'invalid', 'path' => 'active']]])->getStatusCode());
    }

    public function testGroupsRejectUnsupportedFilterAsScimError(): void
    {
        $response = (new Psr17Factory())->createResponse(400);
        $request = (new Psr17Factory())->createServerRequest('GET', '/v2/Groups?filter=displayName%20ne%20%22admins%22');
        $factory = $this->createMock(DataResponseFactoryInterface::class);
        $factory->expects(self::once())->method('createResponse')->with(
            self::callback(static fn(mixed $data): bool => is_array($data) && ($data['scimType'] ?? null) === 'invalidFilter'),
            400,
        )->willReturn($response);
        $items = $this->createStub(ItemsStorageInterface::class);
        $items->method('getRoles')->willReturn([]);
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn($request);

        $result = (new GroupController(
            $this->createStub(AssignmentsStorageInterface::class),
            $factory,
            $items,
            $this->createStub(ManagerInterface::class),
            $requests,
        ))->index();

        self::assertSame(400, $result->getStatusCode());
        self::assertSame('application/scim+json', $result->getHeaderLine('Content-Type'));
    }

    public function testBulkRequiresOperations(): void
    {
        $response = (new Psr17Factory())->createResponse(400);
        $request = (new Psr17Factory())->createServerRequest('POST', '/v2/Bulk')->withParsedBody([]);
        $factory = $this->createMock(DataResponseFactoryInterface::class);
        $factory->expects(self::once())->method('createResponse')->with(
            self::callback(static fn(mixed $data): bool => is_array($data) && ($data['detail'] ?? null) === 'Operations is required' && ($data['status'] ?? null) === '400' && !array_key_exists('scimType', $data)),
            400,
        )->willReturn($response);
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn($request);

        $result = (new BulkController(
            $factory,
            new GroupController(
                $this->createStub(AssignmentsStorageInterface::class),
                $factory,
                $this->createStub(ItemsStorageInterface::class),
                $this->createStub(ManagerInterface::class),
                $requests,
            ),
            $requests,
            $this->controller($factory),
        ))->process();

        self::assertSame(400, $result->getStatusCode());
        self::assertSame('application/scim+json', $result->getHeaderLine('Content-Type'));
    }

    private function controller(DataResponseFactoryInterface $factory): ScimController
    {
        return new ScimController(
            $factory,
            $this->createStub(RequestProviderInterface::class),
            new RandomPasswordGenerator(),
            $history = new PasswordHistoryService(new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]), $this->config()),
            new UserCreationHelper(
                new MailService(
                    $this->createStub(MailerInterface::class),
                    '/tmp',
                    new View(),
                    $this->translator(),
                    $this->createStub(UrlGeneratorInterface::class),
                ),
                $this->createStub(EventDispatcherInterface::class),
                new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]),
                $this->config(),
                $history,
                $this->translator(),
            ),
            new UserUpdateHelper(new SystemClock(), $this->createStub(EventDispatcherInterface::class), $history),
            $this->createStub(EventDispatcherInterface::class),
        );
    }

    private function config(): VoytiConfig
    {
        $params = require InstalledVersions::getInstallPath('yiirocks/voyti') . '/config/params.php';
        return new VoytiConfig(...$params['yiirocks/voyti']);
    }

    private function translator(): TranslatorInterface
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('withDefaultCategory')->willReturnSelf();
        return $translator;
    }

    /** @return array<string, mixed> */
    private function data(mixed $response): array
    {
        $body = $response->getBody();
        self::assertInstanceOf(DataStream::class, $body);
        $data = $body->getData();
        self::assertIsArray($data);
        return $data;
    }
}
