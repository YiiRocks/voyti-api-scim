<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Controller\V2;

use Composer\InstalledVersions;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\EventDispatcher\EventDispatcherInterface;
use YiiRocks\Voyti\Api\Scim\Controller\V2\BulkController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\GroupController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\ScimController;
use YiiRocks\Voyti\Api\Scim\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\Clock\SystemClock;
use YiiRocks\Voyti\Service\MailService;
use YiiRocks\Voyti\Service\Password\PasswordHistoryService;
use YiiRocks\Voyti\Service\Password\RandomPasswordGenerator;
use YiiRocks\Voyti\Service\User\UserCreationHelper;
use YiiRocks\Voyti\Service\User\UserUpdateHelper;
use YiiRocks\Voyti\VoytiConfig;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactory;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactoryInterface;
use Yiisoft\Mailer\MailerInterface;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\RequestProvider\RequestProviderInterface;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Security\PasswordHasher;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\View\View;
use ReflectionMethod;
use Psr\Http\Message\ResponseInterface;

final class BulkControllerTest extends DatabaseTestCase
{
    public function testRejectsTooManyOperations(): void
    {
        $operations = array_fill(0, 101, []);
        $response = $this->controller($operations)->process();

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('application/scim+json', $response->getHeaderLine('Content-Type'));
        $tooMany = $response->getBody()->getData();
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $tooMany['schemas']);
        self::assertSame('tooMany', $tooMany['scimType']);
        self::assertSame('400', $tooMany['status']);
        $accepted = $this->controller(array_fill(0, 100, []))->process();
        self::assertSame(200, $accepted->getStatusCode());
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:BulkResponse'], $accepted->getBody()->getData()['schemas']);
        self::assertSame(400, $this->controller([], null, 0)->process()->getStatusCode());
        $stopped = $this->controller([['method' => 'OPTIONS', 'path' => '/v2/Users'], ['method' => 'OPTIONS', 'path' => '/v2/Users']], null, 1)->process();
        self::assertCount(1, $stopped->getBody()->getData()['Operations']);
    }

    public function testRequiresBulkSchemaAndRejectsOversizedPayloads(): void
    {
        $missingSchema = $this->controller([], null, null, ['urn:ietf:params:scim:api:messages:2.0:Other'])->process();
        self::assertSame(400, $missingSchema->getStatusCode());
        self::assertSame('invalidSyntax', $missingSchema->getBody()->getData()['scimType']);
        $schemas = new ReflectionMethod(BulkController::class, 'schemas');
        self::assertSame([], $schemas->invoke($this->controller([]), ['schemas' => 'invalid']));

        $oversized = $this->controller([], null, null, null, str_repeat('x', 1_048_577))->process();
        self::assertSame(413, $oversized->getStatusCode());
        self::assertSame('tooMany', $oversized->getBody()->getData()['scimType']);
        $limit = $this->controller([], null, null, null, str_repeat('x', 1_048_576))->process();
        self::assertSame(200, $limit->getStatusCode());
    }

    public function testRejectsInvalidOperationMethodAndPath(): void
    {
        $response = $this->controller([
            ['method' => 'OPTIONS', 'path' => '/v2/Users'],
            ['method' => 'POST', 'path' => '/v2/Unknown'],
            ['method' => 'POST', 'path' => '/v2/Users/1'],
            ['method' => 'DELETE', 'path' => '/v2/Users'],
            ['method' => 'post', 'path' => 'v2/users/1/extra'],
            ['method' => 'post', 'path' => 'v2/users'],
            ['method' => 'PUT', 'path' => '/v2/Users/1/extra'],
            ['method' => 'PUT', 'path' => '/v2/Users/bulkId:missing'],
            [],
        ])->process();

        self::assertSame(200, $response->getStatusCode());
        $data = $response->getBody()->getData();
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:BulkResponse'], $data['schemas']);
        self::assertSame('OPTIONS', $data['Operations'][0]['method']);
        self::assertSame('invalidSyntax', $data['Operations'][0]['response']['scimType']);
        self::assertSame('invalidPath', $data['Operations'][1]['response']['scimType']);
        self::assertSame('invalidPath', $data['Operations'][2]['response']['scimType']);
        self::assertSame('invalidPath', $data['Operations'][3]['response']['scimType']);
        self::assertSame('invalidPath', $data['Operations'][4]['response']['scimType']);
        self::assertSame('bulkId is required for POST operations', $data['Operations'][5]['response']['detail']);
        self::assertSame('invalidPath', $data['Operations'][6]['response']['scimType']);
        self::assertSame('invalidPath', $data['Operations'][7]['response']['scimType']);
        self::assertSame('invalidSyntax', $data['Operations'][8]['response']['scimType']);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $data['Operations'][0]['response']['schemas']);
    }

    public function testProcessesInvalidUserAndGroupCreates(): void
    {
        $response = $this->controller([
            ['method' => 'POST', 'path' => '/v2/Users', 'bulkId' => 'u1', 'data' => []],
            ['method' => 'POST', 'path' => '/v2/Groups', 'bulkId' => 'g1', 'data' => []],
        ])->process();

        $data = $response->getBody()->getData();
        self::assertIsArray($data);
        self::assertCount(2, $data['Operations']);
        self::assertSame('u1', $data['Operations'][0]['bulkId']);
        self::assertSame('g1', $data['Operations'][1]['bulkId']);
        self::assertSame('400', $data['Operations'][0]['status']);
        self::assertSame('400', $data['Operations'][1]['status']);
        self::assertSame('userName and emails[0].value are required', $data['Operations'][0]['response']['detail']);
        self::assertSame('displayName is required', $data['Operations'][1]['response']['detail']);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $data['Operations'][0]['response']['schemas']);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $data['Operations'][1]['response']['schemas']);
    }

    public function testDispatchesAllMutationArms(): void
    {
        $response = $this->controller([
            ['method' => 'POST', 'path' => '/v2/Users', 'bulkId' => 'bulk-user', 'data' => ['userName' => 'bulk', 'emails' => [['value' => 'bulk@example.com']]]],
            ['method' => 'PUT', 'path' => '/v2/Users/1', 'data' => ['emails' => []]],
            ['method' => 'PUT', 'path' => '/v2/Users/1', 'data' => ['userName' => 'bulk2', 'emails' => [['value' => 'bulk2@example.com']]]],
            ['method' => 'PATCH', 'path' => '/v2/Users/1', 'data' => ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations' => []]],
            ['method' => 'DELETE', 'path' => '/v2/Users/1'],
            ['method' => 'PUT', 'path' => '/v2/Groups/admins', 'data' => []],
            ['method' => 'PATCH', 'path' => '/v2/Groups/admins', 'data' => ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'admins']]]],
            ['method' => 'DELETE', 'path' => '/v2/Groups/admins'],
            'invalid-operation',
            ['method' => 'POST', 'path' => '/v2/Groups', 'bulkId' => 'invalid-group', 'data' => 'invalid'],
            ['method' => 'POST', 'path' => '/v2/Users', 'bulkId' => 42, 'data' => []],
        ])->process();
        self::assertSame(200, $response->getStatusCode());
        $operations = $response->getBody()->getData()['Operations'];
        self::assertCount(11, $operations);
        self::assertSame('201', $operations[0]['status']);
        self::assertSame('/v2/Users/1', $operations[0]['location']);
        self::assertSame('404', $operations[6]['status']);
        self::assertSame('/v2/Users/1', $operations[4]['location']);
        self::assertSame('400', $operations[1]['status']);
        self::assertArrayNotHasKey('location', $operations[1]);
        self::assertSame('invalidValue', $operations[10]['response']['scimType']);
        self::assertArrayNotHasKey('response', $operations[4]);
        $references = $this->controller([
            ['method' => 'POST', 'path' => '/v2/Users', 'bulkId' => 'new-user', 'data' => ['userName' => 'reference-user', 'emails' => [['value' => 'reference@example.com']]]],
            ['method' => 'DELETE', 'path' => '/v2/Users/bulkId:new-user'],
        ])->process()->getBody()->getData()['Operations'];
        self::assertSame('201', $references[0]['status']);
        self::assertSame('204', $references[1]['status']);
    }

    public function testNonDataResponseDoesNotCreateBulkResponseField(): void
    {
        $psr = new Psr17Factory();
        $factory = $this->createStub(DataResponseFactoryInterface::class);
        $realFactory = new DataResponseFactory($psr);
        $factory->method('createResponse')->willReturnCallback(function (mixed $data = null, int $code = 200) use ($psr, $realFactory): ResponseInterface {
            if (is_array($data) && ($data['schemas'][0] ?? null) === 'urn:ietf:params:scim:api:messages:2.0:BulkResponse') {
                return $realFactory->createResponse($data, $code);
            }
            return $psr->createResponse($code);
        });
        $response = $this->controller([['method' => 'POST', 'path' => '/v2/Users', 'bulkId' => 'invalid-user', 'data' => []]], $factory)->process();
        self::assertArrayNotHasKey('response', $response->getBody()->getData()['Operations'][0]);
    }

    public function testResponseDataIgnoresNonScimBodies(): void
    {
        $method = new ReflectionMethod(BulkController::class, 'responseData');
        $controller = $this->controller([]);
        $factory = new Psr17Factory();
        self::assertNull($method->invoke($controller, $factory->createResponse()));
        self::assertNull($method->invoke($controller, (new DataResponseFactory($factory))->createResponse(null)));

        $resolve = new ReflectionMethod(BulkController::class, 'resolveReferences');
        self::assertSame(['value' => '42', 'nested' => ['value' => 'bulkId:missing']], $resolve->invoke($controller, ['value' => 'bulkId:user', 'nested' => ['value' => 'bulkId:missing']], ['user' => '42']));
        self::assertSame(['bulkId:user', 'nested' => ['value' => '42']], $resolve->invoke($controller, ['bulkId:user', 'nested' => ['value' => 'bulkId:user']], ['user' => '42']));

        $schemas = new ReflectionMethod(BulkController::class, 'schemas');
        self::assertSame(['one', 'two'], $schemas->invoke($controller, ['schemas' => ['one', 2, 'two']]));
    }

    public function testBulkPatchRequiresPatchSchema(): void
    {
        $response = $this->controller([
            ['method' => 'PATCH', 'path' => '/v2/Users/1', 'data' => []],
            ['method' => 'PATCH', 'path' => '/v2/Users/1', 'data' => ['schemas' => [42]]],
        ])->process();

        $operations = $response->getBody()->getData()['Operations'];
        self::assertSame('invalidSyntax', $operations[0]['response']['scimType']);
        self::assertSame('invalidSyntax', $operations[1]['response']['scimType']);
    }

    /** @param list<array<string, mixed>> $operations */
    private function controller(array $operations, ?DataResponseFactoryInterface $factory = null, ?int $failOnErrors = null, ?array $schemas = null, ?string $rawBody = null): BulkController
    {
        $body = ['schemas' => $schemas ?? ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'], 'Operations' => $operations];
        if ($failOnErrors !== null) {
            $body['failOnErrors'] = $failOnErrors;
        }
        $psr = new Psr17Factory();
        $request = $psr->createServerRequest('POST', '/v2/Bulk')->withParsedBody($body);
        if ($rawBody !== null) {
            $request = $request->withBody($psr->createStream($rawBody));
        }
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn($request);
        $factory ??= new DataResponseFactory(new Psr17Factory());
        $groups = new GroupController(
            $this->createStub(AssignmentsStorageInterface::class),
            $factory,
            $this->createStub(ItemsStorageInterface::class),
            $this->createStub(ManagerInterface::class),
            $requests,
        );
        $config = $this->config();
        $history = new PasswordHistoryService(
            new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]),
            $config,
            $this->translator(),
        );
        $users = new ScimController(
            $factory,
            $requests,
            new RandomPasswordGenerator($config),
            $history,
            new UserCreationHelper(
                new MailService($this->createStub(MailerInterface::class), '/tmp', new View(), $this->translator(), $this->createStub(UrlGeneratorInterface::class)),
                $this->createStub(EventDispatcherInterface::class),
                new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]),
                $this->config(),
                $history,
                $this->translator(),
            ),
            new UserUpdateHelper(new SystemClock(), $this->createStub(EventDispatcherInterface::class), $history),
            $this->createStub(EventDispatcherInterface::class),
        );

        return new BulkController($factory, $groups, $requests, $users);
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
}
