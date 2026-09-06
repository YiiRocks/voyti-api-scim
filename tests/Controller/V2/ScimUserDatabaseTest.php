<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Controller\V2;

use Composer\InstalledVersions;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\EventDispatcher\EventDispatcherInterface;
use YiiRocks\Voyti\Exception\ActionPreventedException;
use YiiRocks\Voyti\Event\User\UserEvent;
use YiiRocks\Voyti\Api\Scim\Controller\V2\ScimController;
use YiiRocks\Voyti\Api\Scim\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\Clock\SystemClock;
use YiiRocks\Voyti\Service\MailService;
use YiiRocks\Voyti\Service\Password\PasswordHistoryService;
use YiiRocks\Voyti\Service\Password\RandomPasswordGenerator;
use YiiRocks\Voyti\Service\Password\PasswordGeneratorInterface;
use YiiRocks\Voyti\Service\User\UserCreationHelper;
use YiiRocks\Voyti\Service\User\UserUpdateHelper;
use YiiRocks\Voyti\VoytiConfig;
use Yiisoft\DataResponse\DataStream\DataStream;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactory;
use Yiisoft\Mailer\MailerInterface;
use Yiisoft\RequestProvider\RequestProviderInterface;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Security\PasswordHasher;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\View\View;
use RuntimeException;

final class ScimUserDatabaseTest extends DatabaseTestCase
{
    public function testUserCrudAndConditionalGet(): void
    {
        $factory = new Psr17Factory();
        foreach ([
            $this->controller($factory->createServerRequest('GET', '/v2/Users/999'))->view(999),
            $this->controller($factory->createServerRequest('PUT', '/v2/Users/999'))->replace(999),
            $this->controller($factory->createServerRequest('DELETE', '/v2/Users/999'))->delete(999),
        ] as $notFound) {
            self::assertSame(404, $notFound->getStatusCode());
            self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $this->data($notFound)['schemas']);
            self::assertSame('Resource not found', $this->data($notFound)['detail']);
            self::assertSame('404', $this->data($notFound)['status']);
        }
        $created = $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody([
            'userName' => 'alice',
            'emails' => [['value' => 'alice@example.com']],
            'password' => 'Password123!',
        ]))->create();
        self::assertSame(201, $created->getStatusCode());
        $createdData = $this->data($created);
        $id = (int) $createdData['id'];
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:User'], $createdData['schemas']);
        self::assertSame('alice', $createdData['userName']);
        self::assertTrue($createdData['active']);
        self::assertSame([['value' => 'alice@example.com', 'primary' => true]], $createdData['emails']);
        self::assertSame('User', $createdData['meta']['resourceType']);
        self::assertNotSame('', $createdData['meta']['created']);
        self::assertSame('/v2/Users/' . $createdData['id'], $createdData['meta']['location']);
        self::assertSame('/v2/Users/' . $createdData['id'], $created->getHeaderLine('Location'));
        self::assertSame(201, $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody([
            'userName' => 'zed',
            'emails' => [['value' => 'aaa@example.com']],
        ]))->create()->getStatusCode());
        $connection = ConnectionProvider::get();
        for ($i = 1; $i <= 26; $i++) {
            $connection->createCommand()->insert('user', [
                'username' => 'user-' . $i,
                'email' => 'user-' . $i . '@example.com',
                'password_hash' => 'hash',
                'auth_key' => 'key-' . $i,
                'created_at' => 1000 + $i,
                'updated_at' => 1000 + $i,
            ])->execute();
        }

        $searchRequest = $factory->createServerRequest('POST', '/v2/Users/.search')->withParsedBody([
            'schemas' => [42, 'urn:ietf:params:scim:api:messages:2.0:SearchRequest'],
        ]);
        self::assertSame(200, $this->controller($searchRequest)->search()->getStatusCode());

        $view = $this->controller($factory->createServerRequest('GET', '/v2/Users/' . $id))->view($id);
        self::assertSame(200, $view->getStatusCode());
        self::assertSame($createdData['userName'], $this->data($view)['userName']);
        $etag = $view->getHeaderLine('ETag');
        self::assertSame(304, $this->controller($factory->createServerRequest('GET', '/v2/Users/' . $id)->withHeader('If-None-Match', $etag))->view($id)->getStatusCode());
        $sameActiveDispatcher = $this->createMock(EventDispatcherInterface::class);
        $sameActiveDispatcher->expects(self::never())->method('dispatch');
        $sameActive = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $etag)->withParsedBody(['active' => true]), $sameActiveDispatcher)->replace($id);
        self::assertSame(200, $sameActive->getStatusCode());
        self::assertSame($etag, $sameActive->getHeaderLine('ETag'));
        foreach ([
            'userName eq "alice"' => 1,
            'userName co "lic"' => 1,
            'userName sw "ali"' => 1,
            'emails.value eq "alice@example.com"' => 1,
            'emails.value co "alice@"' => 1,
            'emails.value sw "alice"' => 1,
        ] as $filter => $expected) {
            $filtered = $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => $filter]))->index();
            self::assertSame(200, $filtered->getStatusCode());
            self::assertSame($expected, $this->data($filtered)['totalResults'], $filter);
        }
        foreach (['userName' => 'zed', 'emails.value' => 'user-9', 'meta.created' => 'alice', 'unknown' => 'zed'] as $sortBy => $expectedFirst) {
            $sorted = $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['sortBy' => $sortBy, 'sortOrder' => 'descending', 'count' => 10]))->index();
            self::assertSame(200, $sorted->getStatusCode());
            self::assertSame(28, $this->data($sorted)['totalResults']);
            self::assertSame($expectedFirst, $this->data($sorted)['Resources'][0]['userName'], $sortBy);
        }
        $upperSort = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['sortBy' => 'USERNAME', 'sortOrder' => 'DESCENDING', 'count' => 10]))->index());
        self::assertSame('zed', $upperSort['Resources'][0]['userName']);
        $upperEmailSort = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['sortBy' => 'EMAILS.VALUE', 'sortOrder' => 'DESCENDING', 'count' => 10]))->index());
        self::assertSame('user-9', $upperEmailSort['Resources'][0]['userName']);
        $singlePage = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => 2, 'count' => 1]))->index());
        self::assertSame('user-1', $singlePage['Resources'][0]['userName']);
        $stringStart = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => '2', 'count' => 1]))->index());
        self::assertSame(2, $stringStart['startIndex']);
        $startZero = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => 0, 'count' => 1]))->index());
        self::assertSame(1, $startZero['startIndex']);
        self::assertSame('alice', $startZero['Resources'][0]['userName']);
        $zeroCount = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['count' => 0]))->index());
        self::assertSame(0, $zeroCount['itemsPerPage']);
        $negativeCount = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['count' => -1]))->index());
        self::assertSame(0, $negativeCount['itemsPerPage']);
        $twentyFive = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['count' => 25]))->index());
        self::assertSame(25, $twentyFive['itemsPerPage']);
        $defaultCount = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users'))->index());
        self::assertSame(25, $defaultCount['itemsPerPage']);
        $middlePage = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => 3, 'count' => 2]))->index());
        self::assertSame('user-10', $middlePage['Resources'][0]['userName']);
        $roundedPage = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => 4, 'count' => 3]))->index());
        self::assertSame('user-11', $roundedPage['Resources'][0]['userName']);
        $roundedPage = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['startIndex' => 4, 'count' => 3]))->index());
        self::assertSame('user-11', $roundedPage['Resources'][0]['userName']);
        $collection = $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['count' => 100]))->index();
        $collectionData = $this->data($collection);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:ListResponse'], $collectionData['schemas']);
        self::assertSame(28, $collectionData['totalResults']);
        self::assertSame(1, $collectionData['startIndex']);
        self::assertSame(28, $collectionData['itemsPerPage']);
        self::assertSame(['alice', 'user-1', 'user-10'], array_slice(array_column($collectionData['Resources'], 'userName'), 0, 3));
        self::assertSame([['value' => 'alice@example.com', 'primary' => true]], $collectionData['Resources'][0]['emails']);
        self::assertSame(304, $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['count' => 100])->withHeader('If-None-Match', $collection->getHeaderLine('ETag')))->index()->getStatusCode());
        $selected = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['attributes' => ' userName, ,active ']))->index());
        self::assertSame(['schemas', 'id', 'meta', 'userName', 'active'], array_keys($selected['Resources'][0]));
        $excluded = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['excludedAttributes' => 'emails']))->index());
        self::assertArrayNotHasKey('emails', $excluded['Resources'][0]);
        $excludedUpper = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['excludedAttributes' => ' EMAILS ']))->index());
        self::assertArrayNotHasKey('emails', $excludedUpper['Resources'][0]);
        $excludedUsername = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['excludedAttributes' => ' USERNAME ']))->index());
        self::assertArrayNotHasKey('userName', $excludedUsername['Resources'][0]);
        $emptyAttributes = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['attributes' => ',']))->index());
        self::assertSame('alice', $emptyAttributes['Resources'][0]['userName']);
        $invalidFilter = $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => 'userName ne "alice"']))->index();
        self::assertSame(400, $invalidFilter->getStatusCode());
        self::assertSame('invalidFilter', $this->data($invalidFilter)['scimType']);
        $caseInsensitive = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => 'USERNAME EQ "alice"']))->index());
        self::assertSame(1, $caseInsensitive['totalResults']);
        $exactFilter = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => 'userName EQ "lic"']))->index());
        self::assertSame(0, $exactFilter['totalResults']);
        $containsFilter = $this->data($this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => 'userName CO "lic"']))->index());
        self::assertSame(1, $containsFilter['totalResults']);
        $trailingFilter = $this->controller($factory->createServerRequest('GET', '/v2/Users')->withQueryParams(['filter' => 'userName eq "alice" trailing']))->index();
        self::assertSame(400, $trailingFilter->getStatusCode());

        $ordinaryUpdateDispatcher = $this->createMock(EventDispatcherInterface::class);
        $ordinaryUpdateDispatcher->expects(self::exactly(2))->method('dispatch')->with(self::callback(static fn(mixed $event): bool => method_exists($event, 'getChangedFields') && !in_array('active', $event->getChangedFields(), true)));
        $updated = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $etag)->withParsedBody([
            'userName' => 'alice-updated',
            'emails' => [['value' => 'alice-updated@example.com']],
        ]), $ordinaryUpdateDispatcher)->replace($id);
        self::assertSame(200, $updated->getStatusCode());
        $patched = $this->controller($factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $updated->getHeaderLine('ETag'))->withParsedBody([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
        ]))->patch($id);
        self::assertSame(200, $patched->getStatusCode());
        self::assertFalse($this->data($patched)['active']);
        self::assertSame(412, $this->controller($factory->createServerRequest('DELETE', '/v2/Users/' . $id)->withHeader('If-Match', '"stale"'))->delete($id)->getStatusCode());
        $deleteDispatcher = $this->createMock(EventDispatcherInterface::class);
        $deleteDispatcher->expects(self::once())->method('dispatch')->with(self::isInstanceOf(UserEvent::class));
        self::assertSame(204, $this->controller($factory->createServerRequest('DELETE', '/v2/Users/' . $id)->withHeader('If-Match', $patched->getHeaderLine('ETag')), null, $deleteDispatcher)->delete($id)->getStatusCode());
        self::assertSame(404, $this->controller($factory->createServerRequest('GET', '/v2/Users/' . $id))->view($id)->getStatusCode());
        self::assertSame(201, $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody(['userName' => 'duplicate', 'emails' => [['value' => 'duplicate@example.com']]]))->create()->getStatusCode());
        $search = $this->controller($factory->createServerRequest('POST', '/v2/Users/.search')->withParsedBody([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:SearchRequest'],
            'filter' => 'userName eq "duplicate"',
        ]))->search();
        self::assertSame(200, $search->getStatusCode());
        self::assertSame(1, $this->data($search)['totalResults']);
        $duplicate = $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody(['userName' => 'duplicate', 'emails' => [['value' => 'other@example.com']]]))->create();
        self::assertSame(409, $duplicate->getStatusCode());
        self::assertSame('', $this->data($duplicate)['detail']);
    }

    public function testUserValidationAndPatchBranches(): void
    {
        $factory = new Psr17Factory();
        $create = fn(array $body) => $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody($body))->create();
        self::assertSame(400, $create(['userName' => 'missing-email'])->getStatusCode());
        self::assertSame(400, $create(['userName' => 'bad-email', 'emails' => 'invalid'])->getStatusCode());
        self::assertSame(400, $create(['userName' => 'bad-email', 'emails' => [[]]])->getStatusCode());
        self::assertSame(400, $create(['userName' => 'bad-email', 'emails' => [['value' => []]]])->getStatusCode());
        self::assertSame(201, $create(['userName' => 'generated-user', 'emails' => [['value' => 'generated@example.com']]])->getStatusCode());
        $generator = $this->createMock(PasswordGeneratorInterface::class);
        $generator->expects(self::once())->method('generate')->with(20)->willReturn('GeneratedPassword123!');
        $generatedWithContract = $this->controller($factory->createServerRequest('POST', '/v2/Users')->withParsedBody(['userName' => 'generated-contract', 'emails' => [['value' => 'generated-contract@example.com']]]), null, null, $generator)->create();
        self::assertSame(201, $generatedWithContract->getStatusCode());
        $numericUsername = $create(['userName' => 987654, 'emails' => [['value' => 'numeric@example.com']]]);
        self::assertSame(201, $numericUsername->getStatusCode());
        self::assertSame('987654', $this->data($numericUsername)['userName']);
        $created = $create(['userName' => 'branch-user', 'emails' => [['value' => 'branch@example.com']], 'password' => 'Password123!']);
        self::assertSame(201, $created->getStatusCode());
        $id = (int) $this->data($created)['id'];
        $etag = $created->getHeaderLine('ETag');
        $request = $factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $etag);
        $missingEmail = $this->controller($request->withParsedBody(['emails' => []]))->replace($id);
        self::assertSame(400, $missingEmail->getStatusCode());
        self::assertSame('emails[0].value is required', $this->data($missingEmail)['detail']);
        $reusedPassword = $this->controller($request->withParsedBody(['password' => 'Password123!']))->replace($id);
        self::assertSame(400, $reusedPassword->getStatusCode());
        self::assertSame('Password has been used recently', $this->data($reusedPassword)['detail']);
        $changed = $this->controller($request->withParsedBody(['active' => false, 'userName' => 'branch-user-renamed', 'emails' => [['value' => 'branch2@example.com']]]))->replace($id);
        self::assertSame(200, $changed->getStatusCode());
        $reactivateDispatcher = $this->createMock(EventDispatcherInterface::class);
        $reactivateDispatcher->expects(self::exactly(2))->method('dispatch')->with(self::callback(static fn(mixed $event): bool => method_exists($event, 'getChangedFields') && in_array('active', $event->getChangedFields(), true)));
        $reactivated = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody(['active' => true]), $reactivateDispatcher)->replace($id);
        self::assertTrue($this->data($reactivated)['active']);
        $changed = $reactivated;
        $deactivateDispatcher = $this->createMock(EventDispatcherInterface::class);
        $deactivateDispatcher->expects(self::exactly(2))->method('dispatch')->with(self::callback(static fn(mixed $event): bool => method_exists($event, 'getChangedFields') && in_array('active', $event->getChangedFields(), true)));
        $deactivated = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody(['active' => false]), $deactivateDispatcher)->replace($id);
        self::assertFalse($this->data($deactivated)['active']);
        $changed = $deactivated;
        $passwordCoerced = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody(['password' => 123]))->replace($id);
        self::assertSame(200, $passwordCoerced->getStatusCode());
        $changed = $passwordCoerced;
        $patchedFinal = $this->controller($factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'path' => 'username', 'value' => 'branch-user-final'],
                ['op' => 'replace', 'path' => 'emails', 'value' => [['value' => 'branch3@example.com']]],
                ['op' => 'remove', 'path' => 'active'],
            ],
        ]))->patch($id);
        self::assertSame(200, $patchedFinal->getStatusCode());
        self::assertSame('branch-user-final', $this->data($patchedFinal)['userName']);
        self::assertSame([['value' => 'branch3@example.com', 'primary' => true]], $this->data($patchedFinal)['emails']);
        self::assertTrue($this->data($patchedFinal)['active']);
        $patchedFinal = $this->controller($factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $patchedFinal->getHeaderLine('ETag'))->withParsedBody([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'REPLACE', 'path' => 'ACTIVE', 'value' => 0],
                ['op' => 'REPLACE', 'path' => 'USERNAME', 'value' => 123],
            ],
        ]))->patch($id);
        self::assertSame(200, $patchedFinal->getStatusCode());
        self::assertSame('123', $this->data($patchedFinal)['userName']);
        self::assertFalse($this->data($patchedFinal)['active']);
        self::assertSame(400, $this->controller($factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody(['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations' => [['op' => 'replace', 'path' => 'unknown', 'value' => true]]]))->patch($id)->getStatusCode());
        self::assertSame(400, $this->controller($factory->createServerRequest('PATCH', '/v2/Users/' . $id)->withHeader('If-Match', $changed->getHeaderLine('ETag'))->withParsedBody(['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations' => [['op' => 'replace', 'path' => 'username', 'value' => ['invalid']]]]))->patch($id)->getStatusCode());
        $dispatcher = $this->createStub(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')->willThrowException(new ActionPreventedException('Update blocked'));
        $blocked = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $patchedFinal->getHeaderLine('ETag'))->withParsedBody(['userName' => 'blocked', 'emails' => [['value' => 'branch4@example.com']]]), $dispatcher)->replace($id);
        self::assertSame(400, $blocked->getStatusCode());
        self::assertSame('Update blocked', $this->data($blocked)['detail']);
        $runtimeDispatcher = $this->createStub(EventDispatcherInterface::class);
        $runtimeDispatcher->method('dispatch')->willThrowException(new RuntimeException('Update failed'));
        $runtimeError = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $patchedFinal->getHeaderLine('ETag'))->withParsedBody(['userName' => 'runtime', 'emails' => [['value' => 'runtime@example.com']]]), $runtimeDispatcher)->replace($id);
        self::assertSame(400, $runtimeError->getStatusCode());
        self::assertSame('Update failed', $this->data($runtimeError)['detail']);
        $stale = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', '"stale"')->withParsedBody(['userName' => 'stale', 'emails' => [['value' => 'stale@example.com']]]))->replace($id);
        self::assertSame(412, $stale->getStatusCode());
        self::assertSame('invalidVers', $this->data($stale)['scimType']);
        $passwordChanged = $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $patchedFinal->getHeaderLine('ETag'))->withParsedBody(['password' => 'AnotherPassword123!']))->replace($id);
        self::assertSame(200, $passwordChanged->getStatusCode());
        self::assertSame(200, $this->controller($factory->createServerRequest('PUT', '/v2/Users/' . $id)->withHeader('If-Match', $passwordChanged->getHeaderLine('ETag'))->withParsedBody(['active' => true]))->replace($id)->getStatusCode());
    }

    private function controller($request, ?EventDispatcherInterface $updateDispatcher = null, ?EventDispatcherInterface $eventDispatcher = null, ?PasswordGeneratorInterface $passwordGenerator = null): ScimController
    {
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn($request);
        $config = $this->config();
        $history = new PasswordHistoryService(new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]), $config);
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('withDefaultCategory')->willReturnSelf();
        return new ScimController(
            new DataResponseFactory(new Psr17Factory()),
            $requests,
            $passwordGenerator ?? new RandomPasswordGenerator(),
            $history,
            new UserCreationHelper(
                new MailService($this->createStub(MailerInterface::class), '/tmp', new View(), $translator, $this->createStub(UrlGeneratorInterface::class)),
                $this->createStub(EventDispatcherInterface::class),
                new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]),
                $config,
                $history,
                $translator,
            ),
            new UserUpdateHelper(new SystemClock(), $updateDispatcher ?? $this->createStub(EventDispatcherInterface::class), $history),
            $eventDispatcher ?? $this->createStub(EventDispatcherInterface::class),
        );
    }

    /** @return array<string, mixed> */
    private function data($response): array
    {
        $body = $response->getBody();
        self::assertInstanceOf(DataStream::class, $body);
        $data = $body->getData();
        self::assertIsArray($data);
        return $data;
    }

    private function config(): VoytiConfig
    {
        $params = require InstalledVersions::getInstallPath('yiirocks/voyti') . '/config/params.php';
        $params['yiirocks/voyti']['maxPasswordAge'] = 1;
        return new VoytiConfig(...$params['yiirocks/voyti']);
    }
}
