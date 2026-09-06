<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Controller\V2;

use Nyholm\Psr7\Factory\Psr17Factory;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactory;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Role;
use Yiisoft\RequestProvider\RequestProviderInterface;
use YiiRocks\Voyti\Api\Scim\Controller\V2\GroupController;
use YiiRocks\Voyti\Api\Scim\tests\Support\DatabaseTestCase;
use Yiisoft\DataResponse\DataStream\DataStream;

final class GroupDatabaseTest extends DatabaseTestCase
{
    public function testMembersAreValidatedRenderedAndSynchronized(): void
    {
        $connection = ConnectionProvider::get();
        foreach ([['one', 'one@example.com'], ['two', 'two@example.com']] as [$username, $email]) {
            $connection->createCommand()->insert('user', [
                'username' => $username,
                'email' => $email,
                'password_hash' => 'hash',
                'auth_key' => 'key',
                'created_at' => 1000,
                'updated_at' => 1000,
            ])->execute();
        }

        $admins = new Role('admins');
        $operators = new Role('operators');
        $items = $this->createStub(ItemsStorageInterface::class);
        $items->method('getRoles')->willReturn([$admins, $operators]);
        $items->method('getRole')->willReturnCallback(static fn(string $name): ?Role => ['admins' => $admins, 'operators' => $operators][$name] ?? null);
        $items->method('exists')->willReturn(false);
        $assignments = $this->createMock(AssignmentsStorageInterface::class);
        $assignments->expects(self::atLeastOnce())->method('getByItemNames')->with(self::callback(static fn(array $names): bool => $names !== []))->willReturn([new Assignment('1', 'admins', 1000)]);
        $assignments->expects(self::exactly(2))->method('remove')->with(self::logicalOr(self::equalTo('admins'), self::equalTo('operators')), '1');
        $assignments->expects(self::once())->method('renameItem')->with('admins', 'operators');
        $manager = $this->createMock(ManagerInterface::class);
        $manager->expects(self::once())->method('addRole');
        $manager->expects(self::once())->method('updateRole');
        $manager->expects(self::exactly(2))->method('assign')->with(self::logicalOr(self::equalTo('admins'), self::equalTo('operators')), '2');
        $controller = $this->controller($items, $assignments, $manager);

        $view = $controller->view('admins');
        self::assertSame(200, $view->getStatusCode());
        $body = $view->getBody();
        self::assertInstanceOf(DataStream::class, $body);
        $data = $body->getData();
        self::assertSame('one', $data['members'][0]['display']);
        self::assertSame('1', $data['members'][0]['value']);
        self::assertSame('/v2/Users/1', $data['members'][0]['$ref']);
        self::assertSame('User', $data['members'][0]['type']);
        self::assertSame('Group', $data['meta']['resourceType']);
        self::assertSame(201, $controller->createResource(['displayName' => 'admins', 'members' => [['value' => '2']]])->getStatusCode());
        self::assertSame(200, $controller->replaceResource('admins', ['displayName' => 'operators', 'members' => [['value' => '2']]])->getStatusCode());
        $replaceError = $controller->replaceResource('admins', ['members' => [['value' => '999'], ['value' => '998']]]);
        self::assertSame(400, $replaceError->getStatusCode());
        self::assertSame('One or more group members do not exist: 999, 998', $this->data($replaceError)['detail']);
        $createError = $controller->createResource(['displayName' => 'new', 'members' => [['value' => '999']]]);
        self::assertSame(400, $createError->getStatusCode());
        self::assertSame('One or more group members do not exist: 999', $this->data($createError)['detail']);
    }

    private function controller(
        ItemsStorageInterface $items,
        AssignmentsStorageInterface $assignments,
        ManagerInterface $manager,
    ): GroupController {
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn((new Psr17Factory())->createServerRequest('GET', '/v2/Groups'));
        return new GroupController($assignments, new DataResponseFactory(new Psr17Factory()), $items, $manager, $requests);
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
