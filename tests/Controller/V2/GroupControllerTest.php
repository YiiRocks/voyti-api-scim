<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Controller\V2;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use ReflectionMethod;
use Yiisoft\DataResponse\ResponseFactory\DataResponseFactory;
use Yiisoft\DataResponse\DataStream\DataStream;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Role;
use Yiisoft\RequestProvider\RequestProviderInterface;
use YiiRocks\Voyti\Api\Scim\Controller\V2\GroupController;
use stdClass;

final class GroupControllerTest extends TestCase
{
    public function testEmptyIndexReturnsCollectionEtag(): void
    {
        $controller = $this->controller([], []);

        $response = $controller->index();

        self::assertSame(200, $response->getStatusCode());
        self::assertNotSame('', $response->getHeaderLine('ETag'));
        self::assertSame('application/scim+json', $response->getHeaderLine('Content-Type'));
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:ListResponse'], $this->data($response)['schemas']);
        self::assertSame(0, $this->data($response)['totalResults']);
        self::assertSame(1, $this->data($response)['startIndex']);
        self::assertSame(0, $this->data($response)['itemsPerPage']);
        self::assertSame([], $this->data($response)['Resources']);
        self::assertSame(304, $this->controller([], [], null, null, null, ['If-None-Match' => $response->getHeaderLine('ETag')])->index()->getStatusCode());
    }

    public function testViewAndMutationsReturnNotFoundErrors(): void
    {
        $controller = $this->controller([], []);

        foreach ([$controller->view('missing'), $controller->replaceResource('missing', []), $controller->patchResource('missing', []), $controller->deleteResource('missing')] as $response) {
            self::assertSame(404, $response->getStatusCode());
            self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $this->data($response)['schemas']);
            self::assertSame('Resource not found', $this->data($response)['detail']);
            self::assertSame('404', $this->data($response)['status']);
        }
    }

    public function testCreateRejectsMissingDisplayName(): void
    {
        $missing = $this->controller([], [])->createResource([]);
        self::assertSame(400, $missing->getStatusCode());
        self::assertSame('displayName is required', $this->data($missing)['detail']);
        $items = $this->createStub(ItemsStorageInterface::class);
        $items->method('exists')->willReturn(true);
        self::assertSame(409, $this->controller([], [], $items)->createResource(['displayName' => 'admins'])->getStatusCode());
        $manager = $this->createStub(ManagerInterface::class);
        $manager->method('addRole')->willThrowException(new InvalidArgumentException('cannot add role'));
        self::assertSame(400, $this->controller([], [], null, null, $manager)->createResource(['displayName' => 'admins'])->getStatusCode());
    }

    public function testCreateReplacePatchViewAndDeleteRole(): void
    {
        $role = (new Role('admins'))->withCreatedAt(1000)->withUpdatedAt(2000);
        $renamed = new Role('operators');
        $manager = $this->createMock(ManagerInterface::class);
        $manager->expects(self::once())->method('addRole');
        $manager->expects(self::exactly(2))->method('updateRole');
        $manager->expects(self::once())->method('removeRole');
        $items = $this->items(['admins' => $role, 'operators' => $renamed]);
        $assignments = $this->createStub(AssignmentsStorageInterface::class);
        $assignments->method('getByItemNames')->willReturn([]);
        $controller = $this->controller(['admins' => $role, 'operators' => $renamed], [], $items, $assignments, $manager);

        $created = $controller->createResource(['displayName' => 'admins']);
        self::assertSame(201, $created->getStatusCode());
        $createdData = $this->data($created);
        self::assertSame('admins', $createdData['id']);
        self::assertSame('admins', $createdData['displayName']);
        self::assertSame([], $createdData['members']);
        self::assertSame('Group', $createdData['meta']['resourceType']);
        self::assertSame(gmdate('c', 1000), $createdData['meta']['created']);
        self::assertSame(gmdate('c', 2000), $createdData['meta']['lastModified']);
        self::assertSame('"' . $createdData['meta']['version'] . '"', $created->getHeaderLine('ETag'));
        self::assertSame('/v2/Groups/admins', $createdData['meta']['location']);
        self::assertSame('/v2/Groups/admins', $created->getHeaderLine('Location'));
        self::assertSame(2, $this->data($controller->index())['itemsPerPage']);
        $pageZero = $this->data($this->controller(['admins' => $role], ['startIndex' => 0, 'count' => 0], $items, $assignments)->index());
        self::assertSame(1, $pageZero['startIndex']);
        self::assertSame(0, $pageZero['itemsPerPage']);
        $negativeCount = $this->data($this->controller(['Admins' => new Role('Admins')], ['count' => -1], $items, $assignments)->index());
        self::assertSame(0, $negativeCount['itemsPerPage']);
        $manyRoles = [];
        for ($i = 1; $i <= 26; $i++) {
            $manyRoles['role-' . $i] = new Role('role-' . $i);
        }
        $many = $this->data($this->controller($manyRoles, ['count' => 25], $this->items($manyRoles), $assignments)->index());
        self::assertSame(25, $many['itemsPerPage']);
        $defaultMany = $this->data($this->controller($manyRoles, [], $this->items($manyRoles), $assignments)->index());
        self::assertSame(1, $defaultMany['startIndex']);
        self::assertSame(25, $defaultMany['itemsPerPage']);
        self::assertSame(200, $controller->replaceResource('admins', ['displayName' => 'operators', 'members' => []])->getStatusCode());
        self::assertSame(200, $controller->patchResource('admins', ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'operators']]])->getStatusCode());
        $view = $controller->view('admins');
        self::assertSame(200, $view->getStatusCode());
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:Group'], $this->data($view)['schemas']);
        self::assertSame(304, $this->controller(['admins' => $role], [], $items, $assignments, $manager, ['If-None-Match' => $controller->view('admins')->getHeaderLine('ETag')])->view('admins')->getStatusCode());
        self::assertSame(204, $controller->deleteResource('admins')->getStatusCode());
        self::assertSame(412, $this->controller(['admins' => $role], [], $items, $assignments, $manager, ['If-Match' => '"stale"'])->deleteResource('admins')->getStatusCode());
    }

    public function testFiltersPaginationAndMemberBranches(): void
    {
        $roles = ['Readers' => new Role('Readers'), 'Admins' => new Role('Admins'), 'Operators' => new Role('Operators')];
        $items = $this->items($roles);
        $assignments = $this->createStub(AssignmentsStorageInterface::class);
        $assignments->method('getByItemNames')->willReturn([]);
        $eq = $this->data($this->controller($roles, ['filter' => 'displayName eq "admins"'], $items, $assignments)->index());
        self::assertSame(1, $eq['totalResults']);
        self::assertSame('Admins', $eq['Resources'][0]['displayName']);
        $upperEq = $this->data($this->controller($roles, ['filter' => 'DISPLAYNAME EQ "ADMINS"'], $items, $assignments)->index());
        self::assertSame(['Admins'], array_column($upperEq['Resources'], 'displayName'));
        $contains = $this->data($this->controller($roles, ['filter' => 'displayName co "per"'], $items, $assignments)->index());
        self::assertSame(1, $contains['totalResults']);
        self::assertSame('Operators', $contains['Resources'][0]['displayName']);
        $starts = $this->data($this->controller($roles, ['filter' => 'displayName sw "adm"', 'sortOrder' => 'descending', 'startIndex' => 1, 'count' => 1], $items, $assignments)->index());
        self::assertSame(1, $starts['totalResults']);
        self::assertSame('Admins', $starts['Resources'][0]['displayName']);
        $upper = $this->data($this->controller($roles, ['filter' => 'DISPLAYNAME CO "ER"'], $items, $assignments)->index());
        self::assertSame(['Operators', 'Readers'], array_column($upper['Resources'], 'displayName'));
        $invalid = $this->controller($roles, ['filter' => 'displayName eq "Admins" trailing'], $items, $assignments)->index();
        self::assertSame(400, $invalid->getStatusCode());
        self::assertSame('invalidFilter', $this->data($invalid)['scimType']);
        $ascending = $this->data($this->controller($roles, [], $items, $assignments)->index());
        self::assertSame(['Admins', 'Operators', 'Readers'], array_column($ascending['Resources'], 'displayName'));
        $descending = $this->data($this->controller($roles, ['sortOrder' => 'descending'], $items, $assignments)->index());
        self::assertSame(['Readers', 'Operators', 'Admins'], array_column($descending['Resources'], 'displayName'));
        $sortBy = $this->data($this->controller($roles, ['sortBy' => 'DISPLAYNAME'], $items, $assignments)->index());
        self::assertSame(['Admins', 'Operators', 'Readers'], array_column($sortBy['Resources'], 'displayName'));
        $unsupportedSort = $this->controller($roles, ['sortBy' => 'members'], $items, $assignments)->index();
        self::assertSame(400, $unsupportedSort->getStatusCode());
        self::assertSame('invalidValue', $this->data($unsupportedSort)['scimType']);
        $selected = $this->data($this->controller($roles, ['attributes' => 'displayName'], $items, $assignments)->index());
        self::assertSame(['schemas', 'id', 'meta', 'displayName'], array_keys($selected['Resources'][0]));
        $excluded = $this->data($this->controller($roles, ['excludedAttributes' => 'members'], $items, $assignments)->index());
        self::assertArrayNotHasKey('members', $excluded['Resources'][0]);
        $selectedWithWhitespace = $this->data($this->controller($roles, ['attributes' => ' displayName, '], $items, $assignments)->index());
        self::assertSame(['schemas', 'id', 'meta', 'displayName'], array_keys($selectedWithWhitespace['Resources'][0]));
        $excludedWithWhitespace = $this->data($this->controller($roles, ['excludedAttributes' => ' members, '], $items, $assignments)->index());
        self::assertArrayNotHasKey('members', $excludedWithWhitespace['Resources'][0]);
        $excludedUppercase = $this->data($this->controller($roles, ['excludedAttributes' => ' MEMBERS, '], $items, $assignments)->index());
        self::assertArrayNotHasKey('members', $excludedUppercase['Resources'][0]);
        $excludedCamelCase = $this->data($this->controller($roles, ['excludedAttributes' => ' DISPLAYNAME, '], $items, $assignments)->index());
        self::assertArrayNotHasKey('displayName', $excludedCamelCase['Resources'][0]);
        $attributeList = new ReflectionMethod(GroupController::class, 'attributeList');
        self::assertSame(['displayname', 'id'], $attributeList->invoke($this->controller([], []), ' DisplayName, , ID '));
        $queryParams = new ReflectionMethod(GroupController::class, 'queryParams');
        self::assertSame(['sortOrder' => 'descending', 'count' => 1], $queryParams->invoke($this->controller([], ['sortOrder' => 'descending', 'count' => 1])));
        $viewSelected = $this->data($this->controller($roles, ['attributes' => 'displayName'], $items, $assignments)->view('Admins'));
        self::assertSame(['schemas', 'id', 'meta', 'displayName'], array_keys($viewSelected));
        $page = $this->data($this->controller($roles, ['startIndex' => 2, 'count' => 1], $items, $assignments)->index());
        self::assertSame(2, $page['startIndex']);
        self::assertSame(1, $page['itemsPerPage']);
        self::assertSame(['Operators'], array_column($page['Resources'], 'displayName'));
        $multiQuery = $this->data($this->controller($roles, ['sortOrder' => 'descending', 'count' => 1], $items, $assignments)->index());
        self::assertSame(1, $multiQuery['itemsPerPage']);
        self::assertSame('Readers', $multiQuery['Resources'][0]['displayName']);
        self::assertSame(201, $this->controller([], [], $items, $assignments)->createResource(['displayName' => 'new-role', 'members' => 'invalid'])->getStatusCode());
        self::assertSame(400, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'invalid', 'value' => true]]])->getStatusCode());
        self::assertSame(200, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'remove', 'path' => 'members']]])->getStatusCode());
        self::assertSame(200, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'members', 'value' => []]]])->getStatusCode());
        self::assertSame(200, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'value' => ['displayName' => 'Admins', 'members' => []]]]])->getStatusCode());
        self::assertSame(200, $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'REPLACE', 'path' => 'displayName', 'value' => 'Admins']]])->getStatusCode());
        $trimmed = $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->replaceResource('Admins', ['displayName' => ' Admins ']);
        self::assertSame('Admins', $this->data($trimmed)['id']);
        $trimmedCreate = $this->controller(['new-role' => new Role('new-role')], [], null, $assignments)->createResource(['displayName' => ' new-role ']);
        self::assertSame('new-role', $this->data($trimmedCreate)['id']);
        $displayNamePatch = $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Admins']]]);
        self::assertSame('Admins', $this->data($displayNamePatch)['displayName']);
        $trimmedDisplayNamePatch = $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => ' Admins ']]]);
        self::assertSame('Admins', $this->data($trimmedDisplayNamePatch)['displayName']);
        self::assertSame(400, $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'members', 'value' => 'invalid']]])->getStatusCode());
        $rootPatch = $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => '', 'value' => ['displayName' => ' Admins ', 'members' => []]]]]);
        self::assertSame(200, $rootPatch->getStatusCode());
        self::assertSame('Admins', $this->data($rootPatch)['displayName']);
        self::assertSame(400, $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => '', 'value' => 'invalid']]])->getStatusCode());
        self::assertSame(200, $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => '', 'value' => ['unrelated' => true]]]])->getStatusCode());
        self::assertSame(201, $this->controller(['Admins' => new Role('Admins')], [], $items, $assignments)->createResource(['displayName' => 'Admins', 'members' => ['invalid']])->getStatusCode());
        self::assertSame(200, $this->controller([], [], $items, $assignments)->patchResource('Admins', [])->getStatusCode());
        self::assertSame(400, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [true]])->getStatusCode());
        self::assertSame(400, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'invalid']]])->getStatusCode());
        $conflictItems = $this->createStub(ItemsStorageInterface::class);
        $conflictItems->method('getRole')->willReturn(new Role('Admins'));
        $conflictItems->method('exists')->willReturn(true);
        self::assertSame(409, $this->controller([], [], $conflictItems, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Operators']]])->getStatusCode());
        self::assertSame(400, $this->controller([], [], $items, $assignments)->patchResource('Admins', ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => '']]])->getStatusCode());
        self::assertSame(412, $this->controller([], [], $items, $assignments, null, ['If-Match' => '"stale"'])->replaceResource('Admins', [])->getStatusCode());
        $changingItems = $this->createMock(ItemsStorageInterface::class);
        $changingItems->expects(self::exactly(2))->method('getRole')->willReturnOnConsecutiveCalls(new Role('Admins'), null);
        self::assertSame(404, $this->controller([], [], $changingItems, $assignments)->replaceResource('Admins', [])->getStatusCode());
    }

    public function testRouteWrapperMethodsReadRequestBodies(): void
    {
        $role = new Role('admins');
        $items = $this->items(['admins' => $role]);
        $assignments = $this->createStub(AssignmentsStorageInterface::class);
        $assignments->method('getByItemNames')->willReturn([]);
        self::assertSame(201, $this->controller([], [], $items, $assignments, null, [], ['displayName' => 'admins'])->create()->getStatusCode());
        self::assertSame(400, $this->controller([], [], $items, $assignments, null, [], [])->search()->getStatusCode());
        self::assertSame(200, $this->controller(['admins' => $role], [], $items, $assignments, null, [], ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:SearchRequest']])->search()->getStatusCode());
        self::assertSame(200, $this->controller(['admins' => $role], [], $items, $assignments, null, [], ['displayName' => 'admins'])->replace('admins')->getStatusCode());
        self::assertSame(200, $this->controller(['admins' => $role], [], $items, $assignments, null, [], ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'admins']]])->patch('admins')->getStatusCode());
        self::assertSame(400, $this->controller(['admins' => $role], [], $items, $assignments, null, [], [])->patch('admins')->getStatusCode());
        self::assertSame(204, $this->controller(['admins' => $role], [], $items, $assignments, null, [], [])->delete('admins')->getStatusCode());
        $invalidBody = new stdClass();
        $invalidBody->displayName = 'admins';
        self::assertSame(400, $this->controller([], [], $items, $assignments, null, [], $invalidBody)->create()->getStatusCode());
        self::assertSame(201, $this->controller([], [], $items, $assignments, null, [], ['members' => 'invalid', 'displayName' => 'admins'])->create()->getStatusCode());
    }

    public function testMutationGuardsAndMemberNormalization(): void
    {
        $items = $this->items(['Admins' => new Role('Admins'), 'Operators' => new Role('Operators')]);
        $assignments = $this->createStub(AssignmentsStorageInterface::class);
        $assignments->method('getByItemNames')->willReturn([]);
        $manager = $this->createMock(ManagerInterface::class);
        $manager->expects(self::once())->method('addRole');
        self::assertSame(201, $this->controller([], [], $items, $assignments, $manager)->createResource([
            'displayName' => 'Admins',
        ])->getStatusCode());

        $missingItems = $this->createMock(ItemsStorageInterface::class);
        $missingItems->expects(self::once())->method('getRole')->with('missing')->willReturn(null);
        $missingManager = $this->createMock(ManagerInterface::class);
        $missingManager->expects(self::never())->method('updateRole');
        self::assertSame(404, $this->controller([], [], $missingItems, null, $missingManager)->replaceResource('missing', [])->getStatusCode());
        $missingPatchItems = $this->createMock(ItemsStorageInterface::class);
        $missingPatchItems->expects(self::once())->method('getRole')->with('missing')->willReturn(null);
        self::assertSame(404, $this->controller([], [], $missingPatchItems, null, $missingManager)->patchResource('missing', [])->getStatusCode());

        $invalidManager = $this->createMock(ManagerInterface::class);
        $invalidManager->expects(self::never())->method('updateRole');
        $invalidPatch = $this->controller(['Admins' => new Role('Admins')], [], $items, $this->createStub(AssignmentsStorageInterface::class), $invalidManager);
        $invalidResponse = $invalidPatch->patchResource('Admins', ['Operations' => [true, ['op' => 'replace', 'path' => 'displayName', 'value' => 'ignored']]]);
        self::assertSame(400, $invalidResponse->getStatusCode());
        self::assertSame('Invalid PATCH operation', $this->data($invalidResponse)['detail']);

        $rootAssignments = $this->createMock(AssignmentsStorageInterface::class);
        $rootAssignments->expects(self::exactly(3))->method('getByItemNames')->with(self::callback(static fn(array $names): bool => $names !== []))->willReturn([]);
        $rootManager = $this->createMock(ManagerInterface::class);
        $rootManager->expects(self::once())->method('updateRole');
        $root = $this->controller(['Admins' => new Role('Admins')], [], $items, $rootAssignments, $rootManager)->patchResource('Admins', [
            'Operations' => [['op' => 'replace', 'path' => '', 'value' => ['displayName' => ' Operators ', 'members' => []]]],
        ]);
        self::assertSame(200, $root->getStatusCode());
        self::assertSame('Operators', $this->data($root)['displayName']);
        $nonArrayRoot = $this->controller(['Admins' => new Role('Admins'), 'Operators' => new Role('Operators')], [], $items, $this->createStub(AssignmentsStorageInterface::class), $this->createStub(ManagerInterface::class))->patchResource('Admins', [
            'Operations' => [['op' => 'replace', 'path' => '', 'value' => ['displayName' => ' Operators ', 'members' => 'invalid']]],
        ]);
        self::assertSame(200, $nonArrayRoot->getStatusCode());
    }

    /** @param array<string, Role> $roles */
    private function controller(
        array $roles,
        array $query,
        ?ItemsStorageInterface $items = null,
        ?AssignmentsStorageInterface $assignments = null,
        ?ManagerInterface $manager = null,
        array $headers = [],
        mixed $body = [],
    ): GroupController {
        $request = (new Psr17Factory())->createServerRequest('GET', '/v2/Groups')->withQueryParams($query)->withParsedBody($body);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        $requests = $this->createStub(RequestProviderInterface::class);
        $requests->method('get')->willReturn($request);
        return new GroupController(
            $assignments ?? $this->createStub(AssignmentsStorageInterface::class),
            new DataResponseFactory(new Psr17Factory()),
            $items ?? $this->items($roles),
            $manager ?? $this->createStub(ManagerInterface::class),
            $requests,
        );
    }

    /** @param array<string, Role> $roles */
    private function items(array $roles): ItemsStorageInterface
    {
        $items = $this->createStub(ItemsStorageInterface::class);
        $items->method('getRoles')->willReturn(array_values($roles));
        $items->method('getRole')->willReturnCallback(static fn(string $name): ?Role => $roles[$name] ?? null);
        $items->method('exists')->willReturn(false);
        return $items;
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
