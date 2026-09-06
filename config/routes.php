<?php

declare(strict_types=1);

use YiiRocks\Voyti\Api\Scim\Controller\V2\ScimController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\GroupController;
use YiiRocks\Voyti\Api\Scim\Controller\V2\BulkController;
use Yiisoft\Router\Group;
use Yiisoft\Router\Route;

return [
    Group::create('v2/')
        ->namePrefix('voyti/api-scim-v2-')
        ->routes(
            Route::get('ServiceProviderConfig')->name('service-provider-config')->action([ScimController::class, 'serviceProviderConfig']),
            Route::get('ResourceTypes')->name('resource-types')->action([ScimController::class, 'resourceTypes']),
            Route::get('Schemas')->name('schemas')->action([ScimController::class, 'schemas']),
            Route::get('Schemas/{schema}')->name('schema')->action([ScimController::class, 'schema']),
            Route::post('Bulk')->name('bulk')->action([BulkController::class, 'process']),
            Group::create('Users')
                ->namePrefix('users-')
                ->routes(
                    Route::get('')->name('index')->action([ScimController::class, 'index']),
                    Route::post('')->name('create')->action([ScimController::class, 'create']),
                    Route::post('/.search')->name('search')->action([ScimController::class, 'search']),
                    Route::get('/{id:\\d+}')->name('view')->action([ScimController::class, 'view']),
                    Route::put('/{id:\\d+}')->name('replace')->action([ScimController::class, 'replace']),
                    Route::patch('/{id:\\d+}')->name('patch')->action([ScimController::class, 'patch']),
                    Route::delete('/{id:\\d+}')->name('delete')->action([ScimController::class, 'delete']),
                ),
            Group::create('Groups')
                ->namePrefix('groups-')
                ->routes(
                    Route::get('')->name('index')->action([GroupController::class, 'index']),
                    Route::post('')->name('create')->action([GroupController::class, 'create']),
                    Route::post('/.search')->name('search')->action([GroupController::class, 'search']),
                    Route::get('/{id}')->name('view')->action([GroupController::class, 'view']),
                    Route::put('/{id}')->name('replace')->action([GroupController::class, 'replace']),
                    Route::patch('/{id}')->name('patch')->action([GroupController::class, 'patch']),
                    Route::delete('/{id}')->name('delete')->action([GroupController::class, 'delete']),
                ),
        ),
];
