<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\Api\Scim\tests\Support;

use Psr\SimpleCache\CacheInterface;
use Yiisoft\Db\Cache\SchemaCache;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\Db\Sqlite\Connection;
use Yiisoft\Db\Sqlite\Driver;
use Yiisoft\Db\Sqlite\Dsn;
use YiiRocks\Voyti\Api\Scim\tests\TestCase;

abstract class DatabaseTestCase extends TestCase
{
    private ?ConnectionInterface $connection = null;

    protected function setUp(): void
    {
        $cache = $this->createStub(CacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->method('set')->willReturn(true);
        $schema = new SchemaCache($cache);
        $schema->setEnabled(false);
        $connection = new Connection(new Driver(new Dsn('sqlite', ':memory:')), $schema);
        ConnectionProvider::set($connection);
        $this->connection = $connection;
        $connection->createCommand(<<<'SQL'
            CREATE TABLE "user" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "username" VARCHAR(255) NOT NULL,
                "email" VARCHAR(255) NOT NULL,
                "password_hash" VARCHAR(255) NOT NULL,
                "auth_key" VARCHAR(32) NOT NULL,
                "blocked_at" INTEGER,
                "confirmed_at" INTEGER,
                "created_at" INTEGER NOT NULL,
                "flags" INTEGER NOT NULL DEFAULT 0,
                "data_processing_consent_date" INTEGER,
                "anonymized" INTEGER NOT NULL DEFAULT 0,
                "last_login_at" INTEGER,
                "last_login_ip" VARCHAR(45),
                "password_changed_at" INTEGER,
                "registration_ip" VARCHAR(45),
                "unconfirmed_email" VARCHAR(255),
                "updated_at" INTEGER NOT NULL
            )
            SQL)->execute();
        $connection->createCommand('CREATE UNIQUE INDEX "user-email" ON "user" ("email")')->execute();
        $connection->createCommand('CREATE UNIQUE INDEX "user-username" ON "user" ("username")')->execute();
        $connection->createCommand('CREATE TABLE "user_profile" ("user_id" INTEGER PRIMARY KEY)')->execute();
        $connection->createCommand('CREATE TABLE "user_token" ("user_id" INTEGER, "code" VARCHAR(64), "type" INTEGER, "created_at" INTEGER)')->execute();
        $connection->createCommand('CREATE TABLE "user_sessions" ("user_id" INTEGER, "session_id" VARCHAR(255), "user_agent" TEXT, "ip" VARCHAR(45), "created_at" INTEGER, "updated_at" INTEGER, "revoked_at" INTEGER)')->execute();
        $connection->createCommand('CREATE TABLE "user_password_history" ("user_id" INTEGER, "password_hash" VARCHAR(255), "created_at" INTEGER)')->execute();
    }

    protected function tearDown(): void
    {
        ConnectionProvider::clear();
        $this->connection?->close();
        $this->connection = null;
    }
}
