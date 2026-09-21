<?php

declare(strict_types=1);

final class Database
{
    private static ?PDO $connection = null;

    public static function connection(): PDO
    {
        if (self::$connection instanceof PDO) {
            return self::$connection;
        }

        $path = (string) config('db.path');
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0775, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the SQLite data directory.');
        }

        self::$connection = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        self::$connection->exec('PRAGMA foreign_keys = ON');
        self::$connection->exec('PRAGMA journal_mode = WAL');
        self::$connection->exec('PRAGMA busy_timeout = 5000');

        self::ensureSchema(self::$connection);
        return self::$connection;
    }

    private static function ensureSchema(PDO $pdo): void
    {
        $exists = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'")->fetchColumn();
        if ($exists !== false) {
            return;
        }

        $schema = file_get_contents(WATCHU_ROOT . '/database/schema.sql');
        if ($schema === false) {
            throw new RuntimeException('Database schema file is missing.');
        }

        $pdo->exec($schema);
    }

    public static function resetForTests(?string $path = null): void
    {
        self::$connection = null;
        if ($path !== null) {
            putenv('DB_PATH=' . $path);
        }
    }
}
