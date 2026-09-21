<?php

declare(strict_types=1);

const WATCHU_ROOT = __DIR__ . '/..';

function load_env_file(string $path): void
{
    if (!is_file($path)) {
        return;
    }

    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $value] = array_map('trim', explode('=', $line, 2));
        if ($key === '' || getenv($key) !== false) {
            continue;
        }

        if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
            $value = substr($value, 1, -1);
        }

        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
    }
}

load_env_file(WATCHU_ROOT . '/.env');

function env_value(string $key, mixed $default = null): mixed
{
    $value = getenv($key);
    return $value === false ? $default : $value;
}

function env_bool(string $key, bool $default = false): bool
{
    $value = env_value($key);
    if ($value === null) {
        return $default;
    }

    return filter_var($value, FILTER_VALIDATE_BOOLEAN);
}

function config(string $key, mixed $default = null): mixed
{
    static $values;

    if ($values === null) {
        $rootPath = realpath(WATCHU_ROOT) ?: WATCHU_ROOT;
        $dbPath = (string) env_value('DB_PATH', 'database/watchu.sqlite');
        if (!preg_match('/^(?:[A-Za-z]:[\\\\\/]|\/)/', $dbPath)) {
            $dbPath = $rootPath . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, ltrim($dbPath, '/\\'));
        }

        $sessionPath = (string) env_value('SESSION_PATH', 'data/sessions');
        if (!preg_match('/^(?:[A-Za-z]:[\\\\\/]|\/)/', $sessionPath)) {
            $sessionPath = $rootPath . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, ltrim($sessionPath, '/\\'));
        }

        $values = [
            'app.name' => (string) env_value('APP_NAME', 'Watch-U'),
            'app.env' => (string) env_value('APP_ENV', 'local'),
            'app.url' => rtrim((string) env_value('APP_URL', ''), '/'),
            'app.timezone' => (string) env_value('APP_TIMEZONE', 'Asia/Kuala_Lumpur'),
            'session.name' => (string) env_value('SESSION_NAME', 'WATCHUSESSID'),
            'session.path' => $sessionPath,
            'db.path' => $dbPath,
            'telegram.token' => (string) env_value('TELEGRAM_BOT_TOKEN', ''),
            'wazuh.url' => (string) env_value('WAZUH_URL', ''),
            'wazuh.username' => (string) env_value('WAZUH_USERNAME', ''),
            'wazuh.password' => (string) env_value('WAZUH_PASSWORD', ''),
            'wazuh.ca_bundle' => (string) env_value('WAZUH_CA_BUNDLE', ''),
            'nmap.enabled' => env_bool('ENABLE_NMAP_SCANS', false),
            'nmap.binary' => (string) env_value('NMAP_BINARY', 'nmap'),
            'python.binary' => (string) env_value('PYTHON_BINARY', 'python'),
        ];
    }

    return $values[$key] ?? $default;
}

date_default_timezone_set((string) config('app.timezone'));
