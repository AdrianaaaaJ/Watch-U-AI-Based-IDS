<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/view.php';
require_once __DIR__ . '/Csrf.php';
require_once __DIR__ . '/Auth.php';
require_once __DIR__ . '/WatchuRepository.php';
require_once __DIR__ . '/Services/TelegramService.php';
require_once __DIR__ . '/Services/WazuhService.php';
require_once __DIR__ . '/Services/NmapService.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    $sessionPath = (string) config('session.path');
    if (!is_dir($sessionPath)) {
        mkdir($sessionPath, 0775, true);
    }
    session_save_path($sessionPath);
    session_name((string) config('session.name'));
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

if (isset($_SESSION['last_activity']) && time() - (int) $_SESSION['last_activity'] > 7200) {
    Auth::logout();
    session_name((string) config('session.name'));
    session_start();
}

if (Auth::check()) {
    $_SESSION['last_activity'] = time();
}

Database::connection();
