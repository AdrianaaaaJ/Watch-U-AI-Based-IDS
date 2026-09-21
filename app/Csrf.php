<?php

declare(strict_types=1);

final class Csrf
{
    public static function token(): string
    {
        if (empty($_SESSION['_csrf'])) {
            $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        }

        return (string) $_SESSION['_csrf'];
    }

    public static function field(): string
    {
        return '<input type="hidden" name="csrf_token" value="' . e(self::token()) . '">';
    }

    public static function verify(): void
    {
        $submitted = (string) ($_POST['csrf_token'] ?? '');
        $stored = (string) ($_SESSION['_csrf'] ?? '');
        if ($stored === '' || !hash_equals($stored, $submitted)) {
            http_response_code(419);
            throw new RuntimeException('Your session token expired. Refresh the page and try again.');
        }
    }
}

