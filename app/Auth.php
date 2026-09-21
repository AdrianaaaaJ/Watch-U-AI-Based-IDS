<?php

declare(strict_types=1);

final class Auth
{
    private static ?array $cachedUser = null;
    private static bool $resolved = false;

    public static function attempt(string $email, string $password): bool
    {
        $statement = Database::connection()->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => strtolower(trim($email))]);
        $user = $statement->fetch();

        if (!$user || !password_verify($password, (string) $user['password_hash'])) {
            return false;
        }

        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['last_activity'] = time();
        self::$cachedUser = $user;
        self::$resolved = true;
        return true;
    }

    public static function user(): ?array
    {
        if (self::$resolved) {
            return self::$cachedUser;
        }

        self::$resolved = true;
        $id = (int) ($_SESSION['user_id'] ?? 0);
        if ($id < 1) {
            return null;
        }

        $statement = Database::connection()->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => $id]);
        self::$cachedUser = $statement->fetch() ?: null;
        return self::$cachedUser;
    }

    public static function check(): bool
    {
        return self::user() !== null;
    }

    public static function isSecurityDepartment(): bool
    {
        return (self::user()['role'] ?? '') === 'security_department';
    }

    public static function requireLogin(): void
    {
        if (!self::check()) {
            flash('warning', 'Please sign in to continue.');
            redirect('login');
        }
    }

    public static function requireSecurityDepartment(): void
    {
        self::requireLogin();
        if (!self::isSecurityDepartment()) {
            http_response_code(403);
            throw new RuntimeException('Security Department access is required.');
        }
    }

    public static function logout(): void
    {
        self::$cachedUser = null;
        self::$resolved = true;
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
        }
        session_destroy();
    }
}

