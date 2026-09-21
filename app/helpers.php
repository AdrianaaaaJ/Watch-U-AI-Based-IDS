<?php

declare(strict_types=1);

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csp_nonce(): string
{
    static $nonce;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(18));
    }
    return $nonce;
}

function url(string $page = 'dashboard', array $params = []): string
{
    $base = (string) config('app.url');
    $query = http_build_query(['page' => $page] + $params);
    return ($base !== '' ? $base . '/' : '') . 'index.php?' . $query;
}

function asset_url(string $path): string
{
    $base = (string) config('app.url');
    return ($base !== '' ? $base . '/' : '') . ltrim($path, '/');
}

function redirect(string $page, array $params = []): never
{
    header('Location: ' . url($page, $params));
    exit;
}

function flash(string $type, string $message): void
{
    $_SESSION['_flash'][] = ['type' => $type, 'message' => $message];
}

function consume_flashes(): array
{
    $messages = $_SESSION['_flash'] ?? [];
    unset($_SESSION['_flash']);
    return is_array($messages) ? $messages : [];
}

function is_post(): bool
{
    return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
}

function post_string(string $key, int $maxLength = 500): string
{
    $value = trim((string) ($_POST[$key] ?? ''));
    return mb_substr($value, 0, $maxLength);
}

function severity_class(string $severity): string
{
    return 'severity-' . strtolower($severity);
}

function format_datetime(?string $value, string $format = 'd M Y, H:i'): string
{
    if (!$value) {
        return '—';
    }

    try {
        return (new DateTimeImmutable($value))->format($format);
    } catch (Throwable) {
        return $value;
    }
}

function selected(string $actual, string $expected): string
{
    return $actual === $expected ? ' selected' : '';
}

function checked(bool $value): string
{
    return $value ? ' checked' : '';
}

function active_nav(string $page, string $target): string
{
    return $page === $target ? ' active' : '';
}

function current_filter(string $key): string
{
    return trim((string) ($_GET[$key] ?? ''));
}
