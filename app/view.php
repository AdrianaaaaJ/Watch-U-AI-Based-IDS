<?php

declare(strict_types=1);

function render_view(string $template, array $data = [], bool $guest = false): void
{
    $path = WATCHU_ROOT . '/app/Views/' . $template . '.php';
    if (!is_file($path)) {
        throw new RuntimeException('View not found: ' . $template);
    }

    extract($data, EXTR_SKIP);
    ob_start();
    require $path;
    $content = (string) ob_get_clean();
    require WATCHU_ROOT . '/app/Views/layout.php';
}

