<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/config.php';
require_once __DIR__ . '/../app/Database.php';

$pdo = Database::connection();
$users = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
$incidents = (int) $pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();

echo "Watch-U database is ready at " . config('db.path') . PHP_EOL;
echo "Draft records: {$users} users; {$incidents} incidents" . PHP_EOL;
echo "No demonstration data is added. Connect the approved VM or add records when the project is ready." . PHP_EOL;
