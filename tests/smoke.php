<?php

declare(strict_types=1);

$testPath = __DIR__ . '/../data/watchu-smoke.sqlite';
if (is_file($testPath)) {
    unlink($testPath);
}
putenv('DB_PATH=' . $testPath);
putenv('APP_ENV=testing');

require_once __DIR__ . '/../app/config.php';
require_once __DIR__ . '/../app/Database.php';
require_once __DIR__ . '/../app/helpers.php';
require_once __DIR__ . '/../app/WatchuRepository.php';
require_once __DIR__ . '/../app/Services/NmapService.php';

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }
    echo 'PASS: ' . $message . PHP_EOL;
}

$pdo = Database::connection();
$repository = new WatchuRepository($pdo);

assert_true((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0, 'fresh database starts empty');

$newUser = $repository->createAnalyst('Smoke Tester', 'smoke@example.test', 'StrongSmoke!2026');
$newRole = $pdo->query('SELECT role FROM users WHERE id = ' . (int) $newUser)->fetchColumn();
assert_true($newRole === 'analyst', 'public account creation is Analyst-only');
$pdo->prepare("UPDATE users SET role = 'security_department' WHERE id = :id")->execute(['id' => $newUser]);
$security = $pdo->query('SELECT * FROM users WHERE id = ' . (int) $newUser)->fetch();
assert_true($security['role'] === 'security_department', 'Security Department role can be assigned when access is approved');

$pdo->exec("INSERT INTO assets (hostname, ip_address, operating_system, owner, criticality, status) VALUES ('smoke-host', '192.168.56.20', 'Linux', 'QA', 'Medium', 'Online')");
$assetId = (int) $pdo->lastInsertId();
$pdo->prepare("INSERT INTO incidents (fingerprint, title, source, category, src_ip, dest_ip, severity, score, summary) VALUES (:fingerprint, :title, :source, :category, :src, :dest, :severity, :score, :summary)")->execute([
    'fingerprint' => hash('sha256', 'smoke incident'), 'title' => 'Smoke incident', 'source' => 'Smoke test', 'category' => 'Validation',
    'src' => '192.168.56.10', 'dest' => '192.168.56.20', 'severity' => 'Critical', 'score' => 95, 'summary' => 'Temporary smoke-test record.',
]);
$pdo->prepare("INSERT INTO vulnerabilities (asset_id, cve, title, description, severity, cvss) VALUES (:asset_id, :cve, :title, :description, :severity, :cvss)")->execute([
    'asset_id' => $assetId, 'cve' => 'CVE-2026-0001', 'title' => 'Smoke finding', 'description' => 'Temporary smoke-test finding.', 'severity' => 'High', 'cvss' => 8.1,
]);

$critical = $repository->incidents(['severity' => 'Critical', 'status' => '', 'q' => '']);
assert_true(count($critical) === 1, 'incident severity filtering works');
$firstIncident = (int) $pdo->query('SELECT id FROM incidents LIMIT 1')->fetchColumn();
assert_true($repository->updateIncidentStatus($firstIncident, 'Contained'), 'incident status can be updated');
assert_true(!$repository->updateIncidentStatus($firstIncident, 'Deleted'), 'invalid incident status is rejected');

$nmap = new NmapService();
[$validPrivate] = $nmap->validateTarget('192.168.56.101', '192.168.56.0/24');
[$validPublic] = $nmap->validateTarget('8.8.8.8', '0.0.0.0/0');
[$validInjection] = $nmap->validateTarget('192.168.56.1 --script vuln', '192.168.56.0/24');
assert_true($validPrivate, 'allowlisted RFC1918 scan target is accepted');
assert_true(!$validPublic, 'public scan target is rejected');
assert_true(!$validInjection, 'Nmap option injection is rejected');

[$demoted, $message] = $repository->updateUserRole((int) $security['id'], (int) $security['id'], 'analyst');
assert_true(!$demoted && str_contains($message, 'cannot remove'), 'self-demotion protection works');

echo "All PHP smoke tests passed." . PHP_EOL;
