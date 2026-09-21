<?php

declare(strict_types=1);

// Override local .env values before configuration loads; no real API is contacted.
putenv('WAZUH_URL=http://127.0.0.1:55000');
putenv('WAZUH_USERNAME=test-user');
putenv('WAZUH_PASSWORD=test-password');
putenv('WAZUH_CA_BUNDLE=');

require_once __DIR__ . '/../app/config.php';
require_once __DIR__ . '/../app/helpers.php';
require_once __DIR__ . '/../app/Csrf.php';
require_once __DIR__ . '/../app/Services/WazuhService.php';

function check_wazuh(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }
    echo 'PASS: ' . $message . PHP_EOL;
}

check_wazuh(WazuhService::isConfigured(), 'test configuration is present');
check_wazuh((new WazuhService())->testConnection() === 'Unreachable', 'non-HTTPS manager URL is rejected');
check_wazuh(WazuhService::statusFromResponse(200, '{"data":{"token":"placeholder-jwt"}}') === 'Connected', 'valid API authentication is connected');
check_wazuh(WazuhService::statusFromResponse(401, '{"error":"denied"}') === 'Authentication Failed', 'invalid credentials are reported without response details');
check_wazuh(WazuhService::statusFromResponse(403, '') === 'Authentication Failed', 'forbidden credentials are reported safely');
check_wazuh(WazuhService::statusFromResponse(200, '{"data":{}}') === 'Unreachable', 'missing JWT is not accepted as connected');
check_wazuh(WazuhService::statusFromResponse(502, '') === 'Unreachable', 'manager failures expose no response details');

$_SESSION = [];
$settings = [
    'display_name' => 'Watch-U',
    'system_timezone' => 'Asia/Kuala_Lumpur',
    'dedupe_window_minutes' => '15',
    'telegram_enabled' => '0',
    'telegram_chat_id' => '',
    'alert_min_severity' => 'High',
    'nmap_allowed_cidrs' => '192.168.56.0/24',
];
$wazuhStatus = 'Authentication Failed';
ob_start();
require __DIR__ . '/../app/Views/settings.php';
$settingsHtml = (string) ob_get_clean();
check_wazuh(str_contains($settingsHtml, 'GENERAL') && str_contains($settingsHtml, 'TELEGRAM'), 'existing Settings panels are preserved');
check_wazuh(str_contains($settingsHtml, 'WAZUH INTEGRATION') && str_contains($settingsHtml, 'Authentication Failed'), 'Wazuh status renders in Settings');
check_wazuh(substr_count($settingsHtml, '<form') === 2 && str_contains($settingsHtml, 'wazuh-test'), 'connection test has a separate server-side form');
check_wazuh(!str_contains($settingsHtml, 'test-password') && !str_contains($settingsHtml, 'placeholder-jwt'), 'credentials and JWT are absent from rendered HTML');

echo "All Wazuh service checks passed." . PHP_EOL;
