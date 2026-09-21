<?php

declare(strict_types=1);

require_once __DIR__ . '/app/bootstrap.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-" . csp_nonce() . "'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'");

$repository = new WatchuRepository(Database::connection());
$page = strtolower(trim((string) ($_GET['page'] ?? (Auth::check() ? 'dashboard' : 'login'))));
$page = preg_replace('/[^a-z-]/', '', $page) ?: 'dashboard';

function csv_cell(mixed $value): string
{
    $text = (string) $value;
    if ($text !== '' && preg_match('/^[=+\-@\t\r]/', $text)) {
        return "'" . $text;
    }
    return $text;
}

function incident_filters(): array
{
    return [
        'q' => mb_substr(trim((string) ($_GET['q'] ?? '')), 0, 120),
        'severity' => trim((string) ($_GET['severity'] ?? '')),
        'status' => trim((string) ($_GET['status'] ?? '')),
    ];
}

try {
    if ($page === 'login') {
        if (Auth::check()) {
            redirect('dashboard');
        }
        $errors = [];
        $email = '';
        if (is_post()) {
            Csrf::verify();
            $email = post_string('email', 160);
            $password = (string) ($_POST['password'] ?? '');
            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
                $errors[] = 'Enter a valid email address and password.';
            } elseif (!Auth::attempt($email, $password)) {
                usleep(250000);
                $errors[] = 'The email address or password is incorrect.';
            } else {
                flash('success', 'Welcome back. Your secure session is active.');
                redirect('dashboard');
            }
        }
        render_view('login', compact('page', 'repository', 'errors', 'email') + ['title' => 'Sign in'], true);
        exit;
    }

    if ($page === 'register') {
        if (Auth::check()) {
            redirect('dashboard');
        }
        $errors = [];
        $values = ['name' => '', 'email' => ''];
        if (is_post()) {
            Csrf::verify();
            $values['name'] = post_string('name', 80);
            $values['email'] = post_string('email', 160);
            $password = (string) ($_POST['password'] ?? '');
            $confirmation = (string) ($_POST['password_confirmation'] ?? '');

            if (mb_strlen($values['name']) < 2) {
                $errors[] = 'Name must contain at least 2 characters.';
            }
            if (!filter_var($values['email'], FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Enter a valid email address.';
            } elseif ($repository->emailExists($values['email'])) {
                $errors[] = 'An account already uses this email address.';
            }
            if (strlen($password) < 12 || !preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password) || !preg_match('/\d/', $password) || !preg_match('/[^A-Za-z0-9]/', $password)) {
                $errors[] = 'Password must be 12+ characters and include uppercase, lowercase, a number and a symbol.';
            }
            if (!hash_equals($password, $confirmation)) {
                $errors[] = 'Password confirmation does not match.';
            }
            if ($errors === []) {
                $repository->createAnalyst($values['name'], $values['email'], $password);
                flash('success', 'Analyst account created. You can now sign in.');
                redirect('login');
            }
        }
        render_view('register', compact('page', 'repository', 'errors', 'values') + ['title' => 'Create account'], true);
        exit;
    }

    if ($page === 'logout') {
        Auth::requireLogin();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Sign out requests must use the secure form.');
        }
        Csrf::verify();
        Auth::logout();
        header('Location: ' . url('login'));
        exit;
    }

    Auth::requireLogin();

    if ($page === 'incident-status') {
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Status updates must use the incident form.');
        }
        Csrf::verify();
        $updated = $repository->updateIncidentStatus((int) ($_POST['incident_id'] ?? 0), post_string('status', 40));
        flash($updated ? 'success' : 'warning', $updated ? 'Incident status updated.' : 'The incident status could not be updated.');
        redirect('incidents');
    }

    if ($page === 'user-role') {
        Auth::requireSecurityDepartment();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Role updates must use the access form.');
        }
        Csrf::verify();
        [$ok, $message] = $repository->updateUserRole((int) Auth::user()['id'], (int) ($_POST['user_id'] ?? 0), post_string('role', 40));
        flash($ok ? 'success' : 'warning', $message);
        redirect('users');
    }

    if ($page === 'settings-save') {
        Auth::requireSecurityDepartment();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Settings updates must use the settings form.');
        }
        Csrf::verify();
        $severity = post_string('alert_min_severity', 20);
        $timezone = post_string('system_timezone', 80);
        $window = max(1, min(1440, (int) ($_POST['dedupe_window_minutes'] ?? 15)));
        $allowlist = trim(str_replace(["\r\n", "\r"], "\n", post_string('nmap_allowed_cidrs', 2000)));
        $nmap = new NmapService();
        $cidrErrors = [];
        foreach (array_filter(array_map('trim', explode("\n", $allowlist))) as $cidr) {
            [$valid, $reason] = $nmap->validateTarget($cidr, $cidr);
            if (!$valid) {
                $cidrErrors[] = $cidr . ': ' . $reason;
            }
        }
        if ($allowlist === '' || $cidrErrors !== []) {
            flash('warning', $allowlist === '' ? 'At least one private lab CIDR is required.' : 'Invalid allowlist entry: ' . $cidrErrors[0]);
            redirect('settings');
        }
        $repository->saveSettings([
            'display_name' => post_string('display_name', 100) ?: 'Watch-U Security Operations',
            'telegram_enabled' => isset($_POST['telegram_enabled']) ? '1' : '0',
            'telegram_chat_id' => post_string('telegram_chat_id', 80),
            'alert_min_severity' => in_array($severity, ['Low', 'Medium', 'High', 'Critical'], true) ? $severity : 'High',
            'nmap_allowed_cidrs' => $allowlist,
            'dedupe_window_minutes' => (string) $window,
            'system_timezone' => in_array($timezone, timezone_identifiers_list(), true) ? $timezone : (string) config('app.timezone'),
        ], (int) Auth::user()['id']);
        flash('success', 'System settings saved.');
        redirect('settings');
    }

    if ($page === 'telegram-test') {
        Auth::requireSecurityDepartment();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Telegram tests must use the settings form.');
        }
        Csrf::verify();
        $chatId = post_string('telegram_chat_id', 80);
        [$ok, $message] = (new TelegramService())->send($chatId, '<b>Watch-U test alert</b>' . "\n" . 'Telegram delivery is configured for this Security Department account.');
        flash($ok ? 'success' : 'warning', $message);
        redirect('settings');
    }

    if ($page === 'wazuh-test') {
        Auth::requireSecurityDepartment();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Wazuh tests must use the settings form.');
        }
        Csrf::verify();
        $_SESSION['wazuh_connection_status'] = (new WazuhService())->testConnection();
        redirect('settings');
    }

    if ($page === 'run-scan') {
        Auth::requireSecurityDepartment();
        if (!is_post()) {
            http_response_code(405);
            throw new RuntimeException('Scan requests must use the authorised scan form.');
        }
        Csrf::verify();
        $target = post_string('target', 64);
        $profile = post_string('profile', 20);
        $scanId = $repository->createScan($target, $profile, (int) Auth::user()['id']);
        $nmap = new NmapService();
        [$valid, $reason] = $nmap->validateTarget($target, $repository->settings()['nmap_allowed_cidrs']);
        if (!$valid) {
            $repository->finishScan($scanId, 'Blocked', $reason);
            flash('warning', $reason);
            redirect('scans');
        }
        [$status, $output] = $nmap->run($target, $profile);
        $repository->finishScan($scanId, $status, $output);
        flash($status === 'Completed' ? 'success' : 'warning', $status === 'Completed' ? 'Authorised lab scan completed.' : $output);
        redirect('scans');
    }

    if ($page === 'export') {
        $kind = trim((string) ($_GET['kind'] ?? 'incidents'));
        $filters = incident_filters();
        $filename = 'watchu-' . ($kind === 'vulnerabilities' ? 'vulnerabilities' : 'incidents') . '-' . date('Ymd-His') . '.csv';
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('X-Content-Type-Options: nosniff');
        $stream = fopen('php://output', 'wb');
        fwrite($stream, "\xEF\xBB\xBF");
        if ($kind === 'vulnerabilities') {
            fputcsv($stream, ['ID', 'CVE', 'Finding', 'Asset', 'IP address', 'Severity', 'CVSS', 'Status', 'Detected']);
            foreach ($repository->vulnerabilities($filters) as $row) {
                fputcsv($stream, array_map('csv_cell', [$row['id'], $row['cve'], $row['title'], $row['hostname'], $row['ip_address'], $row['severity'], $row['cvss'], $row['status'], $row['detected_at']]));
            }
        } else {
            fputcsv($stream, ['ID', 'Title', 'Source', 'Category', 'Source IP', 'Destination IP', 'Severity', 'Score', 'Events', 'Status', 'First seen', 'Last seen', 'Summary']);
            foreach ($repository->incidents($filters) as $row) {
                fputcsv($stream, array_map('csv_cell', [$row['id'], $row['title'], $row['source'], $row['category'], $row['src_ip'], $row['dest_ip'], $row['severity'], $row['score'], $row['event_count'], $row['status'], $row['first_seen'], $row['last_seen'], $row['summary']]));
            }
        }
        fclose($stream);
        exit;
    }

    $data = compact('page', 'repository');
    switch ($page) {
        case 'dashboard':
            $data += ['title' => 'Security posture', 'dashboard' => $repository->dashboard()];
            render_view('dashboard', $data);
            break;
        case 'incidents':
            $filters = incident_filters();
            render_view('incidents', $data + ['title' => 'Incidents', 'filters' => $filters, 'incidents' => $repository->incidents($filters)]);
            break;
        case 'vulnerabilities':
            $filters = incident_filters();
            render_view('vulnerabilities', $data + ['title' => 'Vulnerabilities', 'filters' => $filters, 'vulnerabilities' => $repository->vulnerabilities($filters)]);
            break;
        case 'assets':
            $query = mb_substr(trim((string) ($_GET['q'] ?? '')), 0, 120);
            render_view('assets', $data + ['title' => 'Assets', 'query' => $query, 'assets' => $repository->assets($query)]);
            break;
        case 'reports':
            render_view('reports', $data + ['title' => 'Reports']);
            break;
        case 'users':
            Auth::requireSecurityDepartment();
            render_view('users', $data + ['title' => 'User roles', 'users' => $repository->users()]);
            break;
        case 'scans':
            Auth::requireSecurityDepartment();
            render_view('scans', $data + ['title' => 'Private lab scans', 'settings' => $repository->settings(), 'scans' => $repository->scans()]);
            break;
        case 'settings':
            Auth::requireSecurityDepartment();
            $wazuhStatus = WazuhService::isConfigured() ? ($_SESSION['wazuh_connection_status'] ?? 'Not tested') : 'Not configured';
            render_view('settings', $data + ['title' => 'Settings', 'settings' => $repository->settings(), 'wazuhStatus' => $wazuhStatus]);
            break;
        default:
            http_response_code(404);
            render_view('error', $data + ['title' => 'Not found', 'status' => 404, 'heading' => 'Page not found', 'message' => 'The requested Watch-U page does not exist.']);
    }
} catch (Throwable $exception) {
    $status = http_response_code();
    if ($status < 400) {
        $status = 500;
        http_response_code($status);
    }
    $message = config('app.env') === 'local' ? $exception->getMessage() : 'The request could not be completed safely.';
    $heading = match ($status) {
        403 => 'Access denied',
        404 => 'Page not found',
        405 => 'Method not allowed',
        419 => 'Session expired',
        default => 'Watch-U encountered an error',
    };
    render_view('error', compact('page', 'repository', 'status', 'heading', 'message') + ['title' => $heading], !Auth::check());
}
