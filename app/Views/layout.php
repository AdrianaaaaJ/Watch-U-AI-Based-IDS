<?php

$page = $page ?? 'dashboard';
$title = $title ?? config('app.name');
$user = Auth::user();
$flashes = consume_flashes();
$settings = isset($repository) && $repository instanceof WatchuRepository ? $repository->settings() : [];
$siteName = $settings['display_name'] ?? config('app.name');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="description" content="Watch-U security monitoring and incident operations dashboard">
    <title><?= e($title) ?> · <?= e(config('app.name')) ?></title>
    <link rel="stylesheet" href="<?= e(asset_url('assets/css/app.css')) ?>">
    <script src="<?= e(asset_url('assets/js/app.js')) ?>" defer></script>
</head>
<body class="<?= $guest ? 'guest-body' : 'app-body' ?>">
<?php if ($guest): ?>
    <main class="guest-shell">
        <a class="brand brand-large" href="<?= e(url(Auth::check() ? 'dashboard' : 'login')) ?>" aria-label="Watch-U home">
            <span class="brand-mark">W</span>
            <span><strong>WATCH-U</strong><small>SECURITY OPERATIONS</small></span>
        </a>
        <?php foreach ($flashes as $flash): ?>
            <div class="flash flash-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
        <?php endforeach; ?>
        <?= $content ?>
        <p class="guest-footer">Watch-U · local security workspace.</p>
    </main>
<?php else: ?>
    <aside class="sidebar" id="sidebar">
        <a class="brand" href="<?= e(url('dashboard')) ?>">
            <span class="brand-mark">W</span>
            <span><strong>WATCH-U</strong><small>SECURITY OPS</small></span>
        </a>
        <nav class="primary-nav" aria-label="Primary navigation">
            <p class="nav-label">WORKSPACE</p>
            <a class="nav-link<?= active_nav($page, 'dashboard') ?>" href="<?= e(url('dashboard')) ?>"><span class="nav-icon">□</span>Overview</a>
            <a class="nav-link<?= active_nav($page, 'incidents') ?>" href="<?= e(url('incidents')) ?>"><span class="nav-icon">!</span>Incidents</a>
            <a class="nav-link<?= active_nav($page, 'vulnerabilities') ?>" href="<?= e(url('vulnerabilities')) ?>"><span class="nav-icon">◇</span>Vulnerabilities</a>
            <a class="nav-link<?= active_nav($page, 'assets') ?>" href="<?= e(url('assets')) ?>"><span class="nav-icon">⌘</span>Assets</a>
            <p class="nav-label">PREPARE</p>
            <a class="nav-link<?= active_nav($page, 'reports') ?>" href="<?= e(url('reports')) ?>"><span class="nav-icon">↗</span>Reports</a>
            <?php if (Auth::isSecurityDepartment()): ?>
                <a class="nav-link<?= active_nav($page, 'scans') ?>" href="<?= e(url('scans')) ?>"><span class="nav-icon">⌁</span>Lab scans</a>
                <a class="nav-link<?= active_nav($page, 'users') ?>" href="<?= e(url('users')) ?>"><span class="nav-icon">◎</span>Users</a>
                <a class="nav-link<?= active_nav($page, 'settings') ?>" href="<?= e(url('settings')) ?>"><span class="nav-icon">⚙</span>Settings</a>
            <?php endif; ?>
        </nav>
        <div class="sidebar-status">
            <span class="status-dot"></span>
            <span><strong>Local monitoring</strong><small>SQLite · Laragon</small></span>
        </div>
    </aside>
    <div class="app-shell">
        <header class="topbar">
            <button class="mobile-menu" type="button" data-menu-toggle aria-label="Toggle navigation" aria-expanded="false">☰</button>
            <div class="topbar-context">
                <span class="eyebrow">SECURITY OPERATIONS</span>
                <strong><?= e($siteName) ?></strong>
            </div>
            <div class="topbar-actions">
                <div class="live-indicator"><span></span>READY FOR ALERTS</div>
                <div class="user-menu">
                    <span class="avatar"><?= e(strtoupper(substr((string) $user['name'], 0, 1))) ?></span>
                    <span class="user-copy"><strong><?= e($user['name']) ?></strong><small><?= $user['role'] === 'security_department' ? 'Security Department' : 'Analyst' ?></small></span>
                </div>
                <form method="post" action="<?= e(url('logout')) ?>">
                    <?= Csrf::field() ?>
                    <button class="icon-button" type="submit" title="Sign out" aria-label="Sign out">↪</button>
                </form>
            </div>
        </header>
        <main class="content">
            <?php foreach ($flashes as $flash): ?>
                <div class="flash flash-<?= e($flash['type']) ?>" role="alert">
                    <span><?= e($flash['message']) ?></span><button type="button" data-dismiss aria-label="Dismiss">×</button>
                </div>
            <?php endforeach; ?>
            <?= $content ?>
        </main>
        <footer class="app-footer"><span>Watch-U</span><span>Local SQLite · Wazuh feed</span></footer>
    </div>
<?php endif; ?>
</body>
</html>
