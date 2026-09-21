<?php

declare(strict_types=1);

final class WatchuRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function createAnalyst(string $name, string $email, string $password): int
    {
        $statement = $this->pdo->prepare(
            "INSERT INTO users (name, email, password_hash, role, created_at, updated_at)
             VALUES (:name, :email, :password_hash, 'analyst', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        );
        $statement->execute([
            'name' => trim($name),
            'email' => strtolower(trim($email)),
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function emailExists(string $email): bool
    {
        $statement = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email');
        $statement->execute(['email' => strtolower(trim($email))]);
        return $statement->fetchColumn() !== false;
    }

    public function dashboard(): array
    {
        $severityRows = $this->pdo->query('SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity')->fetchAll();
        $severity = array_fill_keys(['Low', 'Medium', 'High', 'Critical'], 0);
        foreach ($severityRows as $row) {
            $severity[$row['severity']] = (int) $row['total'];
        }

        $statusRows = $this->pdo->query('SELECT status, COUNT(*) AS total FROM incidents GROUP BY status')->fetchAll();
        $status = [];
        foreach ($statusRows as $row) {
            $status[$row['status']] = (int) $row['total'];
        }

        $trendRows = $this->pdo->query("SELECT date(last_seen) AS day, SUM(event_count) AS total FROM incidents WHERE date(last_seen) >= date('now', '-6 days') GROUP BY date(last_seen)")->fetchAll();
        $trendMap = [];
        foreach ($trendRows as $row) {
            $trendMap[$row['day']] = (int) $row['total'];
        }
        $trend = [];
        for ($offset = 6; $offset >= 0; $offset--) {
            $day = date('Y-m-d', strtotime('-' . $offset . ' days'));
            $trend[] = ['label' => date('D', strtotime($day)), 'value' => $trendMap[$day] ?? 0];
        }

        return [
            'severity' => $severity,
            'status' => $status,
            'trend' => $trend,
            'open_incidents' => (int) $this->pdo->query("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved', 'False Positive')")->fetchColumn(),
            'critical_incidents' => (int) $this->pdo->query("SELECT COUNT(*) FROM incidents WHERE severity = 'Critical' AND status NOT IN ('Resolved', 'False Positive')")->fetchColumn(),
            'vulnerabilities' => (int) $this->pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE status != 'Remediated'")->fetchColumn(),
            'assets' => (int) $this->pdo->query('SELECT COUNT(*) FROM assets')->fetchColumn(),
            'events' => (int) $this->pdo->query('SELECT COALESCE(SUM(event_count), 0) FROM incidents')->fetchColumn(),
            'recent' => $this->pdo->query('SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 5')->fetchAll(),
            'top_assets' => $this->pdo->query(
                "SELECT a.hostname, a.ip_address, a.criticality, COUNT(v.id) AS vulnerability_count,
                        COALESCE(MAX(v.cvss), 0) AS max_cvss
                 FROM assets a LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.status != 'Remediated'
                 GROUP BY a.id ORDER BY max_cvss DESC, vulnerability_count DESC LIMIT 4"
            )->fetchAll(),
        ];
    }

    public function incidents(array $filters = []): array
    {
        $where = [];
        $params = [];
        if (in_array($filters['severity'] ?? '', ['Low', 'Medium', 'High', 'Critical'], true)) {
            $where[] = 'severity = :severity';
            $params['severity'] = $filters['severity'];
        }
        if (in_array($filters['status'] ?? '', ['Open', 'Investigating', 'Contained', 'Resolved', 'False Positive'], true)) {
            $where[] = 'status = :status';
            $params['status'] = $filters['status'];
        }
        if (($filters['q'] ?? '') !== '') {
            $where[] = '(title LIKE :query OR src_ip LIKE :query OR dest_ip LIKE :query OR category LIKE :query OR source LIKE :query)';
            $params['query'] = '%' . $filters['q'] . '%';
        }

        $sql = 'SELECT i.*, u.name AS assignee FROM incidents i LEFT JOIN users u ON u.id = i.assigned_to';
        if ($where !== []) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= " ORDER BY CASE i.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, i.last_seen DESC";

        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll();
    }

    public function updateIncidentStatus(int $id, string $status): bool
    {
        if (!in_array($status, ['Open', 'Investigating', 'Contained', 'Resolved', 'False Positive'], true)) {
            return false;
        }

        $statement = $this->pdo->prepare('UPDATE incidents SET status = :status, updated_at = CURRENT_TIMESTAMP WHERE id = :id');
        $statement->execute(['status' => $status, 'id' => $id]);
        return $statement->rowCount() === 1;
    }

    public function vulnerabilities(array $filters = []): array
    {
        $where = [];
        $params = [];
        if (in_array($filters['severity'] ?? '', ['Low', 'Medium', 'High', 'Critical'], true)) {
            $where[] = 'v.severity = :severity';
            $params['severity'] = $filters['severity'];
        }
        if (in_array($filters['status'] ?? '', ['Open', 'In Progress', 'Accepted', 'Remediated'], true)) {
            $where[] = 'v.status = :status';
            $params['status'] = $filters['status'];
        }
        if (($filters['q'] ?? '') !== '') {
            $where[] = '(v.title LIKE :query OR v.cve LIKE :query OR a.hostname LIKE :query OR a.ip_address LIKE :query)';
            $params['query'] = '%' . $filters['q'] . '%';
        }

        $sql = 'SELECT v.*, a.hostname, a.ip_address FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id';
        if ($where !== []) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= " ORDER BY CASE v.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, v.cvss DESC";

        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll();
    }

    public function assets(string $query = ''): array
    {
        $sql = "SELECT a.*,
                       COUNT(v.id) AS vulnerability_count,
                       SUM(CASE WHEN v.severity IN ('High', 'Critical') AND v.status != 'Remediated' THEN 1 ELSE 0 END) AS high_risk_count
                FROM assets a LEFT JOIN vulnerabilities v ON v.asset_id = a.id";
        $params = [];
        if ($query !== '') {
            $sql .= ' WHERE a.hostname LIKE :query OR a.ip_address LIKE :query OR a.owner LIKE :query OR a.operating_system LIKE :query';
            $params['query'] = '%' . $query . '%';
        }
        $sql .= ' GROUP BY a.id ORDER BY high_risk_count DESC, a.hostname ASC';
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll();
    }

    public function users(): array
    {
        return $this->pdo->query('SELECT id, name, email, role, created_at, updated_at FROM users ORDER BY name')->fetchAll();
    }

    public function updateUserRole(int $actorId, int $userId, string $role): array
    {
        if (!in_array($role, ['analyst', 'security_department'], true)) {
            return [false, 'Invalid role.'];
        }
        if ($actorId === $userId && $role !== 'security_department') {
            return [false, 'You cannot remove your own Security Department access.'];
        }

        $current = $this->pdo->prepare('SELECT role FROM users WHERE id = :id');
        $current->execute(['id' => $userId]);
        $oldRole = $current->fetchColumn();
        if ($oldRole === false) {
            return [false, 'User not found.'];
        }
        if ($oldRole === 'security_department' && $role === 'analyst') {
            $adminCount = (int) $this->pdo->query("SELECT COUNT(*) FROM users WHERE role = 'security_department'")->fetchColumn();
            if ($adminCount <= 1) {
                return [false, 'At least one Security Department user must remain.'];
            }
        }

        $statement = $this->pdo->prepare('UPDATE users SET role = :role, updated_at = CURRENT_TIMESTAMP WHERE id = :id');
        $statement->execute(['role' => $role, 'id' => $userId]);
        return [true, 'User role updated.'];
    }

    public function settings(): array
    {
        $defaults = [
            'display_name' => 'Watch-U Security Operations',
            'telegram_enabled' => '0',
            'telegram_chat_id' => '',
            'alert_min_severity' => 'High',
            'nmap_allowed_cidrs' => "192.168.56.0/24\n10.10.10.0/24",
            'dedupe_window_minutes' => '15',
            'system_timezone' => (string) config('app.timezone'),
        ];
        $rows = $this->pdo->query('SELECT setting_key, setting_value FROM settings')->fetchAll();
        foreach ($rows as $row) {
            $defaults[$row['setting_key']] = $row['setting_value'];
        }
        return $defaults;
    }

    public function saveSettings(array $values, int $userId): void
    {
        $allowed = ['display_name', 'telegram_enabled', 'telegram_chat_id', 'alert_min_severity', 'nmap_allowed_cidrs', 'dedupe_window_minutes', 'system_timezone'];
        $statement = $this->pdo->prepare(
            'INSERT INTO settings (setting_key, setting_value, updated_by, updated_at)
             VALUES (:key, :value, :user, CURRENT_TIMESTAMP)
             ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP'
        );
        foreach ($allowed as $key) {
            if (array_key_exists($key, $values)) {
                $statement->execute(['key' => $key, 'value' => (string) $values[$key], 'user' => $userId]);
            }
        }
    }

    public function createScan(string $target, string $profile, int $userId): int
    {
        $statement = $this->pdo->prepare('INSERT INTO scan_jobs (target, scan_profile, status, created_by) VALUES (:target, :profile, :status, :user)');
        $statement->execute(['target' => $target, 'profile' => $profile, 'status' => 'Queued', 'user' => $userId]);
        return (int) $this->pdo->lastInsertId();
    }

    public function finishScan(int $id, string $status, string $output): void
    {
        $statement = $this->pdo->prepare(
            'UPDATE scan_jobs SET status = :status, command_output = :output,
             started_at = COALESCE(started_at, CURRENT_TIMESTAMP), finished_at = CURRENT_TIMESTAMP WHERE id = :id'
        );
        $statement->execute(['status' => $status, 'output' => mb_substr($output, 0, 50000), 'id' => $id]);
    }

    public function scans(): array
    {
        return $this->pdo->query(
            'SELECT s.*, u.name AS created_by_name FROM scan_jobs s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC LIMIT 25'
        )->fetchAll();
    }
}
