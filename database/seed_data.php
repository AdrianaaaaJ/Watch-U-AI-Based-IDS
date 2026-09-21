<?php

declare(strict_types=1);

function seed_watchu_database(PDO $pdo): void
{
    $pdo->beginTransaction();
    try {
        $userStatement = $pdo->prepare('INSERT INTO users (name, email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
        $userStatement->execute(['Nur Aisyah', 'security@watchu.local', password_hash('SecureWatch!2026', PASSWORD_DEFAULT), 'security_department']);
        $securityId = (int) $pdo->lastInsertId();
        $userStatement->execute(['Daniel Tan', 'analyst@watchu.local', password_hash('AnalystWatch!2026', PASSWORD_DEFAULT), 'analyst']);
        $analystId = (int) $pdo->lastInsertId();

        $assets = [
            ['soc-core-01', '10.10.10.10', 'Ubuntu 24.04 LTS', 'Security Operations', 'Critical', 'Online'],
            ['finance-db-01', '10.10.10.21', 'Windows Server 2022', 'Finance', 'Critical', 'Online'],
            ['hr-app-02', '10.10.10.34', 'Debian 12', 'Human Resources', 'High', 'Online'],
            ['edge-fw-01', '192.168.56.1', 'pfSense 2.7', 'Infrastructure', 'Critical', 'Online'],
            ['dev-api-03', '192.168.56.43', 'Rocky Linux 9', 'Engineering', 'Medium', 'Maintenance'],
            ['ops-ws-17', '10.10.10.117', 'Windows 11', 'Operations', 'Medium', 'Online'],
            ['backup-nas-01', '10.10.10.61', 'TrueNAS SCALE', 'Infrastructure', 'High', 'Online'],
            ['legacy-print-04', '10.10.10.204', 'Embedded Linux', 'Facilities', 'Low', 'Offline'],
        ];
        $assetStatement = $pdo->prepare('INSERT INTO assets (hostname, ip_address, operating_system, owner, criticality, status, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $assetIds = [];
        foreach ($assets as $index => $asset) {
            $seen = date('Y-m-d H:i:s', strtotime('-' . ($index * 11) . ' minutes'));
            $assetStatement->execute([...$asset, $seen]);
            $assetIds[$asset[0]] = (int) $pdo->lastInsertId();
        }

        $incidents = [
            ['Multiple failed administrator logins', 'Wazuh', 'Authentication', '203.0.113.44', '10.10.10.21', 'Critical', 96, 18, 'Investigating', 'Repeated administrator login failures targeted finance-db-01 from 203.0.113.44. Account lockout and source containment should be verified.', 0],
            ['ET MALWARE Possible Cobalt Strike traffic', 'Suricata', 'Command and Control', '10.10.10.117', '198.51.100.27', 'Critical', 94, 6, 'Contained', 'Beacon-like outbound traffic from ops-ws-17 matched a command-and-control signature. The endpoint was isolated pending forensic review.', 0],
            ['PowerShell encoded command detected', 'Wazuh', 'Execution', '10.10.10.117', null, 'High', 82, 3, 'Investigating', 'An encoded PowerShell command ran on ops-ws-17. Validate the parent process, user context, and endpoint timeline.', 1],
            ['SMB lateral movement pattern', 'Suricata', 'Lateral Movement', '10.10.10.34', '10.10.10.21', 'High', 78, 9, 'Open', 'Repeated SMB connections from hr-app-02 to the finance database exceeded the baseline. Confirm whether the service account activity is expected.', 1],
            ['Suspicious new local administrator', 'Wazuh', 'Persistence', '10.10.10.43', null, 'High', 76, 1, 'Open', 'A new local administrator account appeared on dev-api-03 outside the maintenance window. Review the change owner and authentication trail.', 2],
            ['DNS query to newly registered domain', 'Suricata', 'Command and Control', '10.10.10.117', '10.10.10.10', 'Medium', 58, 12, 'Investigating', 'ops-ws-17 repeatedly queried a newly registered domain. Inspect DNS answers and correlate with endpoint processes.', 2],
            ['Outbound data spike from HR application', 'Suricata', 'Exfiltration', '10.10.10.34', '198.51.100.88', 'High', 84, 4, 'Contained', 'hr-app-02 transferred substantially more outbound data than its normal baseline. The destination and affected records require validation.', 3],
            ['Linux sudo authentication failure', 'Wazuh', 'Privilege Escalation', '10.10.10.10', null, 'Medium', 49, 7, 'Resolved', 'Several failed sudo attempts occurred on soc-core-01. The analyst confirmed a mistyped automation credential and rotated it.', 3],
            ['Port scan against perimeter firewall', 'Suricata', 'Reconnaissance', '198.51.100.163', '192.168.56.1', 'Medium', 52, 144, 'False Positive', 'A high-volume connection sweep reached edge-fw-01. It matched an authorised external exposure assessment.', 4],
            ['Endpoint antivirus definition outdated', 'Wazuh', 'Security Hygiene', '10.10.10.204', null, 'Low', 22, 2, 'Open', 'legacy-print-04 has not received current malware signatures. Confirm vendor support or isolate the device.', 4],
            ['Backup repository permission changed', 'Wazuh', 'Impact', '10.10.10.61', null, 'High', 73, 1, 'Resolved', 'Permissions on the backup repository changed unexpectedly. The storage administrator restored the approved ACL.', 5],
            ['TLS certificate approaching expiry', 'Wazuh', 'Security Hygiene', '10.10.10.34', null, 'Low', 18, 1, 'Open', 'The HR application certificate expires soon. Schedule renewal before the service window closes.', 6],
        ];
        $incidentStatement = $pdo->prepare(
            'INSERT INTO incidents (fingerprint, title, source, category, src_ip, dest_ip, severity, score, event_count, status, summary, summary_provider, raw_json, assigned_to, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($incidents as $index => $incident) {
            $daysAgo = $incident[10];
            $first = date('Y-m-d H:i:s', strtotime('-' . $daysAgo . ' days -' . (25 + $index * 3) . ' minutes'));
            $last = date('Y-m-d H:i:s', strtotime('-' . $daysAgo . ' days -' . ($index * 2) . ' minutes'));
            $fingerprint = hash('sha256', strtolower(implode('|', array_filter([$incident[0], $incident[1], $incident[3], $incident[4]]))));
            $raw = json_encode(['seed' => true, 'rule' => ['description' => $incident[0]], 'source' => $incident[1]], JSON_UNESCAPED_SLASHES);
            $assignee = $index < 4 ? ($index % 2 === 0 ? $securityId : $analystId) : null;
            $incidentStatement->execute([$fingerprint, ...array_slice($incident, 0, 10), 'template', $raw, $assignee, $first, $last]);
        }

        $vulnerabilities = [
            ['finance-db-01', 'CVE-2025-49704', 'Windows service remote code execution', 'A network-facing service is missing the approved security update.', 'Critical', 9.8, 'In Progress', 1],
            ['edge-fw-01', 'CVE-2024-3400', 'Gateway command injection exposure', 'The lab gateway build requires vendor mitigation validation.', 'Critical', 10.0, 'Open', 2],
            ['hr-app-02', 'CVE-2024-6387', 'OpenSSH signal handler race condition', 'The installed OpenSSH package predates the fixed distribution build.', 'High', 8.1, 'In Progress', 3],
            ['backup-nas-01', 'CVE-2023-48795', 'SSH prefix truncation weakness', 'The SSH stack is affected by the Terrapin protocol weakness.', 'Medium', 5.9, 'Accepted', 7],
            ['dev-api-03', 'CVE-2025-29927', 'Framework middleware authorisation bypass', 'The development API uses a vulnerable middleware release.', 'Critical', 9.1, 'Open', 1],
            ['soc-core-01', 'CVE-2024-3094', 'Supply-chain package version detected', 'Scanner found a package name requiring manual provenance verification.', 'High', 8.8, 'Remediated', 12],
            ['ops-ws-17', 'CVE-2025-24054', 'NTLM hash disclosure risk', 'The workstation is pending the latest cumulative security update.', 'High', 7.5, 'Open', 2],
            ['legacy-print-04', null, 'Default SNMP community string', 'The device still responds to a vendor default read community.', 'Medium', 6.5, 'Open', 14],
            ['hr-app-02', null, 'Missing Content-Security-Policy', 'The internal application does not set a restrictive CSP response header.', 'Low', 3.1, 'Accepted', 20],
            ['finance-db-01', null, 'TLS 1.0 still enabled', 'A legacy database listener accepts TLS 1.0 connections.', 'Medium', 5.3, 'In Progress', 8],
        ];
        $vulnerabilityStatement = $pdo->prepare(
            'INSERT INTO vulnerabilities (asset_id, cve, title, description, severity, cvss, status, detected_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)'
        );
        foreach ($vulnerabilities as $vulnerability) {
            [$hostname, $cve, $title, $description, $severity, $cvss, $status, $daysAgo] = $vulnerability;
            $vulnerabilityStatement->execute([$assetIds[$hostname], $cve, $title, $description, $severity, $cvss, $status, date('Y-m-d H:i:s', strtotime('-' . $daysAgo . ' days'))]);
        }

        $settings = [
            'display_name' => 'Watch-U Security Operations',
            'telegram_enabled' => '0',
            'telegram_chat_id' => '',
            'alert_min_severity' => 'High',
            'nmap_allowed_cidrs' => "192.168.56.0/24\n10.10.10.0/24",
            'dedupe_window_minutes' => '15',
            'system_timezone' => 'Asia/Kuala_Lumpur',
        ];
        $settingStatement = $pdo->prepare('INSERT INTO settings (setting_key, setting_value, updated_by) VALUES (?, ?, ?)');
        foreach ($settings as $key => $value) {
            $settingStatement->execute([$key, $value, $securityId]);
        }

        $pdo->commit();
    } catch (Throwable $exception) {
        $pdo->rollBack();
        throw $exception;
    }
}
