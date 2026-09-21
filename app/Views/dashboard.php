<div class="page-heading">
    <div><span class="kicker">WORKSPACE OVERVIEW</span><h1>Security posture</h1><p>Incidents imported from security alerts appear here.</p></div>
    <div class="page-actions"><span class="data-freshness"><span></span><?= $dashboard['events'] > 0 ? 'Incident data available' : 'Waiting for alerts' ?></span><a class="button button-secondary" href="<?= e(url('dashboard')) ?>">Refresh</a></div>
</div>

<section class="metric-grid">
    <article class="metric-card accent-critical"><span class="metric-label">Critical incidents</span><strong><?= number_format($dashboard['critical_incidents']) ?></strong><small>requiring priority review</small><span class="metric-symbol">!</span></article>
    <article class="metric-card accent-warning"><span class="metric-label">Active incidents</span><strong><?= number_format($dashboard['open_incidents']) ?></strong><small><?= number_format($dashboard['events']) ?> correlated events</small><span class="metric-symbol">⌁</span></article>
    <article class="metric-card accent-purple"><span class="metric-label">Open vulnerabilities</span><strong><?= number_format($dashboard['vulnerabilities']) ?></strong><small>across managed assets</small><span class="metric-symbol">◇</span></article>
    <article class="metric-card accent-teal"><span class="metric-label">Monitored assets</span><strong><?= number_format($dashboard['assets']) ?></strong><small>inventory coverage</small><span class="metric-symbol">⌘</span></article>
</section>

<section class="dashboard-grid">
    <article class="panel panel-span-2">
        <div class="panel-heading"><div><span class="kicker">EVENT VOLUME</span><h2>Seven-day signal trend</h2></div><span class="panel-badge"><?= $dashboard['events'] > 0 ? 'INCIDENT DATA' : 'NO DATA YET' ?></span></div>
        <div class="chart-wrap"><canvas data-line-chart aria-label="Incident event trend chart"></canvas></div>
        <script type="application/json" id="trend-data" nonce="<?= e(csp_nonce()) ?>"><?= json_encode($dashboard['trend'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
    </article>
    <article class="panel">
        <div class="panel-heading"><div><span class="kicker">SEVERITY MIX</span><h2>Incident risk</h2></div></div>
        <div class="donut-layout">
            <div class="donut-wrap"><canvas data-donut-chart aria-label="Incident severity chart"></canvas><span><strong><?= array_sum($dashboard['severity']) ?></strong><small>INCIDENTS</small></span></div>
            <div class="chart-legend">
                <?php foreach (['Critical', 'High', 'Medium', 'Low'] as $severity): ?>
                    <div><i class="legend-dot <?= severity_class($severity) ?>"></i><span><?= e($severity) ?></span><strong><?= $dashboard['severity'][$severity] ?></strong></div>
                <?php endforeach; ?>
            </div>
        </div>
        <script type="application/json" id="severity-data" nonce="<?= e(csp_nonce()) ?>"><?= json_encode($dashboard['severity'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
    </article>
</section>

<section class="dashboard-grid lower-grid">
    <article class="panel panel-span-2">
        <div class="panel-heading"><div><span class="kicker">LATEST ACTIVITY</span><h2>Incident queue</h2></div><a href="<?= e(url('incidents')) ?>">View all →</a></div>
        <div class="table-wrap">
            <table><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Events</th><th>Last seen</th></tr></thead><tbody>
            <?php if ($dashboard['recent'] === []): ?><tr><td colspan="5" class="empty-state">No incidents yet. Start the live reader and generate a Wazuh alert to test the feed.</td></tr><?php endif; ?>
            <?php foreach ($dashboard['recent'] as $incident): ?>
                <tr><td><strong><?= e($incident['title']) ?></strong><small><?= e($incident['source']) ?> · <?= e($incident['src_ip'] ?: 'local host') ?></small></td><td><span class="severity-pill <?= severity_class($incident['severity']) ?>"><?= e($incident['severity']) ?></span></td><td><span class="status-pill"><?= e($incident['status']) ?></span></td><td><?= number_format((int) $incident['event_count']) ?></td><td><?= e(format_datetime($incident['last_seen'], 'd M H:i')) ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        </div>
    </article>
    <article class="panel">
        <div class="panel-heading"><div><span class="kicker">EXPOSURE</span><h2>Assets at risk</h2></div><a href="<?= e(url('assets')) ?>">Inventory →</a></div>
        <div class="risk-list">
            <?php if ($dashboard['top_assets'] === []): ?><p class="empty-state">No asset records yet.</p><?php endif; ?>
            <?php foreach ($dashboard['top_assets'] as $asset): ?>
                <div class="risk-row"><span class="asset-icon">⌘</span><span><strong><?= e($asset['hostname']) ?></strong><small><?= e($asset['ip_address']) ?></small></span><span class="risk-score"><strong><?= e(number_format((float) $asset['max_cvss'], 1)) ?></strong><small><?= (int) $asset['vulnerability_count'] ?> findings</small></span></div>
            <?php endforeach; ?>
        </div>
    </article>
</section>
