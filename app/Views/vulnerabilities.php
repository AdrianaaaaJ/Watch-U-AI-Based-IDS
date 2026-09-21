<div class="page-heading">
    <div><span class="kicker">EXPOSURE MANAGEMENT</span><h1>Vulnerabilities</h1><p>Prioritised technical findings mapped to the asset inventory.</p></div>
    <div class="page-actions"><a class="button button-primary" href="<?= e(url('export', ['kind' => 'vulnerabilities'] + $filters)) ?>">Download CSV</a></div>
</div>

<form class="filter-bar" method="get" action="index.php">
    <input type="hidden" name="page" value="vulnerabilities">
    <input type="hidden" name="severity" value="<?= e($filters['severity']) ?>">
    <div class="filter-controls"><label class="search-field"><span>⌕</span><input type="search" name="q" value="<?= e($filters['q']) ?>" placeholder="Search CVE, finding, host or IP"></label><label class="status-filter"><span>Status</span><select name="status"><option value="">All statuses</option><?php foreach (['Open', 'In Progress', 'Accepted', 'Remediated'] as $value): ?><option<?= selected($filters['status'], $value) ?>><?= e($value) ?></option><?php endforeach; ?></select></label><button class="button button-secondary" type="submit">Search</button><a class="clear-filter" href="<?= e(url('vulnerabilities')) ?>">Reset</a></div>
    <div class="severity-filter" role="group" aria-label="Filter vulnerabilities by severity"><span>Severity</span><?php foreach (['' => 'All', 'Critical' => 'Critical', 'High' => 'High', 'Medium' => 'Medium', 'Low' => 'Low'] as $value => $label): ?><?php $params = array_filter(array_merge($filters, ['severity' => $value]), static fn ($item) => $item !== ''); ?><a class="severity-button<?= $filters['severity'] === $value ? ' active' : '' ?><?= $value !== '' ? ' ' . severity_class($value) : '' ?>" href="<?= e(url('vulnerabilities', $params)) ?>"<?= $filters['severity'] === $value ? ' aria-current="page"' : '' ?>><?= e($label) ?></a><?php endforeach; ?></div>
</form>

<section class="panel">
    <div class="panel-heading"><div><span class="kicker">FINDING REGISTER</span><h2><?= count($vulnerabilities) ?> findings</h2></div><span class="panel-badge">CVSS PRIORITY</span></div>
    <div class="table-wrap"><table><thead><tr><th>CVSS</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Status</th><th>Detected</th></tr></thead><tbody>
        <?php if ($vulnerabilities === []): ?><tr><td colspan="6" class="empty-state">No vulnerabilities match these filters.</td></tr><?php endif; ?>
        <?php foreach ($vulnerabilities as $finding): ?>
            <tr><td><span class="score-box <?= severity_class($finding['severity']) ?>"><?= e(number_format((float) $finding['cvss'], 1)) ?></span></td><td><strong><?= e($finding['title']) ?></strong><small><?= e($finding['cve'] ?: 'Configuration finding') ?></small><p class="table-description"><?= e($finding['description']) ?></p></td><td><strong><?= e($finding['hostname']) ?></strong><small class="mono"><?= e($finding['ip_address']) ?></small></td><td><span class="severity-pill <?= severity_class($finding['severity']) ?>"><?= e($finding['severity']) ?></span></td><td><span class="status-pill"><?= e($finding['status']) ?></span></td><td><?= e(format_datetime($finding['detected_at'], 'd M Y')) ?></td></tr>
        <?php endforeach; ?>
    </tbody></table></div>
</section>
