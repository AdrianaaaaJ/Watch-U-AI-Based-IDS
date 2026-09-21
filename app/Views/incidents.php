<div class="page-heading">
    <div><span class="kicker">DETECTION & RESPONSE</span><h1>Incidents</h1><p>Correlated alerts are grouped by fingerprint to keep the investigation queue actionable.</p></div>
    <div class="page-actions"><a class="button button-primary" href="<?= e(url('export', ['kind' => 'incidents'] + $filters)) ?>">Download CSV</a></div>
</div>

<form class="filter-bar" method="get" action="index.php">
    <input type="hidden" name="page" value="incidents">
    <input type="hidden" name="severity" value="<?= e($filters['severity']) ?>">
    <div class="filter-controls"><label class="search-field"><span>⌕</span><input type="search" name="q" value="<?= e($filters['q']) ?>" placeholder="Search title, IP, category or source"></label><label class="status-filter"><span>Status</span><select name="status"><option value="">All statuses</option><?php foreach (['Open', 'Investigating', 'Contained', 'Resolved', 'False Positive'] as $value): ?><option<?= selected($filters['status'], $value) ?>><?= e($value) ?></option><?php endforeach; ?></select></label><button class="button button-secondary" type="submit">Search</button><a class="clear-filter" href="<?= e(url('incidents')) ?>">Reset</a></div>
    <div class="severity-filter" role="group" aria-label="Filter incidents by severity"><span>Severity</span><?php foreach (['' => 'All', 'Critical' => 'Critical', 'High' => 'High', 'Medium' => 'Medium', 'Low' => 'Low'] as $value => $label): ?><?php $params = array_filter(array_merge($filters, ['severity' => $value]), static fn ($item) => $item !== ''); ?><a class="severity-button<?= $filters['severity'] === $value ? ' active' : '' ?><?= $value !== '' ? ' ' . severity_class($value) : '' ?>" href="<?= e(url('incidents', $params)) ?>"<?= $filters['severity'] === $value ? ' aria-current="page"' : '' ?>><?= e($label) ?></a><?php endforeach; ?></div>
</form>

<section class="panel">
    <div class="panel-heading"><div><span class="kicker">CORRELATED QUEUE</span><h2><?= count($incidents) ?> incidents</h2></div><span class="panel-badge">SCORED 0–100</span></div>
    <div class="table-wrap incidents-table">
        <table><thead><tr><th>Risk</th><th>Detection</th><th>Network context</th><th>Events</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
        <?php if ($incidents === []): ?><tr><td colspan="6" class="empty-state">No incidents match these filters.</td></tr><?php endif; ?>
        <?php foreach ($incidents as $incident): ?>
            <tr>
                <td><span class="score-box <?= severity_class($incident['severity']) ?>"><?= (int) $incident['score'] ?></span><small><?= e($incident['severity']) ?></small></td>
                <td class="incident-title"><strong><?= e($incident['title']) ?></strong><small><?= e($incident['source']) ?> · <?= e($incident['category']) ?></small><details><summary>AI-ready summary</summary><p><?= e($incident['summary']) ?></p><small>Provider: <?= e($incident['summary_provider']) ?></small></details></td>
                <td><span class="mono"><?= e($incident['src_ip'] ?: 'local') ?></span><small>→ <?= e($incident['dest_ip'] ?: 'host event') ?></small></td>
                <td><strong><?= number_format((int) $incident['event_count']) ?></strong><small><?= (int) $incident['event_count'] > 1 ? 'deduplicated' : 'unique' ?></small></td>
                <td><?= e(format_datetime($incident['last_seen'], 'd M H:i')) ?><small>First: <?= e(format_datetime($incident['first_seen'], 'd M H:i')) ?></small></td>
                <td>
                    <form method="post" action="<?= e(url('incident-status')) ?>" class="inline-status-form">
                        <?= Csrf::field() ?><input type="hidden" name="incident_id" value="<?= (int) $incident['id'] ?>">
                        <select name="status" aria-label="Status for <?= e($incident['title']) ?>" data-auto-submit><?php foreach (['Open', 'Investigating', 'Contained', 'Resolved', 'False Positive'] as $value): ?><option<?= selected($incident['status'], $value) ?>><?= e($value) ?></option><?php endforeach; ?></select>
                        <button class="sr-only" type="submit">Update</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody></table>
    </div>
</section>
