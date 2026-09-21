<div class="page-heading">
    <div><span class="kicker">ATTACK SURFACE</span><h1>Assets</h1><p>Systems monitored by Watch-U and their current exposure profile.</p></div>
    <span class="data-freshness"><span></span><?= count($assets) ?> inventoried</span>
</div>
<form class="filter-bar compact-filter" method="get" action="index.php"><input type="hidden" name="page" value="assets"><label class="search-field"><span>⌕</span><input type="search" name="q" value="<?= e($query) ?>" placeholder="Search hostname, IP, owner or operating system"></label><button class="button button-secondary" type="submit">Search inventory</button><?php if ($query !== ''): ?><a class="clear-filter" href="<?= e(url('assets')) ?>">Clear</a><?php endif; ?></form>
<section class="asset-grid">
    <?php if ($assets === []): ?><article class="panel empty-state asset-empty-state">No asset records yet.</article><?php endif; ?>
    <?php foreach ($assets as $asset): ?>
        <article class="asset-card">
            <div class="asset-card-head"><span class="asset-large-icon">⌘</span><span class="asset-state"><i class="<?= strtolower($asset['status']) ?>"></i><?= e($asset['status']) ?></span></div>
            <h2><?= e($asset['hostname']) ?></h2><span class="mono"><?= e($asset['ip_address']) ?></span>
            <dl><div><dt>Operating system</dt><dd><?= e($asset['operating_system']) ?></dd></div><div><dt>Owner</dt><dd><?= e($asset['owner']) ?></dd></div><div><dt>Criticality</dt><dd><span class="severity-pill <?= severity_class($asset['criticality']) ?>"><?= e($asset['criticality']) ?></span></dd></div><div><dt>Last seen</dt><dd><?= e(format_datetime($asset['last_seen'], 'd M, H:i')) ?></dd></div></dl>
            <div class="asset-card-foot"><span><strong><?= (int) $asset['vulnerability_count'] ?></strong> total findings</span><span><strong class="danger-text"><?= (int) $asset['high_risk_count'] ?></strong> high risk</span></div>
        </article>
    <?php endforeach; ?>
</section>
