<div class="page-heading"><div><span class="kicker">EVIDENCE & REPORTING</span><h1>Reports</h1><p>Download incident and vulnerability records as CSV files.</p></div></div>

<section class="report-grid simple-reports">
    <article class="report-card">
        <span class="report-icon">!</span>
        <div><span class="kicker">INCIDENT REGISTER</span><h2>Incident operations report</h2><p>Export detection, severity, network context and response status from the current database.</p></div>
        <div class="report-actions"><a class="button button-primary" href="<?= e(url('export', ['kind' => 'incidents'])) ?>">Download CSV</a></div>
    </article>
    <article class="report-card">
        <span class="report-icon purple">◇</span>
        <div><span class="kicker">EXPOSURE REGISTER</span><h2>Vulnerability exposure report</h2><p>Export affected assets, CVSS priority and remediation progress from the current database.</p></div>
        <div class="report-actions"><a class="button button-primary" href="<?= e(url('export', ['kind' => 'vulnerabilities'])) ?>">Download CSV</a></div>
    </article>
</section>

<section class="panel report-note"><span class="nav-icon">i</span><div><strong>CSV exports</strong><p>Open the files in HeidiSQL, Excel or another spreadsheet tool. Exports work even when there are no records.</p></div></section>
