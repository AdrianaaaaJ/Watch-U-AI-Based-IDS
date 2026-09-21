<section class="error-card"><span class="error-code"><?= (int) $status ?></span><span class="kicker">REQUEST STOPPED</span><h1><?= e($heading) ?></h1><p><?= e($message) ?></p><a class="button button-primary" href="<?= e(url(Auth::check() ? 'dashboard' : 'login')) ?>">Return to safety</a></section>

