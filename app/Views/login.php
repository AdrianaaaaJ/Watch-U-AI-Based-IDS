<section class="auth-card">
    <div class="auth-heading">
        <span class="kicker">SECURE ACCESS</span>
        <h1>Welcome back</h1>
        <p>Sign in when your team is ready to begin using the Watch-U workspace.</p>
    </div>
    <?php if (!empty($errors)): ?>
        <div class="validation-errors" role="alert">
            <?php foreach ($errors as $error): ?><p><?= e($error) ?></p><?php endforeach; ?>
        </div>
    <?php endif; ?>
    <form method="post" action="<?= e(url('login')) ?>" class="stacked-form">
        <?= Csrf::field() ?>
        <label>Email address<input type="email" name="email" value="<?= e($email ?? '') ?>" autocomplete="email" required autofocus></label>
        <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        <button class="button button-primary button-wide" type="submit">Sign in securely <span>&rarr;</span></button>
    </form>
    <p class="auth-switch">New to Watch-U? <a href="<?= e(url('register')) ?>">Create an Analyst account</a></p>
</section>
<aside class="demo-credentials draft-note">
    <span class="status-dot"></span>
    <div><strong>Account access</strong><p>Public registration creates an Analyst account. Security Department access is assigned by an existing administrator.</p></div>
</aside>
