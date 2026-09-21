<section class="auth-card">
    <div class="auth-heading">
        <span class="kicker">ANALYST ENROLMENT</span>
        <h1>Create your account</h1>
        <p>Public enrolment creates an Analyst account. Elevated access must be assigned by Security Department staff.</p>
    </div>
    <?php if (!empty($errors)): ?>
        <div class="validation-errors" role="alert">
            <?php foreach ($errors as $error): ?><p><?= e($error) ?></p><?php endforeach; ?>
        </div>
    <?php endif; ?>
    <form method="post" action="<?= e(url('register')) ?>" class="stacked-form">
        <?= Csrf::field() ?>
        <label>Full name<input type="text" name="name" value="<?= e($values['name'] ?? '') ?>" minlength="2" maxlength="80" autocomplete="name" required autofocus></label>
        <label>Email address<input type="email" name="email" value="<?= e($values['email'] ?? '') ?>" maxlength="160" autocomplete="email" required></label>
        <label>Password<input type="password" name="password" minlength="12" autocomplete="new-password" aria-describedby="password-help" required><small id="password-help">Use 12+ characters with uppercase, lowercase, a number and a symbol.</small></label>
        <label>Confirm password<input type="password" name="password_confirmation" minlength="12" autocomplete="new-password" required></label>
        <button class="button button-primary button-wide" type="submit">Create Analyst account <span>→</span></button>
    </form>
    <p class="auth-switch">Already enrolled? <a href="<?= e(url('login')) ?>">Sign in</a></p>
</section>

