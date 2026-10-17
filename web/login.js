'use strict';
(function () {
    const $ = (id) => document.getElementById(id);

    function show(id, msg) {
        const el = $(id);
        el.textContent = msg;               // textContent: server text is never parsed as HTML
        el.classList.remove('hidden');
    }
    function clearMessages() {
        $('register-error').classList.add('hidden');
        $('login-error').classList.add('hidden');
    }
    function resetToggles() {
        document.querySelectorAll('.pw-toggle').forEach((b) => {
            $(b.dataset.for).type = 'password';
            b.textContent = 'Show';
            b.setAttribute('aria-pressed', 'false');
        });
    }
    // after sign-up the way forward is locked until the person says the login code is saved (no e-mail: lost = lost)
    function lockContinue(on) {
        const b = $('btn-to-login');
        b.textContent = on ? 'Continue to log in' : 'Already have an account? Log in';
        b.classList.toggle('key', on);
        b.classList.toggle('switch-btn', !on);
        b.disabled = on;
        $('saved-ack').checked = false;
        $('copy-status').textContent = '';
    }
    function switchTo(which) {
        clearMessages();
        resetToggles();
        $('register-form').classList.toggle('hidden', which !== 'register');
        $('login-form').classList.toggle('hidden', which !== 'login');
        $('drive-title').textContent = 'A:\\' + which;
        if (which === 'register') {
            $('register-success').classList.add('hidden');
            $('register-fields').classList.remove('hidden');
            lockContinue(false);
        }
    }

    async function post(url, body) {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'same-origin',
        });
        let data = {};
        try { data = await r.json(); } catch (e) { /* non-JSON error page */ }
        return data;
    }

    let registeredAs = '';

    async function copyCode() {
        const code = $('unique-code').textContent;
        let ok = false;
        try { await navigator.clipboard.writeText(code); ok = true; } catch (e) { /* plain http, or refused */ }
        if (!ok) {
            try {
                const range = document.createRange();
                range.selectNodeContents($('unique-code'));
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                ok = document.execCommand('copy');
            } catch (e) { /* ignore */ }
        }
        $('copy-status').textContent = ok ? 'Copied.' : 'Could not copy. Select the code and copy it yourself.';
    }

    function downloadCode() {
        const text = ['Terminet.IRC login code', '', 'Username:   ' + registeredAs, 'Login code: ' + $('unique-code').textContent, '',
            'Keep this file private. You need the code and your password to log in.',
            'There is no recovery: the server cannot show the code again.', ''].join('\r\n');
        const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = 'terminet-login-code.txt';
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    async function register() {
        clearMessages();
        const username = $('reg-username').value.trim();
        const password = $('reg-password').value;
        if (!username || !password) return show('register-error', 'Username and password are required.');
        if (password.length < 8) return show('register-error', 'Password must be at least 8 characters.');
        try {
            const data = await post('/api/register', { username, password });
            if (data.success) {
                $('register-fields').classList.add('hidden');
                $('register-success').classList.remove('hidden');
                $('unique-code').textContent = data.unique_code;
                $('reg-password').value = '';
                registeredAs = data.username || username;
                $('reg-tag').textContent = registeredAs;
                resetToggles();
                lockContinue(true);
            } else {
                show('register-error', data.message || 'Registration failed.');
            }
        } catch (e) {
            show('register-error', 'An error occurred. Please try again.');
        }
    }

    async function login() {
        clearMessages();
        const unique_code = $('login-code').value.trim();
        const password = $('login-password').value;
        if (!unique_code || !password) return show('login-error', 'Unique code and password are required.');
        try {
            const data = await post('/api/login', { unique_code, password });
            if (data.success) {
                window.location.href = '/chat';      // session cookie is already set (HttpOnly)
            } else {
                show('login-error', data.message || 'Login failed.');
            }
        } catch (e) {
            show('login-error', 'An error occurred. Please try again.');
        }
    }

    $('btn-register').addEventListener('click', register);
    $('btn-login').addEventListener('click', login);
    $('btn-to-login').addEventListener('click', () => { if (!$('btn-to-login').disabled) switchTo('login'); });
    $('saved-ack').addEventListener('change', () => { $('btn-to-login').disabled = !$('saved-ack').checked; });
    $('btn-copy-code').addEventListener('click', copyCode);
    $('btn-download-code').addEventListener('click', downloadCode);
    document.querySelectorAll('.pw-toggle').forEach((b) => b.addEventListener('click', () => {
        const input = $(b.dataset.for);
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        b.textContent = show ? 'Hide' : 'Show';
        b.setAttribute('aria-pressed', String(show));
    }));
    $('btn-to-register').addEventListener('click', () => switchTo('register'));
    for (const [id, fn] of [['reg-username', register], ['reg-password', register],
                            ['login-code', login], ['login-password', login]]) {
        $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.isComposing && e.keyCode !== 229) fn(); });
    }

    // already signed in? skip the login screen
    fetch('/api/me', { credentials: 'same-origin' })
        .then((r) => { if (r.ok) window.location.href = '/chat'; })
        .catch(() => { });
})();
