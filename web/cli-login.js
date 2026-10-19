'use strict';
/* The CLI theme's sign-in: a prompt instead of a form. Same endpoints as login.js (/api/register, /api/login), same
   rule that you must say the login code is saved before moving on. Text reaches the DOM only as text. */
(function () {
    const $ = (id) => document.getElementById(id);
    const log = $('tty-log'), input = $('tty-in'), label = $('tty-prompt');
    const cli = () => document.documentElement.dataset.theme === 'cli';
    let busy = false;
    let asking = null;                 // {resolve} while a question is open
    let saved = { code: '', name: '', ack: true };
    const hist = [];
    let at = 0;

    function say(text, cls) {
        const row = document.createElement('div');
        row.className = 'tty-row' + (cls ? ' ' + cls : '');
        row.textContent = text;
        log.append(row);
        log.scrollTop = log.scrollHeight;
    }
    function ask(text, hidden) {
        return new Promise((resolve) => {
            asking = { resolve };
            label.textContent = text;
            input.type = hidden ? 'password' : 'text';
            input.value = '';
            input.focus();
        });
    }
    const idle = () => { label.textContent = saved.ack ? 'guest> ' : 'guest (save your code)> '; input.type = 'text'; };

    async function post(url, body) {
        try {
            const r = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            return await r.json();
        } catch (e) { return { success: false, message: 'could not reach the server' }; }
    }

    async function register(name) {
        name = name || await ask('username: ', false);
        if (!name) return say('cancelled');
        const pw = await ask('password (8+ characters): ', true);
        if (!pw) return say('cancelled');
        if (pw.length < 8) return say('error: password must be at least 8 characters', 'err');
        const d = await post('/api/register', { username: name.trim(), password: pw });
        if (!d.success) return say('error: ' + (d.message || 'registration failed'), 'err');
        saved = { code: d.unique_code, name: d.username || name, ack: false };
        say('account created. your name is ' + saved.name);
        say('login code: ' + saved.code, 'code');
        say('Save it now. You need it with your password to log in. There is no recovery, and the server cannot show it again.\ncommands: copy, save (a .txt file), saved (when it is safe)');
    }
    async function login(code) {
        if (!saved.ack) return say('error: say "saved" first. the code cannot be shown again', 'err');
        code = code || await ask('login code: ', false);
        if (!code) return say('cancelled');
        const pw = await ask('password: ', true);
        if (!pw) return say('cancelled');
        const d = await post('/api/login', { unique_code: code.trim(), password: pw });
        if (d.success) { say('ok'); location.href = '/chat'; } else say('error: ' + (d.message || 'login failed'), 'err');
    }
    async function copy() {
        if (!saved.code) return say('nothing to copy');
        try { await navigator.clipboard.writeText(saved.code); say('copied'); } catch (e) { say('could not copy. select the code above and copy it yourself'); }
    }
    function download() {
        if (!saved.code) return say('nothing to save');
        const text = ['Terminet.IRC login code', '', 'Username:   ' + saved.name, 'Login code: ' + saved.code, '',
            'Keep this file private. You need the code and your password to log in.',
            'There is no recovery: the server cannot show the code again.', ''].join('\r\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
        a.download = 'terminet-login-code.txt';
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }

    const HELP = ['register [name]   make an account (asks for a password)', 'login [code]      sign in (asks for the password)',
        'copy | save | saved   after registering: copy the code, save it as a file, say it is safe',
        'theme [name]      modern, classic or cli', 'clear            wipe the screen'].join('\n');

    async function run(line) {
        const [cmd, ...rest] = line.trim().split(/\s+/);
        const arg = rest.join(' ');
        switch ((cmd || '').toLowerCase()) {
            case '': return;
            case 'help': case '?': return say(HELP);
            case 'clear': log.replaceChildren(); return;
            case 'register': return register(arg);
            case 'login': return login(arg);
            case 'copy': return copy();
            case 'save': return download();
            case 'saved': saved.ack = true; return say('ok. now: login ' + (saved.code || ''));
            case 'theme': {
                const T = window.TNTheme;
                if (!arg) return say('theme: ' + T.get() + '   (' + T.list.join(', ') + ')');
                return T.set(arg.toLowerCase()) ? undefined : say('error: no such theme. try: ' + T.list.join(', '), 'err');
            }
            default: return say('error: unknown command "' + cmd + '". type help', 'err');
        }
    }

    input.addEventListener('keydown', async (e) => {
        if (e.isComposing || e.keyCode === 229) return;
        if (e.key === 'Escape' && asking) { const a = asking; asking = null; input.value = ''; a.resolve(null); return; }
        if (e.key === 'ArrowUp' && !asking && at > 0) { e.preventDefault(); input.value = hist[--at]; return; }
        if (e.key === 'ArrowDown' && !asking && at < hist.length) { e.preventDefault(); input.value = ++at < hist.length ? hist[at] : ''; return; }
        if (e.key !== 'Enter') return;
        e.preventDefault();
        const v = input.value;
        input.value = '';
        if (asking) {
            const a = asking;
            asking = null;
            say(label.textContent + (input.type === 'password' ? '' : v), 'echo');
            a.resolve(v);
            return;
        }
        if (busy) return;
        say(label.textContent + v, 'echo');
        if (v.trim()) { hist.push(v.trim()); at = hist.length; }
        busy = true;
        try { await run(v); } finally { busy = false; idle(); input.focus(); }
    });
    document.addEventListener('tn:theme', () => { if (cli()) { input.focus(); if (!log.childElementCount) say('Terminet.IRC. no e-mail, no tracking. type help.'); } });
    $('tty').addEventListener('click', () => { if (cli() && !String(getSelection())) input.focus(); });

    idle();
    say('Terminet.IRC. no e-mail, no tracking. type help.');
    if (cli()) input.focus();
})();
