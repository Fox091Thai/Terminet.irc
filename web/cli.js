'use strict';
/*
 * Extra slash commands (they work in every theme) and the terminal layer of the CLI theme: prompt, history, Tab,
 * masked questions. Everything goes through chat.js's own socket and endpoints (window.TN); nothing here is trusted
 * more than a button click would be, the server checks every action again. Text reaches the DOM only as text.
 */
(function () {
    const TN = window.TN;
    if (!TN) return;
    const $ = (id) => document.getElementById(id);
    const cli = () => document.documentElement.dataset.theme === 'cli';
    const say = (t) => TN.notice(t);
    const bad = (t) => { TN.notice('error: ' + t); return false; };
    const state = () => TN.state;

    let sock = null;
    let servers = [];                 // {id, name, code, owned}
    let rooms = [];                   // rooms of the open server
    let pending = null;               // {fn, expect}: waits for /yes
    let wantRooms = false;
    const waits = {};                 // one-shot callbacks for members / bans / invites
    const told = new Set();           // rooms already announced as active

    /* ------------------------------------------------------------ helpers */
    const rows = (head, list) => say([head].concat(list).join('\n'));
    function pick(list, arg, what) {
        const q = String(arg || '').replace(/^#/, '').trim().toLowerCase();
        if (!q) return bad('say which ' + what + ': a number or a name');
        if (/^\d+$/.test(q)) return list[Number(q) - 1] || bad('there is no ' + what + ' number ' + q);
        const hit = list.filter((x) => x.name.toLowerCase() === q);
        const part = hit.length ? hit : list.filter((x) => x.name.toLowerCase().startsWith(q));
        return part.length === 1 ? part[0] : bad(part.length ? 'more than one ' + what + ' fits: ' + part.map((x) => x.name).join(', ') : 'no ' + what + ' called ' + arg);
    }
    function needServer(owner) {
        const s = state().server;
        if (!s) return bad('open a server first (/servers, then /open <n>)');
        if (owner && s.owner_id !== state().me.user_id) return bad('only the server owner can do that');
        return s;
    }
    function ask(text, fn, expect) {
        pending = { fn, expect: expect || null };
        say(text + '\n  type /yes' + (expect ? ' ' + expect : '') + ' to go ahead; anything else cancels');
    }
    function who(list, arg) {
        const q = String(arg || '').trim().toLowerCase();
        if (!q) return bad('say who: a name, or name[#00001] when two people share one');
        let hit = list.filter((m) => m.name.toLowerCase() === q);
        if (!hit.length) hit = list.filter((m) => TN.plain(m.name).toLowerCase() === q);
        if (hit.length === 1) return hit[0];
        return bad(hit.length ? 'more than one ' + arg + ': ' + hit.map((m) => m.name).join(', ') + ' (use the full name with the number)' : 'nobody called ' + arg);
    }
    function lookup(kind, event, fn) {          // ask the server for a list and hand it to fn once
        const s = needServer();
        if (!s) return;
        waits[kind] = fn;
        sock.emit(event, { server_id: s.id });
    }
    const left = (unix) => {
        const s = unix - Date.now() / 1000;
        return s < 3600 ? Math.max(1, Math.round(s / 60)) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' d';
    };
    function printRooms() {
        const cur = state().roomId;
        if (!rooms.length) return say('no rooms');
        rows('rooms:', rooms.map((r, i) => String(i + 1).padStart(2) + '  #' + r.name.replace(/\s*\[Read-only\]$/i, '') +
            (r.is_locked === 4 ? '  [read-only]' : r.is_locked === 1 ? '  [locked]' : '') + (r.topic ? '  - ' + r.topic : '') + (r.id === cur ? '  <- here' : '')));
    }
    const kindOf = new Map([['everyone', 0], ['owner', 1], ['none', 4]]);
    const hoursOf = new Map([['off', 0], ['0', 0], ['1h', 1], ['1', 1], ['24h', 24], ['24', 24], ['7d', 168], ['168', 168]]);

    /* ----------------------------------------------------------- commands */
    const help = TN.help;
    function cmd(name, usage, text, fn) {
        TN.cmds[name] = fn;
        help.push(('/' + name.slice(1) + (usage ? ' ' + usage : '')).padEnd(26) + text);
    }
    help.push('*** MORE COMMANDS ***');

    cmd('/servers', '', 'your servers, numbered', () => {
        if (!servers.length) return say('no servers yet: /newserver <name> or /joinserver <code>');
        const cur = state().server;
        rows('servers:', servers.map((s, i) => String(i + 1).padStart(2) + '  ' + s.name + (s.owned ? '  (owner, code ' + s.code + ')' : '') + (cur && cur.id === s.id ? '  <- open' : '')));
    });
    cmd('/open', '<n|name>', 'open a server, list its rooms', (a) => {
        const s = pick(servers, a, 'server');
        if (s) { wantRooms = true; sock.emit('get_server_data', { server_id: s.id }); }
    });
    cmd('/rooms', '', 'rooms of this server', () => { if (needServer()) printRooms(); });
    cmd('/join', '<n|name>', 'enter a room of this server', (a) => {
        if (!needServer()) return;
        const r = pick(rooms, a, 'room');
        if (r) sock.emit('join_room', { room_id: r.id });
    });
    cmd('/who', '', 'who is in this room right now', () => {
        const st = state();
        if (!st.roomId) return bad('join a room first');
        say('in this room (' + st.users.length + '): ' + st.users.map((u) => u.name).join(', '));
    });
    cmd('/members', '', 'everyone in this server, roles, online', () => lookup('members', 'get_members', (list) =>
        rows('members (' + list.length + '):', list.map((m) => (m.online ? '* ' : '  ') + m.name + (m.role !== 'member' ? '  [' + m.role + ']' : '')))));
    cmd('/whoami', '', 'your name, server, room', () => {
        const st = state();
        say(st.me.username + (st.server ? ' on ' + st.server.name + ' (' + (st.server.role || 'member') + ')' : '') + (st.roomId ? ', room open' : ''));
    });
    cmd('/code', '', 'the permanent code of this server (owner)', () => {
        const s = needServer(true);
        const x = s && servers.find((v) => v.id === s.id);
        if (x) say('server code: ' + x.code);
    });
    cmd('/newserver', '<name>', 'create a server', (a) => (a ? sock.emit('create_server', { name: a }) : bad('usage: /newserver <name>')));
    cmd('/joinserver', '<code>', 'join a server with its code', (a) => (a ? sock.emit('join_server', { server_code: a }) : bad('usage: /joinserver <code>')));
    cmd('/leave', '', 'leave this server', () => {
        const s = needServer();
        if (s) ask('Leave "' + s.name + '"?', () => sock.emit('leave_server', { server_id: s.id }));
    });
    cmd('/delserver', '', 'delete this server for good (owner)', () => {
        const s = needServer(true);
        if (s) ask('Delete "' + s.name + '"? This is permanent.', () => sock.emit('delete_server', { server_id: s.id }));
    });
    cmd('/newroom', '<name>', 'create a room (owner)', (a) => {
        const s = needServer(true);
        if (s) a ? sock.emit('create_room', { server_id: s.id, room_name: a }) : bad('usage: /newroom <name>');
    });
    cmd('/delroom', '[n|name]', 'delete a room, default this one (owner)', (a) => {
        if (!needServer(true)) return;
        const r = a ? pick(rooms, a, 'room') : rooms.find((x) => x.id === state().roomId);
        if (r) ask('Delete "#' + r.name + '"?', () => sock.emit('delete_room', { room_id: r.id }));
        else if (!a) bad('say which room');
    });
    cmd('/invite', '[hours] [uses]', 'make an invite code: hours 1, 24 or 168; uses 1, 10 or 0 = unlimited (default 24 10)', (a) => {
        const s = needServer(true);
        const [h, u] = a.split(/\s+/);
        const hours = h ? Number(h) : 24, uses = u === undefined || u === '' ? 10 : Number(u);
        if (!s) return;
        if (![1, 24, 168].includes(hours) || ![1, 10, 0].includes(uses)) return bad('usage: /invite [1|24|168 hours] [1|10|0 uses]   (0 = unlimited)');
        sock.emit('create_invite', { server_id: s.id, hours, uses });
    });
    cmd('/invites', '', 'active invite codes (owner)', () => {
        if (needServer(true)) lookup('invites', 'list_invites', (list) => (list.length ? rows('invite codes:', list.map((i) =>
            i.code + '  ' + (i.expires_at ? left(i.expires_at) + ' left' : 'no expiry') + ', ' + i.uses + '/' + (i.max_uses || '∞') + ' used')) : say('no active codes')));
    });
    cmd('/revoke', '<code>', 'revoke an invite code (owner)', (a) => {
        const s = needServer(true);
        if (s) a ? sock.emit('revoke_invite', { server_id: s.id, code: a.toUpperCase() }) : bad('usage: /revoke <code>');
    });
    const person = (name, usage, text, owner, act) => cmd(name, usage, text, (a) => {
        const s = needServer(owner);
        if (s) lookup('members', 'get_members', (list) => { const m = who(list, a); if (m) act(s, m); });
    });
    person('/kick', '<name>', 'remove someone, renews the code (staff)', false, (s, m) =>
        ask('Kick ' + m.name + '? They are removed; the server code is renewed and the invite codes are revoked.', () => sock.emit('kick_user', { server_id: s.id, user_id: m.user_id })));
    person('/ban', '<name>', 'ban someone (owner)', true, (s, m) =>
        ask('Ban ' + m.name + '? They cannot join again, even with a valid code, until you lift the ban.', () => sock.emit('ban_user', { server_id: s.id, user_id: m.user_id })));
    person('/mod', '<name>', 'make a moderator (owner)', true, (s, m) => sock.emit('set_role', { server_id: s.id, user_id: m.user_id, role: 'moderator' }));
    person('/unmod', '<name>', 'back to member (owner)', true, (s, m) => sock.emit('set_role', { server_id: s.id, user_id: m.user_id, role: 'member' }));
    person('/owner', '<name>', 'hand the server over (owner)', true, (s, m) =>
        ask('Make ' + m.name + ' the owner of "' + s.name + '"? You stay a member but lose every owner right.',
            () => sock.emit('transfer_owner', { server_id: s.id, user_id: m.user_id, confirm: s.name }), s.name));
    cmd('/bans', '', 'who is banned (owner)', () => {
        if (needServer(true)) lookup('bans', 'get_bans', (list) => (list.length ? rows('banned:', list.map((b) => '  ' + b.name)) : say('nobody is banned')));
    });
    cmd('/unban', '<name>', 'lift a ban (owner)', (a) => {
        const s = needServer(true);
        if (s) lookup('bans', 'get_bans', (list) => { const b = who(list, a); if (b) sock.emit('unban_user', { server_id: s.id, user_id: b.user_id }); });
    });
    cmd('/kind', 'everyone|owner|none', 'who may write in this room (owner)', (a) => {
        if (!needServer(true) || !state().roomId) return;
        if (!kindOf.has(a)) return bad('usage: /kind everyone | owner | none');
        sock.emit('set_room_kind', { room_id: state().roomId, kind: kindOf.get(a) });
    });
    cmd('/retention', 'off|1h|24h|7d', 'delete messages after this long (owner)', (a) => {
        if (!needServer(true) || !state().roomId) return;
        if (!hoursOf.has(a.toLowerCase())) return bad('usage: /retention off | 1h | 24h | 7d');
        sock.emit('set_retention', { room_id: state().roomId, hours: hoursOf.get(a.toLowerCase()) });
    });
    function line(sid) {                        // the short id the CLI shows in front of a line -> the line
        const q = String(sid || '').replace(/^#/, '').toLowerCase();
        if (q.length < 4) return bad('give the id shown in front of the line (at least 4 characters)');
        const hit = Array.from($('chat-messages').querySelectorAll('.message[data-mid]')).filter((r) => r.dataset.mid.startsWith(q));
        return hit.length === 1 ? hit[0] : bad(hit.length ? 'that id fits more than one line, type more of it' : 'no line with that id on screen');
    }
    cmd('/reply', '<id> [text]', 'answer a line (its id shows in the CLI theme)', (a) => {
        const m = /^(#?[0-9a-f]+)(?:\s+([\s\S]+))?$/i.exec(a);
        if (!m) return bad('usage: /reply <id> [text]');
        const row = line(m[1]);
        if (!row) return;
        if (!m[2]) return TN.reply(row.dataset.mid);
        if (state().roomId && state().canWrite) sock.emit('send_message', { message: m[2], reply_to: row.dataset.mid });
        else bad('you cannot write here');
    });
    cmd('/del', '[id]', 'delete a line, default your last one', (a) => {
        const row = a ? line(a) : Array.from($('chat-messages').querySelectorAll('.message.mine[data-mid]')).pop();
        if (row) sock.emit('delete_message', { message_id: row.dataset.mid });
        else if (!a) bad('you have no line on screen');
    });
    cmd('/upload', '', 'pick a file to send (drag and drop works too)', () => TN.upload());
    cmd('/sound', '', 'beep on news in other rooms: on/off', () => { $('btn-sound').click(); say('sound ' + ($('btn-sound').getAttribute('aria-pressed') === 'true' ? 'on' : 'off')); });
    cmd('/theme', '[name]', 'modern, classic or cli', (a) => {
        const T = window.TNTheme;
        if (!a) return say('theme: ' + T.get() + '   (' + T.list.join(', ') + ')');
        if (!T.set(a.toLowerCase())) bad('no such theme. try: ' + T.list.join(', '));
    });
    cmd('/logout', '', 'sign out', () => TN.logout());

    /* things that need a secret: asked one by one, answer masked */
    const secret = $('cli-secret'), box = document.querySelector('.input-container');
    function question(label, hidden) {
        return new Promise((resolve) => {
            box.classList.add('asking');
            secret.type = hidden ? 'password' : 'text';
            secret.value = '';
            $('cli-prompt').textContent = label;
            secret.focus();
            const done = (v) => {
                secret.removeEventListener('keydown', key);
                box.classList.remove('asking');
                prompt();
                $('message-input').focus();
                resolve(v);
            };
            const key = (e) => {
                if (e.isComposing) return;
                if (e.key === 'Enter') { e.preventDefault(); done(secret.value); }
                else if (e.key === 'Escape') done(null);
            };
            secret.addEventListener('keydown', key);
        });
    }
    cmd('/passwd', '', 'change your password', async () => {
        const o = await question('current password: ', true);
        const n = o && await question('new password (8+): ', true);
        const n2 = n && await question('repeat it: ', true);
        if (n2 === null || !n2) return say('cancelled');
        if (n !== n2) return bad('the new passwords do not match');
        const r = await TN.post('/api/change_password', { old_password: o, new_password: n });
        say(r.ok ? 'password changed. every other device was signed out.' : 'error: ' + r.error);
    });
    cmd('/signout', 'others|all', 'sign out other devices, or everywhere', async (a) => {
        if (a !== 'others' && a !== 'all') return bad('usage: /signout others | all');
        const r = await TN.post('/api/logout_all', { keep_current: a === 'others' });
        if (!r.ok) return bad(r.error);
        if (a === 'all') location.href = '/'; else say('all other devices were signed out');
    });
    cmd('/deleteaccount', '', 'delete your account, messages and files', async () => {
        say('This removes your account, your messages and your files for good. There is no recovery.\nIf you own a server, delete it or hand it over first. Esc cancels.');
        const pw = await question('password: ', true);
        const name = pw && await question('your full name, ' + state().me.username + ': ', false);
        if (!name) return say('cancelled');
        const r = await TN.post('/api/delete_account', { password: pw, confirm: name.trim() });
        if (r.ok) location.href = '/'; else bad(r.error);
    });
    cmd('/yes', '[name]', 'confirm the question just asked', (a) => {
        const p = pending;
        if (!p) return say('nothing to confirm');
        if (p.expect && a !== p.expect) return bad('type it exactly: /yes ' + p.expect);
        pending = null;
        p.fn();
    });

    /* ------------------------------------------------- the terminal layer */
    function prompt() {
        const st = state();
        const room = st.roomId && $('chat-title').textContent;
        $('cli-prompt').textContent = st.server ? '[' + st.server.name + (room ? ' ' + room : '') + ']> ' : '[no server]> ';
    }
    const input = $('message-input');
    const hist = [];
    let at = 0;
    input.addEventListener('keydown', (e) => {
        if (!cli() || e.isComposing) return;
        if (e.key === 'Enter' && !e.shiftKey) {
            const t = input.value.trim();
            if (t) { hist.push(t); at = hist.length; }
            if (pending && !/^\/yes(\s|$)/i.test(t)) pending = null;       // anything else cancels the question
        } else if (e.key === 'ArrowUp' && !input.value.includes('\n') && at > 0) {
            e.preventDefault(); input.value = hist[--at];
        } else if (e.key === 'ArrowDown' && !input.value.includes('\n') && at < hist.length) {
            e.preventDefault(); input.value = ++at < hist.length ? hist[at] : '';
        } else if (e.key === 'Tab' && /^\/\w*$/.test(input.value)) {         // complete a command name
            e.preventDefault();
            const hits = Object.keys(TN.cmds).concat(['/help', '/nick', '/me', '/img', '/gif', '/video', '/topic', '/clear', '/lock', '/unlock', '/rotate'])
                .filter((c) => c.startsWith(input.value.toLowerCase()));
            if (hits.length === 1) input.value = hits[0] + ' ';
            else if (hits.length) say(hits.sort().join('  '));
        }
    }, true);
    for (const ev of ['tn:state', 'tn:theme']) document.addEventListener(ev, () => { if (!box.classList.contains('asking')) prompt(); });
    document.addEventListener('tn:theme', () => { if (cli()) { input.focus(); if (!$('chat-messages').childElementCount) say('Terminet.IRC. Type /help. Tab completes a command.'); } });
    // in the CLI theme a click on the log keeps the cursor on the prompt (unless text is being selected)
    $('chat-messages').addEventListener('click', () => { if (cli() && !String(getSelection()) && !box.classList.contains('asking')) input.focus(); });

    /* ------------------------------------------------------- socket events */
    document.addEventListener('tn:socket', () => {
        sock = TN.socket;
        sock.on('servers_list', (d) => {
            servers = (d.owned_servers || []).map((s) => ({ id: s.id, name: s.name, code: s.code, owned: true }))
                .concat((d.joined_servers || []).map((s) => ({ id: s.id, name: s.name, owned: false })));
        });
        sock.on('server_data', (d) => {
            if (!d.success) return;
            rooms = d.rooms || [];
            if (wantRooms) { wantRooms = false; say('opened "' + d.server.name + '"'); printRooms(); }
        });
        sock.on('room_joined', (d) => told.delete(d.room_id));
        sock.on('members_list', (d) => { if (d.success && waits.members) { const f = waits.members; waits.members = null; f(d.members || []); } });
        sock.on('bans_list', (d) => { if (d.success && waits.bans) { const f = waits.bans; waits.bans = null; f(d.bans || []); } });
        sock.on('invites_list', (d) => { if (d.success && waits.invites) { const f = waits.invites; waits.invites = null; f(d.invites || []); } });
        sock.on('room_activity', (d) => {
            if (!cli() || told.has(d.room_id)) return;
            told.add(d.room_id);
            const s = servers.find((x) => x.id === d.server_id), r = rooms.find((x) => x.id === d.room_id);
            say('news in ' + (s ? s.name : 'server ' + d.server_id) + (r ? ' #' + r.name : ''));
        });
        sock.on('connect', () => { if (cli()) say('connected'); });
        sock.on('disconnect', () => { if (cli()) say('disconnected, retrying'); });
    });

    prompt();
    if (cli()) input.focus();
})();
