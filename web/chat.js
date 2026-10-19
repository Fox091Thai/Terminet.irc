'use strict';
/*
 * Terminet.IRC chat client.
 * Rules this file lives by (they are what lets the CSP say script-src 'self'):
 *   - server-supplied text only ever reaches the DOM through textContent / text nodes
 *   - no innerHTML, no inline handlers, no inline style attributes
 *   - the client never sends who it is: the session cookie decides that server-side
 *   - remote media is click-to-load (loading it tells that host your IP address)
 */
(function () {
    const $ = (id) => document.getElementById(id);
    const FILE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    const MAX_FILE_BYTES = 50 * 1024 * 1024;
    const MAX_DOM_MESSAGES = 700;

    let socket = null;
    let me = null;                 // {user_id, username}
    let currentServer = null;      // {id, name, owner_id, ...}
    let currentRoomId = null;
    let currentLock = 0;
    let confirmFn = null;
    let confirmExpect = null;      // a name the person must type before the confirm button works
    let replyTo = null;            // {id, name, text} while a reply is being written
    let lastUsers = [];
    let currentRoomServer = null;  // server id of the room that is open
    let mentionRe = null;
    let stickBottom = true;        // is the log scrolled to (nearly) the end?
    let uploading = Promise.resolve();
    let canWrite = false;          // may this person type a message in the open room right now?
    let inputHint = '';
    const BASE_TITLE = document.title;
    const cli = () => document.documentElement.dataset.theme === 'cli';
    const unread = new Map();      // room id -> {server, n}; lives in this tab only (plan M3, option A)
    const roomNames = new Map();   // room id -> name, for the open server
    const serverNames = new Map(); // server id -> name
    const roomMeta = new Map();    // room id -> {topic, hours} (hours = auto-delete window, 0 = off)
    const msgIndex = new Map();    // message id -> {name, text} of the lines on screen, for reply quotes

    /* ---------------------------------------------------------------- DOM */
    function h(tag, props, ...kids) {
        const e = document.createElement(tag);
        if (props) {
            for (const [k, v] of Object.entries(props)) {
                if (k === 'class') e.className = v;
                else if (k === 'text') e.textContent = v;
                else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
                else e.setAttribute(k, v);
            }
        }
        for (const kid of kids) if (kid != null) e.append(kid);   // strings become text nodes
        return e;
    }

    const isOwner = () => !!(currentServer && me && currentServer.owner_id === me.user_id);
    const isStaff = () => !!currentServer && (currentServer.role === 'owner' || currentServer.role === 'moderator');
    // N1: names arrive as "Bill[#00001]"; the number is drawn dimmer than the name
    const plainName = (s) => String(s).replace(/\[#\d{5}\]$/, '');
    function nameNodes(full) {
        const m = /^([\s\S]*?)(\[#\d{5}\])$/.exec(String(full));
        return m ? [m[1], h('span', { class: 'tag', text: m[2] })] : [String(full)];
    }
    const snippet = (t) => { t = String(t).replace(/\s+/g, ' ').trim(); return t.length > 80 ? t.slice(0, 80) + '...' : t; };
    const retentionText = (hrs) => hrs === 168 ? '7 days' : hrs + ' h';

    /* ----------------------------------------- per-viewer preferences (may be unavailable: private mode) */
    function pref(key, dflt) {
        try { const v = localStorage.getItem(key); return v === null ? dflt : v; } catch (e) { return dflt; }
    }
    function setPref(key, v) { try { localStorage.setItem(key, v); } catch (e) { /* ignore */ } }

    /* ------------------------------------------------------- beep (no audio file: synthesised, +0 bytes) */
    let audio = null;
    let lastBeep = 0;
    function unlockAudio() {          // browsers only allow sound after a click or key press
        if (audio && audio.state === 'running') return;
        if (!audio) {
            const AC = window.AudioContext || window.webkitAudioContext;
            if (!AC) return;
            try { audio = new AC(); } catch (e) { audio = null; return; }
        }
        if (audio.state === 'suspended') audio.resume().catch(() => { });
    }
    function beep() {
        if (pref('tn_sound', '1') !== '1' || !audio || audio.state !== 'running') return;
        const now = Date.now();
        if (now - lastBeep < 1500) return;
        lastBeep = now;
        try {
            const t = audio.currentTime, osc = audio.createOscillator(), gain = audio.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, t);
            osc.frequency.exponentialRampToValueAtTime(660, t + 0.16);
            gain.gain.setValueAtTime(0.0001, t);
            gain.gain.exponentialRampToValueAtTime(0.05, t + 0.02);        // quiet on purpose
            gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.18);
            osc.connect(gain); gain.connect(audio.destination);
            osc.start(t); osc.stop(t + 0.2);
        } catch (e) { /* no sound is not an error */ }
    }
    function paintSound() {
        const on = pref('tn_sound', '1') === '1';
        $('btn-sound').textContent = on ? 'Sound on' : 'Sound off';
        $('btn-sound').setAttribute('aria-pressed', String(on));
    }

    /* ------------------------------------------- desktop alerts: opt-in, never the text, never the sender */
    const alertsSupported = () => 'Notification' in window;
    const alertsOn = () => alertsSupported() && Notification.permission === 'granted' && pref('tn_notify', '0') === '1';
    function paintAlerts() {
        const b = $('btn-notify');
        b.classList.toggle('hidden', !alertsSupported());
        if (!alertsSupported()) return;
        const blocked = Notification.permission === 'denied';
        b.textContent = blocked ? 'Alerts blocked' : alertsOn() ? 'Alerts on' : 'Alerts off';
        b.setAttribute('aria-pressed', String(alertsOn()));
        b.disabled = blocked;
        b.title = blocked ? 'Blocked in the browser settings for this site.' : 'Desktop alerts say which room has news, never what was written.';
    }
    function toggleAlerts() {
        if (!alertsSupported()) return;
        if (alertsOn()) { setPref('tn_notify', '0'); paintAlerts(); return; }
        // the permission prompt only ever opens from this click, never on page load
        Promise.resolve(Notification.requestPermission()).then((p) => {
            if (p === 'granted') setPref('tn_notify', '1');
            paintAlerts();
        }).catch(() => paintAlerts());
    }
    function desktopAlert(roomId, serverId) {
        if (!document.hidden || !alertsOn()) return;
        const where = roomNames.has(roomId) ? '#' + roomNames.get(roomId) : (serverNames.get(serverId) || 'Terminet');
        try {
            const n = new Notification('Terminet.IRC', { body: 'New message in ' + where, tag: 'tn-' + roomId, silent: true });
            n.onclick = () => { window.focus(); n.close(); };
        } catch (e) { /* ignore */ }
    }

    /* ------------------------------------------------------------------ unread counters (M3) */
    function badge(n) {
        return h('span', { class: 'ubadge', title: n + ' unread', text: n > 99 ? '99+' : String(n) });
    }
    function paintUnread() {
        document.querySelectorAll('.ubadge').forEach((e) => e.remove());
        let total = 0;
        const perServer = new Map();
        for (const [rid, u] of unread) {
            total += u.n;
            perServer.set(u.server, (perServer.get(u.server) || 0) + u.n);
            const el = $('room-item-' + rid);
            if (el) el.querySelector('.rname').after(badge(u.n));
        }
        for (const [sid, n] of perServer) {
            const el = $('server-item-' + sid);
            if (el && !el.classList.contains('active')) el.append(badge(n));   // the open server shows it per room instead
        }
        document.title = (total ? '(' + (total > 99 ? '99+' : total) + ') ' : '') + BASE_TITLE;
    }
    function bump(roomId, serverId) {
        const u = unread.get(roomId) || { server: serverId, n: 0 };
        u.n += 1;
        u.server = serverId;
        unread.set(roomId, u);
        paintUnread();
    }
    function clearUnread(roomId) { if (unread.delete(roomId)) paintUnread(); }
    function noteIncoming(roomId, serverId) { bump(roomId, serverId); beep(); desktopAlert(roomId, serverId); }

    function notify(message, type = 'success') {
        if (cli()) return localNotice((type === 'error' ? 'error: ' : '') + String(message));
        const old = document.querySelector('.notification');
        if (old) old.remove();
        const n = h('div', { class: 'notification ' + (type === 'error' ? 'error' : 'success'), text: String(message) });
        document.body.append(n);
        setTimeout(() => n.classList.add('show'), 10);
        setTimeout(() => { n.classList.remove('show'); setTimeout(() => n.remove(), 300); }, 3500);
    }

    const roomLabel = (name) => String(name).replace(/\s*\[Read-only\]$/i, '');

    // "@Bill[#00002]" or "@Bill#00002" names that Bill alone; a bare "@Bill" names every Bill (nobody can tell which was meant)
    function buildMention() {
        try {
            const t = /^([\s\S]*?)\[#(\d{5})\]$/.exec(me.username);
            const esc = (t ? t[1] : me.username).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const exact = t ? '\\[?#' + t[2] + '\\]?|' : '';
            mentionRe = new RegExp('(?<![\\p{L}\\p{N}_])@' + esc + '(?:' + exact + '(?![\\p{L}\\p{N}_]|\\[?#\\d))(?![\\p{L}\\p{N}_])', 'iu');
        } catch (e) { mentionRe = null; }              // an old browser without look-behind: no highlight, no harm
    }

    const ping = () => document.dispatchEvent(new Event('tn:state'));
    function paintMe() {
        ping();
        buildMention();
        $('current-username').replaceChildren(...nameNodes(me.username));
        $('current-avatar').className = 'avatar ' + nickClass(me.username);
        $('current-avatar').firstElementChild.textContent = Array.from(plainName(me.username))[0].toUpperCase();
    }

    function setStatus(state) {
        $('connection-status').className = 'connection-status ' + state;
        $('status-text').textContent = { connected: 'Connected', connecting: 'Connecting...', disconnected: 'Disconnected' }[state];
    }

    function openModal(id) { $(id).classList.add('open'); }      // a drawer stays open underneath: the new server shows up in it
    function closeModal(id) {
        const m = $(id);
        m.classList.remove('open');
        m.querySelectorAll('input').forEach((i) => { i.value = ''; });
    }
    function confirmBox(title, message, fn, expect) {
        $('confirm-title').textContent = title;
        $('confirm-message').textContent = message;
        confirmFn = fn;
        confirmExpect = expect || null;
        $('confirm-input').classList.toggle('hidden', !expect);
        $('confirm-input').placeholder = expect || '';
        openModal('confirm-modal');
        if (expect) $('confirm-input').focus();
    }

    /* ------------------------------------------------------------ messages */
    const pad2 = (n) => String(n).padStart(2, '0');
    const fmtTime = (ts) => { const d = new Date(ts || Date.now()); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()); };
    const fmtFull = (ts) => new Date(ts || Date.now()).toLocaleString([], { hour12: false });
    const dayKey = (ts) => { const d = new Date(ts || Date.now()); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); };
    const fmtDay = (ts) => new Date(ts || Date.now()).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
    // a nick keeps one of eight colours everywhere, picked from a hash of the name
    function nickClass(name) {
        let n = 0;
        for (const ch of String(name)) n = (n * 31 + ch.codePointAt(0)) >>> 0;
        return 'nc' + (n % 8);
    }

    function parseUrl(s) {
        try {
            const u = new URL(s);
            return (u.protocol === 'https:' && !u.username && !u.password) ? u : null;
        } catch (e) { return null; }
    }
    function buildEmbed(kind, u) {
        if (kind === 'image') {
            const img = h('img', { alt: 'image', loading: 'lazy', decoding: 'async', referrerpolicy: 'no-referrer' });
            img.addEventListener('error', () => img.replaceWith(document.createTextNode('[image failed to load]')));
            img.src = u.href;
            return img;
        }
        const v = h('video', { controls: '', preload: 'metadata' });
        v.src = u.href;
        return v;
    }

    function embedFor(raw, wantVideo) {
        const u = parseUrl(raw);
        if (!u) return null;
        const path = u.pathname.toLowerCase();
        let kind = null;
        if (!wantVideo && /\.(jpe?g|gif|png|webp|bmp|svg)$/.test(path)) kind = 'image';
        else if (/\.(mp4|webm|ogg|mov)$/.test(path)) kind = 'video';
        if (!kind) return null;
        const box = h('div', { class: 'embedded-content' });
        const btn = h('button', {
            class: 'embed-load', type: 'button',
            title: 'Loading contacts that server and reveals your IP address to it.',
            text: `[click to load ${kind} from ${u.hostname}]`,
        });
        btn.addEventListener('click', () => box.replaceChildren(buildEmbed(kind, u)));
        box.append(btn);
        return box;
    }

    // S4: https links become real links; anything else (javascript:, data:, http:, user:pass@) stays plain text
    function trimUrl(raw) {
        for (;;) {
            const c = raw.slice(-1);
            if (/[.,;:!?]/.test(c)) raw = raw.slice(0, -1);
            else if (c === ')' && raw.split(')').length > raw.split('(').length) raw = raw.slice(0, -1);
            else return raw;
        }
    }
    function addText(node, str) {
        let last = 0;
        for (const m of str.matchAll(/https:\/\/[^\s<>"']+/gi)) {
            const raw = trimUrl(m[0]);
            const u = parseUrl(raw);
            if (!u) continue;
            if (m.index > last) node.append(str.slice(last, m.index));
            node.append(h('a', { class: 'msg-link', href: u.href, target: '_blank', rel: 'noopener noreferrer', text: raw }));
            last = m.index + raw.length;
        }
        if (last < str.length) node.append(str.slice(last));
    }

    // <b> <bold> <big> <small> <center> <blink> <marquee> <size=N>, built as DOM nodes, never parsed HTML
    const TAG_RE = /<(\/?)(bold|b|big|center|small|blink|marquee|size)(?:=(\d{1,3}))?>/gi;
    function renderRich(text) {
        const root = document.createDocumentFragment();
        const stack = [{ tag: null, node: root }];
        const top = () => stack[stack.length - 1].node;
        let last = 0;
        let m;
        TAG_RE.lastIndex = 0;
        while ((m = TAG_RE.exec(text))) {
            const closing = m[1] === '/';
            const tag = m[2].toLowerCase();
            const arg = m[3];
            if (!closing) {
                if (stack.length > 7 || (tag === 'size') !== (arg !== undefined)) continue;   // stays literal text
                addText(top(), text.slice(last, m.index));
                last = TAG_RE.lastIndex;
                const node = document.createElement(tag === 'size' ? 'span' : tag);
                if (tag === 'size') node.style.fontSize = Math.max(6, Math.min(48, parseInt(arg, 10) || 16)) + 'px';
                top().append(node);
                stack.push({ tag, node });
            } else if (arg === undefined && stack.length > 1 && stack[stack.length - 1].tag === tag) {
                addText(top(), text.slice(last, m.index));
                last = TAG_RE.lastIndex;
                stack.pop();
            }
        }
        addText(top(), text.slice(last));
        return root;
    }

    function renderBody(text) {
        const frag = document.createDocumentFragment();
        const cmd = /^\/(img|gif|video)\s+(\S+)\s*$/i.exec(text);
        if (cmd) {
            const e = embedFor(cmd[2], cmd[1].toLowerCase() === 'video');
            if (e) { frag.append(e); return frag; }
        }
        frag.append(renderRich(text));
        const seen = new Set();
        for (const m of text.matchAll(/https:\/\/[^\s<>"']+/gi)) {
            if (seen.size >= 3) break;
            if (seen.has(m[0])) continue;
            seen.add(m[0]);
            const e = embedFor(m[0], false);
            if (e) frag.append(e);
        }
        return frag;
    }

    function goneBox(name) {
        return h('div', { class: 'file-gone' }, h('span', { class: 'gone-label', text: '[file deleted]' }),
            h('span', { class: 'gone-name', text: name }));
    }

    function fileEmbed(fd, missing) {
        if (!fd || !FILE_ID_RE.test(fd.file_id)) return document.createTextNode('[invalid file]');
        const url = '/files/' + fd.file_id;                       // never trust a server-sent URL
        const name = String(fd.filename || 'file');
        if (missing) return goneBox(name);                         // the server knows it is gone: do not even ask for it
        const link = (label) => h('a', { class: 'file-download', href: url, download: name, rel: 'noopener', text: label });
        switch (fd.file_type) {
            case 'image': {
                const img = h('img', { alt: name, loading: 'lazy', src: url });
                return h('div', { class: 'embedded-content' }, img);
            }
            case 'video': {
                const v = h('video', { controls: '', preload: 'metadata' });
                v.src = url;
                return h('div', { class: 'embedded-content' }, v);
            }
            case 'audio': {
                const a = h('audio', { controls: '', preload: 'metadata' });
                a.src = url;
                return h('div', { class: 'embedded-content' }, a);
            }
            case 'text': {
                const box = h('div', { class: 'text-preview', text: 'Loading...' });
                fetch(url, { credentials: 'same-origin' })
                    .then((r) => { if (!r.ok) throw new Error('x'); return r.text(); })
                    .then((t) => { box.textContent = t.length > 1000 ? t.slice(0, 1000) + '...' : t; })
                    .catch(() => { box.textContent = '[preview unavailable]'; });
                return h('div', { class: 'file-card' }, h('span', { class: 'fname', text: name }), box, link('Download'));
            }
            default:
                return h('div', { class: 'file-card' }, h('span', { class: 'fname', text: name }), link('Download'));
        }
    }

    const nearBottom = (box) => box.scrollHeight - box.scrollTop - box.clientHeight <= 80;
    const hideJump = () => $('jump-new').classList.add('hidden');
    const ME_RE = /^\/me\s+(\S[\s\S]*)$/;

    function addMessage(m, scroll = true) {
        const box = $('chat-messages');
        const stick = nearBottom(box);
        const type = m.type === 'system' ? 'system' : m.type === 'file' ? 'file' : 'user';
        const mine = type !== 'system' && !!me && m.user_id === me.user_id;
        const text = String(m.message ?? '');
        const action = type === 'user' ? ME_RE.exec(text) : null;

        // S2: a dated line whenever the day changes (the first line of an old room gets one too)
        const day = dayKey(m.ts);
        const prev = box.lastElementChild;
        if (day !== (prev ? prev.dataset.day : dayKey(Date.now()))) {
            box.append(h('div', { class: 'day-sep', 'data-day': day, text: fmtDay(m.ts) }));
        }

        const row = h('div', { class: 'message ' + type + (mine ? ' mine' : '') + (action ? ' action' : '') });
        row.dataset.day = day;
        if (m.id) { row.dataset.mid = String(m.id); row.dataset.sid = String(m.id).slice(0, 6); }   // sid: the short name the CLI theme shows
        if (type !== 'system') row.dataset.uid = String(m.user_id);
        if (m.reply_to && type === 'user') {                   // M2: the line this one answers, quoted above it
            const q = h('div', { class: 'quote', 'data-reply': String(m.reply_to) });
            fillQuote(q);
            row.append(q);
        }
        row.append(h('span', { class: 'timestamp', title: fmtFull(m.ts), text: fmtTime(m.ts) }), ' ');
        const nick = () => h('span', { class: 'username ' + nickClass(m.username) }, ...nameNodes(m.username));
        if (type === 'system') {
            row.append(h('em', { text }));
        } else if (action) {                                   // S7: "/me waves" shows as "* nick waves"
            row.append('* ', nick(), ' ', renderBody(action[1]));
        } else if (type === 'file') {
            row.append(nick(), ' ');
            const fd = m.file_data;
            if (fd && FILE_ID_RE.test(fd.file_id)) { row.dataset.fid = fd.file_id; row.dataset.fname = String(fd.filename || 'file'); }
            row.append(h('div', { class: 'file-slot' }, fileEmbed(fd, !!m.file_missing)));
        } else {
            row.append(nick(), ' ', renderBody(text));
        }
        // S10: a line that names us (whole word, any case) is lit up. Only in the open room: the server never reads text for this.
        if (!mine && type === 'user' && mentionRe && mentionRe.test(action ? action[1] : text)) row.classList.add('mention');
        if (m.id && type !== 'system') {
            const fn = m.file_data && m.file_data.filename;
            msgIndex.set(String(m.id), { name: String(m.username), text: type === 'file' ? '[file] ' + String(fn || 'file') : text });
        }
        // authors may delete their own lines, the owner and moderators any line (the server decides; this only hides the button)
        if (m.id && me) {
            const tools = h('span', { class: 'msg-tools' });
            if (type !== 'system') tools.append(replyButton(m.id));
            if (isStaff() || (type !== 'system' && m.user_id === me.user_id)) tools.append(deleteButton(m.id));
            if (tools.childElementCount) row.append(tools);
        }
        box.append(row);
        while (box.childElementCount > MAX_DOM_MESSAGES) {
            const first = box.firstElementChild;
            if (first.dataset.mid) msgIndex.delete(first.dataset.mid);
            first.remove();
        }
        if (!scroll) return;
        // S3: follow the log only when already at the end, or when we wrote the line; otherwise leave the reader alone
        if (mine || stick) { box.scrollTop = box.scrollHeight; stickBottom = true; hideJump(); }
        else $('jump-new').classList.remove('hidden');
    }

    function deleteButton(id) {
        // two clicks, no native dialog: the first arms the button for 3 s, the second deletes
        let timer = null;
        const btn = h('button', { class: 'msg-del', title: 'Delete message', text: '\u00d7' });
        btn.addEventListener('click', () => {
            if (!btn.classList.contains('armed')) {
                btn.classList.add('armed');
                btn.textContent = 'delete?';
                timer = setTimeout(() => { btn.classList.remove('armed'); btn.textContent = '\u00d7'; }, 3000);
                return;
            }
            clearTimeout(timer);
            socket.emit('delete_message', { message_id: id });
        });
        return btn;
    }

    function fillQuote(q) {
        const o = msgIndex.get(q.dataset.reply);
        q.textContent = '\u21aa ' + (o ? o.name + ': ' + snippet(o.text) : '[original message is gone]');
        q.classList.toggle('gone', !o);
    }

    function replyButton(id) {
        return h('button', {
            class: 'msg-reply', title: 'Reply', text: 'Reply',
            onclick: () => {
                const o = msgIndex.get(String(id));
                if (!o) return;
                if ($('message-input').disabled) return notify('You cannot write in this room.', 'error');
                setReply({ id: String(id), name: o.name, text: o.text });
            },
        });
    }
    function setReply(r) {
        replyTo = r;
        $('reply-bar').classList.toggle('hidden', !r);
        if (!r) return;
        $('reply-text').textContent = 'Replying to ' + r.name + ': ' + snippet(r.text);
        $('message-input').focus();
    }

    function removeRow(row) {
        const box = $('chat-messages');
        const before = row.previousElementSibling, after = row.nextElementSibling, id = row.dataset.mid;
        row.remove();
        if (before && before.classList.contains('day-sep') && (!after || after.classList.contains('day-sep'))) before.remove();
        if (!id) return;
        msgIndex.delete(id);
        for (const q of box.querySelectorAll('.quote')) if (q.dataset.reply === id) fillQuote(q);   // the quote outlives its line
    }
    function removeWhere(test) {
        for (const row of Array.from($('chat-messages').children)) if (row.classList.contains('message') && test(row)) removeRow(row);
    }
    function removeMessages(ids) { const set = new Set(ids); removeWhere((r) => set.has(r.dataset.mid)); }

    function renderMessages(list) {
        $('chat-messages').replaceChildren();
        msgIndex.clear();
        for (const m of list) addMessage(m, false);
        $('chat-messages').scrollTop = $('chat-messages').scrollHeight;
        stickBottom = true;
        hideJump();
    }

    function renderUsers(users) {
        lastUsers = users;
        const box = $('users-list');
        box.replaceChildren();
        for (const u of users) {
            const row = h('div', { class: 'user-item' },
                h('i', { class: 'dot ' + nickClass(u.name) }), h('span', { class: 'uname' }, ...nameNodes(u.name)));
            if (isOwner() && u.id !== me.user_id) {                  // moderators kick from the Members dialog, which knows who is a moderator
                row.append(h('button', {
                    class: 'kick-btn', text: 'Kick',
                    onclick: () => confirmBox('Kick user',
                        `Kick ${u.name} from this server? They are removed; the server code is renewed and the invite codes are revoked.`,
                        () => { socket.emit('kick_user', { server_id: currentServer.id, user_id: u.id }); closeModal('confirm-modal'); }),
                }));
            }
            box.append(row);
        }
        $('users-count').textContent = String(users.length);
    }

    /* ---------------------------------------------------- sidebar / rooms */
    function showChat() {
        $('welcome-screen').classList.add('hidden');
        $('chat-container').classList.remove('hidden');
        $('users-panel').classList.remove('hidden');
    }
    function showWelcome() {
        currentServer = null; currentRoomId = null;
        ping();
        setReply(null);
        $('welcome-screen').classList.remove('hidden');
        $('chat-container').classList.add('hidden');
        $('users-panel').classList.add('hidden');
        $('create-room-btn').classList.add('hidden');
        $('current-room').textContent = 'No room selected';
        document.querySelectorAll('.server-item').forEach((e) => e.classList.remove('active'));
    }

    function updateInput(enabled, placeholder) {
        const input = $('message-input');
        canWrite = enabled;
        inputHint = placeholder;
        input.disabled = !enabled && !cli();          // the CLI prompt stays live: commands work without a room
        input.placeholder = placeholder || 'Message, or /help';
        for (const b of [$('btn-send'), $('btn-upload')]) b.disabled = !enabled;
    }
    function applyLock(lock) {
        currentLock = lock;
        const owner = isOwner();
        if (lock === 4) updateInput(false, 'This channel is read-only');
        else if (lock === 1) updateInput(owner, owner ? 'Channel is locked, but you can type' : 'This channel is locked');
        else updateInput(true);
        renderServerActions();
    }

    const headBtn = (text, fn, cls = '') => h('button', { class: 'header-btn ' + cls, text, onclick: fn });
    function renderServerActions() {
        ping();
        const box = $('server-actions');
        box.replaceChildren();
        if (!currentServer) return;
        if (isStaff()) {
            box.append(headBtn('Members', openMembers));
            if (currentRoomId) box.append(headBtn('Room', openRoom));
        }
        if (!isOwner()) return;
        if (currentRoomId) {
            box.append(headBtn(currentLock === 0 ? 'Lock channel' : 'Unlock channel',
                () => socket.emit('lock_channel', { room_id: currentRoomId, lock: currentLock === 0 })));
        }
        box.append(headBtn('Invites', openInvites),
            headBtn('Delete server', () => confirmDeleteServer(currentServer.id, currentServer.name), 'danger'));
    }

    /* ----------------------------- room settings, invites, members (M4 M5 M6 M8 M9 M10 M13) */
    function paintRoomMeta() {
        const meta = (currentRoomId && roomMeta.get(currentRoomId)) || { topic: '', hours: 0 };
        $('chat-topic').textContent = meta.topic;
        $('chat-topic').title = meta.topic;
        const r = $('chat-retention');
        r.classList.toggle('hidden', !meta.hours);
        r.textContent = meta.hours ? 'auto-delete ' + retentionText(meta.hours) : '';
        r.title = meta.hours ? 'Messages in this room are deleted after ' + retentionText(meta.hours) + '.' : '';
    }
    const metaHours = () => (roomMeta.get(currentRoomId) || { hours: 0 }).hours;
    function openRoom() {
        const meta = roomMeta.get(currentRoomId) || { topic: '', hours: 0 };
        openModal('room-modal');
        $('room-topic').value = meta.topic;
        $('room-kind').value = String(currentLock);
        $('room-retention').value = String(meta.hours);
        $('room-owner-only').classList.toggle('hidden', !isOwner());
    }

    const membersOpen = () => $('members-modal').classList.contains('open');
    function loadMembers() {
        socket.emit('get_members', { server_id: currentServer.id });
        $('bans-box').classList.toggle('hidden', !isOwner());
        if (isOwner()) socket.emit('get_bans', { server_id: currentServer.id });
    }
    function openMembers() { openModal('members-modal'); loadMembers(); }

    function renderMembers(list) {
        const box = $('members-list'), sid = currentServer.id, owner = isOwner();
        box.replaceChildren();
        for (const m of list) {
            const row = h('div', { class: 'plain-row' },
                h('i', { class: 'status' + (m.online ? ' on' : ''), title: m.online ? 'online' : 'offline' }),
                h('span', { class: 'uname' }, ...nameNodes(m.name)));
            if (m.role !== 'member') row.append(h('span', { class: 'rbadge', text: m.role }));
            const acts = h('span', { class: 'row-actions' });
            const btn = (text, fn, cls = '') => acts.append(h('button', { class: 'action-btn ' + cls, text, onclick: fn }));
            if (m.user_id !== me.user_id && m.role !== 'owner') {
                if (owner) {
                    const to = m.role === 'moderator' ? 'member' : 'moderator';
                    btn(to === 'member' ? 'Demote' : 'Moderator', () => socket.emit('set_role', { server_id: sid, user_id: m.user_id, role: to }));
                }
                if (owner || m.role === 'member') {
                    btn('Kick', () => confirmBox('Kick user', `Kick ${m.name}? They are removed; the server code is renewed and the invite codes are revoked.`,
                        () => { socket.emit('kick_user', { server_id: sid, user_id: m.user_id }); closeModal('confirm-modal'); }), 'delete');
                }
                if (owner) {
                    btn('Ban', () => confirmBox('Ban user', `Ban ${m.name}? They are removed and cannot join again, even with a valid code, until you lift the ban.`,
                        () => { socket.emit('ban_user', { server_id: sid, user_id: m.user_id }); closeModal('confirm-modal'); }), 'delete');
                    btn('Make owner', () => confirmBox('Hand over server',
                        `Make ${m.name} the owner of "${currentServer.name}"? You stay a member but lose every owner right. Type the server name to confirm.`,
                        () => { socket.emit('transfer_owner', { server_id: sid, user_id: m.user_id, confirm: $('confirm-input').value.trim() }); closeModal('confirm-modal'); },
                        currentServer.name), 'delete');
                }
            }
            row.append(acts);
            box.append(row);
        }
    }
    function renderBans(list) {
        const box = $('bans-list');
        box.replaceChildren();
        if (!list.length) return box.append(h('div', { class: 'empty-note', text: 'Nobody is banned.' }));
        for (const b of list) {
            box.append(h('div', { class: 'plain-row' }, h('span', { class: 'uname' }, ...nameNodes(b.name)),
                h('span', { class: 'row-actions' }, h('button', {
                    class: 'action-btn', text: 'Unban',
                    onclick: () => socket.emit('unban_user', { server_id: currentServer.id, user_id: b.user_id }),
                }))));
        }
    }

    function openInvites() { openModal('invite-modal'); socket.emit('list_invites', { server_id: currentServer.id }); }
    function timeLeft(unix) {
        const s = unix - Date.now() / 1000;
        return s < 3600 ? Math.max(1, Math.round(s / 60)) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' d';
    }
    function renderInvites(list) {
        const box = $('invite-list');
        box.replaceChildren();
        if (!list.length) return box.append(h('div', { class: 'empty-note', text: 'No active codes.' }));
        for (const i of list) {
            box.append(h('div', { class: 'plain-row' },
                h('span', { class: 'uname code', text: i.code }),
                h('span', { class: 'dim', text: `${i.expires_at ? timeLeft(i.expires_at) + ' left' : 'no expiry'}, ${i.uses}/${i.max_uses || '\u221e'} used` }),
                h('span', { class: 'row-actions' }, h('button', {
                    class: 'action-btn delete', text: 'Revoke',
                    onclick: () => socket.emit('revoke_invite', { server_id: currentServer.id, code: i.code }),
                }))));
        }
    }

    function confirmDeleteServer(id, name) {
        confirmBox('Delete server', `Delete "${name}"? This is permanent.`,
            () => { socket.emit('delete_server', { server_id: id }); closeModal('confirm-modal'); });
    }

    function renderServers(owned, joined) {
        const list = $('servers-list');
        list.replaceChildren();
        serverNames.clear();
        for (const srv of owned.concat(joined)) serverNames.set(Number(srv.id), String(srv.name));
        if (!owned.length && !joined.length) {
            list.append(h('div', { class: 'empty-note', text: 'No servers found' }));
            paintUnread();
            return;
        }
        const add = (srv, isOwned) => {
            const actions = h('div', { class: 'server-actions' });
            if (isOwned) {
                actions.append(
                    h('button', {
                        class: 'action-btn', text: 'New code',
                        onclick: (e) => { e.stopPropagation(); confirmBox('New invite code',
                            `Regenerate the invite code of "${srv.name}"? The old code stops working.`,
                            () => { socket.emit('rotate_code', { server_id: srv.id }); closeModal('confirm-modal'); }); },
                    }),
                    h('button', {
                        class: 'action-btn delete', text: 'Delete',
                        onclick: (e) => { e.stopPropagation(); confirmDeleteServer(srv.id, srv.name); },
                    }));
            } else {
                actions.append(h('button', {
                    class: 'action-btn leave', text: 'Leave',
                    onclick: (e) => { e.stopPropagation(); confirmBox('Leave server', `Leave "${srv.name}"?`,
                        () => { socket.emit('leave_server', { server_id: srv.id }); closeModal('confirm-modal'); }); },
                }));
            }
            const el = h('div', { class: 'server-item', id: 'server-item-' + Number(srv.id) },
                h('strong', { text: srv.name }), h('br'),
                isOwned ? h('small', { text: `Code: ${srv.code} (Owner)` }) : null,
                actions);
            el.addEventListener('click', () => socket.emit('get_server_data', { server_id: srv.id }));
            list.append(el);
        };
        owned.forEach((s) => add(s, true));
        joined.forEach((s) => add(s, false));
        paintUnread();
    }

    function markActiveRoom() {
        document.querySelectorAll('.room-item').forEach((e) => e.classList.remove('active'));
        const el = currentRoomId && $('room-item-' + currentRoomId);
        if (el) el.classList.add('active');
    }

    function renderServerData(server, rooms) {
        currentServer = server;
        roomNames.clear();
        for (const r of rooms) {
            roomNames.set(Number(r.id), roomLabel(r.name));
            roomMeta.set(Number(r.id), { topic: r.topic || '', hours: r.retention_hours || 0 });
        }
        for (const [rid, u] of unread) if (u.server === server.id && !roomNames.has(rid)) unread.delete(rid);   // room was deleted
        $('create-room-btn').classList.toggle('hidden', !isOwner());
        document.querySelectorAll('.server-item').forEach((e) => e.classList.remove('active'));
        const el = $('server-item-' + Number(server.id));
        if (!el) return;
        el.classList.add('active');
        el.querySelector('.rooms-container')?.remove();
        const box = h('div', { class: 'rooms-container' }, h('div', { class: 'rooms-label', text: 'Rooms' }));
        for (const room of rooms) {
            const label = roomLabel(room.name);
            const item = h('div', { class: 'room-item', id: 'room-item-' + Number(room.id) },
                h('span', { class: 'hash', text: '#' }), h('span', { class: 'rname', text: label }));
            if (room.is_locked === 4) item.append(h('span', { class: 'rbadge', text: 'read-only' }));
            else if (room.is_locked === 1) item.append(h('span', { class: 'rbadge', text: 'locked' }));
            if (isOwner() && rooms.length > 1) {
                item.append(h('div', { class: 'room-actions' }, h('button', {
                    class: 'action-btn delete', text: 'Delete',
                    onclick: (e) => { e.stopPropagation(); confirmBox('Delete room', `Delete "#${label}"?`,
                        () => { socket.emit('delete_room', { room_id: room.id }); closeModal('confirm-modal'); }); },
                })));
            }
            item.addEventListener('click', () => socket.emit('join_room', { room_id: room.id }));
            box.append(item);
        }
        el.append(box);
        markActiveRoom();
        const cur = rooms.find((r) => Number(r.id) === currentRoomId);
        if (cur) { applyLock(cur.is_locked); paintRoomMeta(); } else renderServerActions();
        renderUsers(lastUsers);
        paintUnread();
    }

    /* -------------------------------------------------------------- socket */
    function initSocket() {
        setStatus('connecting');
        socket = io({ transports: ['websocket', 'polling'], reconnectionDelay: 2000, reconnectionDelayMax: 15000 });
        document.dispatchEvent(new Event('tn:socket'));

        socket.on('connect', () => {
            setStatus('connected');
            socket.emit('get_user_servers', {});
            if (currentServer) socket.emit('get_server_data', { server_id: currentServer.id });
            if (currentRoomId) socket.emit('join_room', { room_id: currentRoomId });
        });
        socket.on('disconnect', () => setStatus('disconnected'));
        socket.on('connect_error', (err) => {
            setStatus('disconnected');
            if (err && err.message === 'unauthorized') window.location.href = '/';
        });
        socket.on('connection_confirmed', (d) => { me = { user_id: d.user_id, username: d.username }; });

        socket.on('servers_list', (d) => {
            renderServers(d.owned_servers || [], d.joined_servers || []);
            if (currentServer) {
                if ($('server-item-' + currentServer.id)) socket.emit('get_server_data', { server_id: currentServer.id });
                else showWelcome();
            }
        });
        socket.on('servers_changed', () => socket.emit('get_user_servers', {}));
        socket.on('rooms_changed', (d) => {
            if (currentServer && d.server_id === currentServer.id) socket.emit('get_server_data', { server_id: d.server_id });
        });

        socket.on('server_created', (d) => {
            if (d.success) { notify('Server created!'); closeModal('create-server-modal'); socket.emit('get_user_servers', {}); }
            else notify('Failed to create server: ' + d.error, 'error');
        });
        socket.on('server_joined', (d) => {
            if (d.success) { notify('Joined server!'); closeModal('join-server-modal'); socket.emit('get_user_servers', {}); }
            else notify('Failed to join server: ' + d.error, 'error');
        });
        socket.on('server_left', (d) => {
            if (d.success) { notify('Left server.'); if (currentServer && currentServer.id === d.server_id) showWelcome(); }
            else notify('Failed to leave server: ' + d.error, 'error');
        });
        socket.on('server_deleted', (d) => {
            if (d.success) { notify('Server deleted.'); if (currentServer && currentServer.id === d.server_id) showWelcome(); }
            else notify('Failed to delete server: ' + d.error, 'error');
            socket.emit('get_user_servers', {});
        });
        socket.on('kicked_from_server_reload', (d) => {
            notify(d.message, 'error');
            if (currentServer && currentServer.id === d.server_id) showWelcome();
        });
        socket.on('kick_result', (d) => notify(d.success ? d.message : 'Kick failed: ' + d.error, d.success ? 'success' : 'error'));
        socket.on('code_rotated', (d) => notify(d.success ? 'Invite code regenerated.' : d.error, d.success ? 'success' : 'error'));

        socket.on('server_data', (d) => {
            if (d.success) renderServerData(d.server, d.rooms);
            else notify('Failed to load server: ' + d.error, 'error');
        });
        socket.on('room_joined', (d) => {
            currentRoomId = d.room_id;
            currentRoomServer = d.server_id;
            roomMeta.set(d.room_id, { topic: d.topic || '', hours: d.retention_hours || 0 });
            setReply(null);
            clearUnread(d.room_id);
            setDrawer(null);
            $('current-room').textContent = '#' + roomLabel(d.room_name);
            $('chat-title').textContent = '#' + roomLabel(d.room_name);
            showChat();
            renderMessages(d.messages || []);
            applyLock(d.is_locked);
            paintRoomMeta();
            markActiveRoom();
        });
        socket.on('room_closed', (d) => {
            if (d.room_id !== currentRoomId) return;
            currentRoomId = null;
            setReply(null);
            paintRoomMeta();
            $('chat-messages').replaceChildren();
            $('chat-title').textContent = '#';
            $('current-room').textContent = 'No room selected';
            updateInput(false, 'Pick a room');
            renderServerActions();
            notify('This room was deleted.', 'error');
        });
        socket.on('room_created', (d) => {
            if (d.success) { notify('Room created!'); closeModal('create-room-modal'); }
            else notify('Failed to create room: ' + d.error, 'error');
        });
        socket.on('room_deleted', (d) => notify(d.success ? d.message : 'Failed to delete room: ' + d.error, d.success ? 'success' : 'error'));
        socket.on('new_message', (m) => {
            addMessage(m);
            // an open room counts as read, unless the tab is hidden: then it is news like any other room
            if (document.hidden && currentRoomId && m.type !== 'system' && me && m.user_id !== me.user_id) {
                noteIncoming(currentRoomId, currentRoomServer);
            }
        });
        socket.on('room_activity', (d) => {
            const rid = Number(d.room_id), sid = Number(d.server_id);
            if (!Number.isInteger(rid) || !Number.isInteger(sid) || rid === currentRoomId) return;
            noteIncoming(rid, sid);
        });
        socket.on('file_gone', (d) => {
            if (d.room_id !== currentRoomId || !FILE_ID_RE.test(String(d.file_id))) return;
            for (const row of $('chat-messages').querySelectorAll('.message.file')) {
                const slot = row.dataset.fid === d.file_id ? row.querySelector('.file-slot') : null;
                if (slot) slot.replaceChildren(goneBox(row.dataset.fname || 'file'));
            }
        });
        socket.on('message_deleted', (d) => { if (d.room_id === currentRoomId) removeMessages([d.id]); });
        socket.on('messages_expired', (d) => { if (d.room_id === currentRoomId) removeMessages(d.ids || []); });
        socket.on('user_gone', (d) => {                       // M7: an account was deleted: its lines go from the open log too
            if (d.server_id === currentRoomServer) removeWhere((r) => r.dataset.uid === String(d.user_id));
            if (membersOpen()) loadMembers();
        });
        const metaOf = (id) => roomMeta.get(id) || { topic: '', hours: 0 };
        socket.on('topic_changed', (d) => {
            roomMeta.set(d.room_id, Object.assign(metaOf(d.room_id), { topic: d.topic || '' }));
            if (d.room_id === currentRoomId) paintRoomMeta();
        });
        socket.on('retention_changed', (d) => {
            roomMeta.set(d.room_id, Object.assign(metaOf(d.room_id), { hours: d.hours || 0 }));
            if (d.room_id === currentRoomId) paintRoomMeta();
        });
        socket.on('delete_result', (d) => { if (!d.success) notify('Delete failed: ' + d.error, 'error'); });
        socket.on('users_list', (d) => { if (d.room_id === currentRoomId) renderUsers(d.users || []); });
        socket.on('channel_lock_status', (d) => {
            if (d.room_id !== currentRoomId) return;
            applyLock(typeof d.kind === 'number' ? d.kind : d.locked ? 1 : 0);
            notify(d.message, d.locked ? 'error' : 'success');
        });
        socket.on('nickname_changed', (d) => {
            if (!d.success) return;
            me.username = d.new_nick;
            paintMe();
            notify('Nickname changed!');
            closeModal('nick-modal');
        });
        socket.on('nickname_error', (d) => notify('Nickname change failed: ' + d.error, 'error'));

        socket.on('members_changed', (d) => { if (membersOpen() && currentServer && d.server_id === currentServer.id) loadMembers(); });
        socket.on('members_list', (d) => {
            if (!d.success) return notify(d.error, 'error');
            if (currentServer && d.server_id === currentServer.id) renderMembers(d.members || []);
        });
        socket.on('bans_list', (d) => { if (d.success && currentServer && d.server_id === currentServer.id) renderBans(d.bans || []); });
        socket.on('invites_list', (d) => { if (d.success && currentServer && d.server_id === currentServer.id) renderInvites(d.invites || []); });
        socket.on('invite_created', (d) => {
            if (!d.success) return notify(d.error, 'error');
            notify('Code created: ' + d.code);
            socket.emit('list_invites', { server_id: d.server_id });
        });
        socket.on('invite_revoked', (d) => {
            if (d.success) socket.emit('list_invites', { server_id: d.server_id });
            else notify(d.error, 'error');
        });
        socket.on('transfer_result', (d) => {
            if (d.success) closeModal('members-modal');
            notify(d.success ? d.message : d.error, d.success ? 'success' : 'error');
        });
        for (const ev of ['role_result', 'ban_result', 'topic_result', 'retention_result', 'kind_result']) {
            socket.on(ev, (d) => {
                if (!d.success) notify(d.error, 'error');
                else if (d.message) notify(d.message);
                if (d.success && membersOpen()) loadMembers();
            });
        }
        socket.on('room_error', (d) => notify('Room error: ' + d.error, 'error'));
        socket.on('message_error', (d) => notify('Message error: ' + d.error, 'error'));
        socket.on('app_error', (d) => notify(d.error, 'error'));
    }

    /* ------------------------------------------------------------- actions */
    function localNotice(text) { addMessage({ type: 'system', message: text, ts: Date.now() }); }

    function helpText() {
        return ['*** TERMINET IRC COMMANDS ***',
            '/help - Show this help message',
            '/nick <nickname> - Change your nickname (a number like [#00001] is added after it)',
            '/me <action> - Say it in the third person ("* nick waves")',
            '/img <https-url> | /gif <https-url> - Embed image/GIF (click to load)',
            '/video <https-url> - Embed video (click to load)',
            '/topic <text> - Set the topic of this room, empty clears it (owner or moderator)',
            '/clear - Clear chat screen',
            '/lock, /unlock - Lock/unlock this channel (server owner)',
            '/rotate - Regenerate the server invite code (server owner)',
            '',
            '*** FORMATTING TAGS (use < >) ***',
            'b, bold, big, small, center, blink, marquee, size=12'].join('\n');
    }

    function handleCommand(text) {
        const [cmd, ...rest] = text.split(/\s+/);
        const arg = rest.join(' ').trim();
        switch (cmd.toLowerCase()) {
            case '/help': localNotice(helpText() + (TN.help.length ? '\n\n' + TN.help.join('\n') : '')); return true;
            case '/nick':
                if (arg) socket.emit('change_nickname', { new_nick: plainName(arg) });
                else notify('Usage: /nick <new_nickname>', 'error');
                return true;
            case '/clear': $('chat-messages').replaceChildren(); return true;
            case '/topic':
                if (!isStaff() || !currentRoomId) notify('Only the server owner or a moderator can set the topic.', 'error');
                else socket.emit('set_topic', { room_id: currentRoomId, topic: arg });
                return true;
            case '/lock': case '/unlock':
                if (!isOwner() || !currentRoomId) notify('Only the server owner can do that here.', 'error');
                else socket.emit('lock_channel', { room_id: currentRoomId, lock: cmd.toLowerCase() === '/lock' });
                return true;
            case '/rotate':
                if (!isOwner()) notify('Only the server owner can do that.', 'error');
                else socket.emit('rotate_code', { server_id: currentServer.id });
                return true;
            default: {
                const run = TN.cmds[cmd.toLowerCase()];
                if (!run) return false;      // unknown /command: send as a normal message
                run(arg);
                return true;
            }
        }
    }

    function sendMessage() {
        const input = $('message-input');
        const text = input.value.trim();
        if (!text) return;
        if (!socket.connected && !/^\/(help|clear|theme)(\s|$)/i.test(text)) return notify('Not connected to server', 'error');
        if (text.startsWith('/') && handleCommand(text)) { /* a command, done */ }
        else if (!currentRoomId) return notify('No room open. Try /servers or /help.', 'error');
        else if (!canWrite) return notify(inputHint || 'You cannot write in this room.', 'error');
        else {
            socket.emit('send_message', replyTo ? { message: text, reply_to: replyTo.id } : { message: text });
            setReply(null);
        }
        input.value = '';
        autoResize(input);
    }
    function autoResize(t) { t.style.height = 'auto'; t.style.height = (t.scrollHeight + t.offsetHeight - t.clientHeight) + 'px'; }

    function uploadFile(file) {
        return new Promise((resolve) => {
            if (!currentRoomId) { notify('Join a room first.', 'error'); return resolve(); }
            if (file.size > MAX_FILE_BYTES) { notify('File too large (max 50 MB)', 'error'); return resolve(); }
            const fd = new FormData();
            fd.append('file', file);
            fd.append('room_id', String(currentRoomId));
            const box = $('upload-progress');
            $('upload-filename').textContent = file.name;
            $('progress-fill').style.width = '0%';
            $('upload-percentage').textContent = '0%';
            box.classList.remove('hidden');
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/upload');
            xhr.upload.onprogress = (e) => {
                if (!e.lengthComputable) return;
                const p = Math.round((e.loaded / e.total) * 100);
                $('progress-fill').style.width = p + '%';
                $('upload-percentage').textContent = p + '%';
            };
            const done = () => { box.classList.add('hidden'); $('file-input').value = ''; resolve(); };
            xhr.onload = () => {
                done();
                let res = {};
                try { res = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
                if (xhr.status === 200 && res.success) notify('File uploaded!');
                else notify('Upload failed: ' + (res.error || 'status ' + xhr.status), 'error');
            };
            xhr.onerror = () => { done(); notify('Upload failed (network error).', 'error'); };
            xhr.send(fd);
        });
    }

    // S6: the button, paste and drop all end up here, one file at a time (the server allows 6 uploads a minute)
    function enqueueUploads(files) {
        const list = Array.from(files).slice(0, 5);
        if (!list.length) return;
        if (!currentRoomId || $('btn-upload').disabled) return notify('You cannot post files in this room.', 'error');
        for (const f of list) uploading = uploading.then(() => uploadFile(f));
    }
    const hasFiles = (e) => !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');

    function bindFileDrop() {
        const zone = $('chat-container');
        zone.addEventListener('dragover', (e) => { if (hasFiles(e)) { e.preventDefault(); zone.classList.add('dragging'); } });
        zone.addEventListener('dragleave', (e) => { if (!zone.contains(e.relatedTarget)) zone.classList.remove('dragging'); });
        zone.addEventListener('drop', (e) => {
            if (!hasFiles(e)) return;
            e.preventDefault();
            zone.classList.remove('dragging');
            enqueueUploads(e.dataTransfer.files);
        });
        // a file dropped anywhere else must not make the browser navigate away from the chat
        window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
        window.addEventListener('drop', (e) => { if (hasFiles(e)) e.preventDefault(); });
        document.addEventListener('paste', (e) => {
            const cd = e.clipboardData;
            if (!cd || !cd.files || !cd.files.length || zone.classList.contains('hidden')) return;
            if (cd.getData('text/plain')) return;           // a copied table has an image and text: paste the text as usual
            e.preventDefault();
            enqueueUploads(cd.files);
        });
    }

    async function logout() {
        try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) { /* ignore */ }
        window.location.href = '/';
    }

    async function postJson(url, body) {
        let r, j = {};
        try {
            r = await fetch(url, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
            });
            j = await r.json();
        } catch (e) { /* network or non-JSON reply */ }
        return { ok: !!(r && r.ok && j.success), error: j.error || j.message || 'request failed' };
    }

    async function changePassword() {
        const oldPw = $('acc-old').value, newPw = $('acc-new').value;
        if (!oldPw || !newPw) return notify('Fill in both passwords.', 'error');
        if (newPw !== $('acc-new2').value) return notify('The new passwords do not match.', 'error');
        const res = await postJson('/api/change_password', { old_password: oldPw, new_password: newPw });
        if (!res.ok) return notify(res.error, 'error');
        closeModal('account-modal');
        notify('Password changed. Every other device was signed out.');
    }

    async function deleteAccount() {
        const password = $('acc-del-pw').value, confirm = $('acc-del-name').value.trim();
        if (!password || !confirm) return notify('Enter your password and your full name.', 'error');
        const res = await postJson('/api/delete_account', { password, confirm });
        if (!res.ok) return notify(res.error, 'error');
        window.location.href = '/';
    }

    async function signOutDevices(keepCurrent) {
        const res = await postJson('/api/logout_all', { keep_current: keepCurrent });
        if (!res.ok) return notify(res.error, 'error');
        if (!keepCurrent) { window.location.href = '/'; return; }
        closeModal('account-modal');
        notify('All other devices were signed out.');
    }

    /* ----------------------------------------------- narrow screens: side panels become drawers (S5) */
    function setDrawer(which) {
        document.body.classList.toggle('drawer-left', which === 'left');
        document.body.classList.toggle('drawer-right', which === 'right');
        $('btn-rooms').setAttribute('aria-expanded', String(which === 'left'));
        $('btn-people').setAttribute('aria-expanded', String(which === 'right'));
    }
    const drawer = () => document.body.classList.contains('drawer-left') ? 'left' : document.body.classList.contains('drawer-right') ? 'right' : null;
    function setMore(open) {
        $('header-actions').classList.toggle('open', open);
        $('btn-more').setAttribute('aria-expanded', String(open));
    }

    /* ------------------------------ what cli.js (extra slash commands, the CLI theme) is allowed to touch */
    const TN = window.TN = {
        cmds: {}, help: [],
        get socket() { return socket; },
        get state() { return { me, server: currentServer, roomId: currentRoomId, users: lastUsers, canWrite }; },
        notice: localNotice, notify, post: postJson, logout, plain: plainName,
        reply(id) {
            const o = msgIndex.get(String(id));
            if (o) setReply({ id: String(id), name: o.name, text: o.text });
            return !!o;
        },
        upload: () => $('btn-upload').click(),
    };
    document.addEventListener('tn:theme', () => updateInput(canWrite, inputHint));

    /* ---------------------------------------------------------------- init */
    function bind() {
        for (const id of ['btn-rooms', 'welcome-menu']) $(id).addEventListener('click', () => setDrawer(drawer() === 'left' ? null : 'left'));
        $('btn-people').addEventListener('click', () => setDrawer(drawer() === 'right' ? null : 'right'));
        $('scrim').addEventListener('click', () => setDrawer(null));
        $('btn-more').addEventListener('click', () => setMore(!$('header-actions').classList.contains('open')));
        $('header-actions').addEventListener('click', () => setMore(false));
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { setDrawer(null); setMore(false); } });

        for (const ev of ['pointerdown', 'keydown']) document.addEventListener(ev, unlockAudio, { passive: true });
        $('btn-sound').addEventListener('click', () => { setPref('tn_sound', pref('tn_sound', '1') === '1' ? '0' : '1'); paintSound(); unlockAudio(); });
        $('btn-notify').addEventListener('click', toggleAlerts);
        paintSound();
        paintAlerts();
        document.addEventListener('visibilitychange', () => { if (!document.hidden && currentRoomId) clearUnread(currentRoomId); });

        const log = $('chat-messages');
        log.addEventListener('scroll', () => { stickBottom = nearBottom(log); if (stickBottom) hideJump(); });
        // pictures load after their row was added and push the end of the log away: stay on the end if we were on it
        log.addEventListener('load', () => { if (stickBottom) log.scrollTop = log.scrollHeight; }, true);
        $('jump-new').addEventListener('click', () => { log.scrollTop = log.scrollHeight; stickBottom = true; hideJump(); });
        bindFileDrop();

        $('btn-create-server').addEventListener('click', () => { openModal('create-server-modal'); $('server-name').focus(); });
        $('btn-join-server').addEventListener('click', () => { openModal('join-server-modal'); $('join-server-code').focus(); });
        $('create-room-btn').addEventListener('click', () => {
            if (!currentServer) return notify('Select a server first', 'error');
            openModal('create-room-modal'); $('room-name').focus();
        });
        $('welcome-create').addEventListener('click', () => $('btn-create-server').click());
        $('welcome-join').addEventListener('click', () => $('btn-join-server').click());
        $('btn-logout').addEventListener('click', logout);
        $('btn-account').addEventListener('click', () => { openModal('account-modal'); $('acc-old').focus(); });
        $('do-change-pw').addEventListener('click', changePassword);
        $('do-logout-others').addEventListener('click', () => signOutDevices(true));
        $('do-logout-all').addEventListener('click', () => signOutDevices(false));
        $('do-delete-account').addEventListener('click', deleteAccount);
        $('btn-nick').addEventListener('click', () => {
            const i = $('new-nickname'); openModal('nick-modal'); i.value = plainName(me.username); i.focus(); i.select();
        });
        $('reply-cancel').addEventListener('click', () => setReply(null));
        $('do-save-topic').addEventListener('click', () => socket.emit('set_topic', { room_id: currentRoomId, topic: $('room-topic').value.trim() }));
        $('do-save-room').addEventListener('click', () => {
            const kind = Number($('room-kind').value), hours = Number($('room-retention').value);
            if (kind !== currentLock) socket.emit('set_room_kind', { room_id: currentRoomId, kind });
            if (hours !== metaHours()) socket.emit('set_retention', { room_id: currentRoomId, hours });
            closeModal('room-modal');
        });
        $('do-create-invite').addEventListener('click', () => socket.emit('create_invite', {
            server_id: currentServer.id, hours: Number($('inv-hours').value), uses: Number($('inv-uses').value) }));
        $('btn-send').addEventListener('click', sendMessage);
        $('btn-upload').addEventListener('click', () => {
            if (!currentRoomId) return notify('Join a room to upload files', 'error');
            $('file-input').click();
        });
        $('file-input').addEventListener('change', (e) => { if (e.target.files.length) enqueueUploads(e.target.files); });

        $('do-create-server').addEventListener('click', () => {
            const name = $('server-name').value.trim();
            if (!name) return notify('Server name is required', 'error');
            socket.emit('create_server', { name });
        });
        $('do-join-server').addEventListener('click', () => {
            const code = $('join-server-code').value.trim();
            if (!code) return notify('Server code is required', 'error');
            socket.emit('join_server', { server_code: code });
        });
        $('do-create-room').addEventListener('click', () => {
            const name = $('room-name').value.trim();
            if (!name) return notify('Room name is required', 'error');
            socket.emit('create_room', { server_id: currentServer.id, room_name: name });
        });
        $('do-change-nick').addEventListener('click', () => {
            const n = $('new-nickname').value.trim();
            if (!n) return notify('Nickname cannot be empty', 'error');
            if (n !== plainName(me.username)) socket.emit('change_nickname', { new_nick: n });
        });
        $('confirm-action').addEventListener('click', () => {
            if (confirmExpect && $('confirm-input').value.trim() !== confirmExpect) return notify('Type the name exactly as shown.', 'error');
            if (confirmFn) confirmFn();
        });

        document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => closeModal(b.dataset.close)));
        document.querySelectorAll('.modal').forEach((m) => {
            m.addEventListener('click', (e) => { if (e.target === m) closeModal(m.id); });
            m.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && e.target.tagName === 'INPUT' && !e.isComposing && e.keyCode !== 229) {     // 229 = an IME is still choosing a word
                    e.preventDefault();
                    const go = e.target.dataset.enter ? $(e.target.dataset.enter) : m.querySelector('.modal-btn:not(.cancel):not(.secondary):not(.danger)');
                    if (go) go.click();
                }
                if (e.key === 'Escape') closeModal(m.id);
            });
        });

        const input = $('message-input');
        input.addEventListener('input', () => autoResize(input));
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) { e.preventDefault(); sendMessage(); }
            else if (e.key === 'Escape' && replyTo) setReply(null);
        });
        updateInput(false, 'Pick a server and a room');
    }

    async function boot() {
        let r;
        try { r = await fetch('/api/me', { credentials: 'same-origin' }); } catch (e) { r = null; }
        if (!r || !r.ok) { window.location.href = '/'; return; }
        me = (await r.json()).user;
        paintMe();
        bind();
        initSocket();
    }
    boot();
})();
