# Security notes

Audit of the v1.3 prototype, what changed in v2, and what is still your responsibility.
Findings marked **(reproduced)** were exploited against an unmodified v1.3 server before
the rewrite.

## What v1.3 got wrong

12 problems, 3 of them critical. Each one below says what was wrong, what an attacker could do with it, and what v2 does instead. Items marked **(reproduced)** were actually exploited against v1.3 to confirm they were real.

| Severity | Count | Problems |
|----------|-------|----------|
| Critical | 3 | 1, 2, 3 |
| High     | 4 | 4, 5, 6, 7 |
| Medium   | 4 | 8, 9, 10, 11 |
| Low      | 1 | 12 |

---

## Critical

### 1. No authentication on the realtime API

**What was wrong:** `/api/login` returned a `user_id` and nothing else. After that, every Socket.IO event simply believed whatever `user_id`, `username`, `owner_id` and `kicked_by` the browser sent.

**What an attacker could do:** act as any other user, including a server owner. Read a server and its invite code, delete it, kick people, rename other users, post into rooms they were never in.

**(reproduced):** an account that was never a member read the victim's server, got its invite code and deleted it, using only the victim's numeric id.

**v2:** server-side sessions. The token is random (256 bits), stored hashed, lasts 72 hours, times out after 24 hours idle, and can be revoked. Identity comes from the session cookie only; ids sent by the client are ignored. Every event re-checks membership and ownership in the database.

### 2. Database and source code could be downloaded

**What was wrong:** `Flask(static_folder='.')` served the whole working directory as static files.

**What an attacker could do:** `GET /./terminet.db`, `/./terminet_server.py` (which contained the default `SECRET_KEY`, encryption key and salt) and `/./uploads/...`.

**(reproduced)** with `curl --path-as-is`. Browsers normalise the `/./` away, scripts don't.

**v2:** static files come from `web/` only. The database, key and uploads live in `data/` (mode 0700), outside the web root. Startup refuses a layout where `data/` is inside `web/`.

### 3. Hard-coded secrets

**What was wrong:** the encryption key was `"Defualt"`, the salt was `b'defualt'`, and `SECRET_KEY` was in the source, with a note saying "please change line 29/75/76". The key was also printed to the log at startup.

**What it meant:** anyone running it unmodified had encryption in name only.

**v2:** a random per-install key in `data/terminet.secret` (mode 0600), or one derived from `TERMINET_KEY` with scrypt. Nothing to edit, nothing logged. The server refuses to start if the key file is missing next to an existing database, or if the passphrase is wrong.

---

## High

### 4. Cross-site scripting (XSS) everywhere

**What was wrong:** server names, room names, usernames and filenames were pasted into `innerHTML` and into inline handlers like `onclick="...('${name}')"`.

**What an attacker could do:** a server named `');alert(document.cookie);//` ran script for everyone who saw the list.

**v2:** the frontend was rewritten. Text from the server reaches the page only through `textContent` or text nodes. No `innerHTML`, no inline handlers, no inline styles. A strict CSP (`script-src 'self'; style-src 'self'`) is a second layer, and the server also validates and cleans names. Tested with attack payloads in every field, in a real browser.

### 5. Anyone with a file id could download any upload

**What was wrong:** `/upload` and `file_uploaded` trusted a `user_id` and `room_id` sent by the client. Uploads were also read in full before the size check.

**What an attacker could do:** download any file by id, and post any file into any room as anyone.

**v2:** `/files/<id>` and `/upload` need a session and room or server membership. The server announces uploads itself. Size is capped while streaming (and by `MAX_CONTENT_LENGTH`). Files are stored under a random name and served as an attachment, with `nosniff` and a sandbox CSP.

### 6. No rate limits, no brute-force protection

**What was wrong:** login code and password could be guessed at full speed. Registration, messages, uploads and room creation had no limits. Invite codes were 8 characters, so guessable.

**v2:**
- Login: 5 failures per code per 15 minutes, 20 per IP per 10 minutes. Unknown codes get a dummy hash, so timing doesn't reveal whether a code exists.
- Also limited: registration, join by code, messages, uploads, nick changes, server and room creation, socket events, and connections per IP.

### 7. Login codes stored in plaintext and written to the log

**What was wrong:** the log contained lines like `User registered: name -> CODE`. Passwords could be any length, and one character was accepted **(reproduced)**.

**v2:** the login code is stored only as an HMAC and never logged. It is 12 characters (60 bits). Passwords must be 8 to 128 characters, with a small common-password check. No IPs, codes or message text go in the logs, and the HTTP access log is off by default.

---

## Medium

### 8. Permissive CORS, no CSRF protection, debug logging of everything

**What was wrong:** `cors_allowed_origins="*"`, no CSRF protection, and packet-level debug logging of every Socket.IO frame, so messages appeared in clear text in the console.

**v2:** same-origin only (extra origins via `TERMINET_ORIGINS`). `SameSite=Strict` cookie, plus `Origin` and `Sec-Fetch-Site` checks on requests that change state. Debug loggers off.

### 9. Remote embeds leaked viewers' IP addresses

**What was wrong:** `/img`, `/gif`, `/video` and any image or video URL were fetched automatically, from any host, including attacker-run ones. That is a tracking pixel by design, in an app for people who want privacy.

**v2:** click-to-load, `https:` only, no referrer. The prompt names the host before anything loads.

YouTube embeds were allowed in v2 through a sandboxed `youtube-nocookie.com` iframe. Phase 3 removed them, and the CSP has no `frame-src` at all.

### 10. Impersonation and spoofing

**What was wrong:** usernames were case-sensitive and unrestricted (`admin`, `Admin`, look-alike characters, bidi override characters), and any member could rename any other.

**v2:** uniqueness ignores case and separators. NFKC normalisation, no mixing Latin with Cyrillic or Greek, a reserved-names list, and invisible or bidi characters stripped from names and messages.

### 11. Kick did nothing useful

**What was wrong:**
- A kicked user could rejoin with the same invite code.
- Every member could see the invite code.
- Deleting a room or server left its uploads on disk.
- The welcome room could be deleted through a name quirk.

**v2:** the invite code is visible to the owner only. Kick (and `/rotate`) generate a new one. Deleting a room or server deletes its files. Special rooms are identified by type, not by name.

---

## Low

### 12. Assorted small things

**What was wrong:**
- Permissions checked once at join and never again.
- No limit on message size.
- Error text (`str(e)`) returned to clients.
- `encrypt` silently fell back to plaintext, and `decrypt` returned the ciphertext on error.
- SQLite connections never closed.
- `/health` leaked details.
- No security headers.

**v2:**
- Membership checked on every send.
- Limits on message, name, room and member counts.
- Generic error messages.
- Encryption fails closed.
- Connections are closed.
- Security headers: CSP, `nosniff`, frame-deny, no-referrer, COOP/CORP, and HSTS over TLS.

What was **not** a problem: SQL queries were already parameterised (the f-strings only
interpolated constant table names); no SQL injection found. Password hashing (Werkzeug
scrypt) was fine and is unchanged.

Also fixed while there, not security: `/chat` served `IRC.html` but the file was `IRC.HTML` (404
on Linux); the login page's script threw on load (undefined `mottoElement`) so its
"already logged in" redirect never ran; the chat page called `socket.on` before the socket
existed, silently killing the rest of its script.

## What v2 does and does not protect

Protects: other users of the same server (they can't impersonate you, read rooms they're not
in, or reach your files), people on the network (with TLS), someone who gets a copy of the
database file but not the key, people who find the server by scanning, the viewers' IPs from
embeds they didn't click.

Does **not** protect:

* **From whoever runs the server.** Names and messages are encrypted at rest with a key the
  server holds, so the operator can read everything. This is not end-to-end encryption.
* **Uploaded files are stored unencrypted** in `data/uploads/`. Use full-disk encryption if
  that matters.
* **At-rest encryption only helps if the key is not stored next to the data.** By default
  `terminet.secret` sits beside the DB: fine against a stolen backup of the DB file alone, not
  against a stolen disk. Use `TERMINET_KEY` (passphrase) or point `TERMINET_DATA` at another
  disk if the floppy/USB stick can walk away.
* **Plain HTTP.** Without TLS, passwords and the session cookie are readable on the network.
  Use `--gen-cert` or a reverse proxy (see README). The server warns on non-loopback HTTP.
* **No account recovery** (by design: no e-mail, no phone). Lose the login code or the password
  and the account is gone. You can change the password while signed in (Account), but a weak
  password plus a leaked login code is a weak account.
* **Resource exhaustion at scale.** Rate limits are per process and in memory (reset on restart).
  Disk use by uploads is capped (see below), the database is not: messages are small and
  limited to 512 per room, but accounts, servers and rooms are only rate-limited. The built-in
  server is Werkzeug's, fine for a small group; for more run gunicorn with exactly one worker behind
  Caddy/nginx (README, "Running it for real").
* **Registration is open.** Anyone who can reach the server can make accounts (rate-limited:
  5 per IP/hour, 60/hour overall; tune with `TERMINET_REG_*`). Joining a server still needs
  its invite code.
* A member can screenshot, copy, re-upload. A kicked member keeps what they already saw.
  Deleting a message removes it from the server, not from anyone's screen or copy.

## Added in overhaul 

**Stolen or forgotten sessions (C1).** A session cookie used to be good for 7 days with no way to
cancel it. Now:

* A session ends 72 hours after login (`TERMINET_SESSION_HOURS`) and after 24 hours without
  activity (`TERMINET_IDLE_HOURS`). Activity is any authenticated HTTP request or socket event
  from the browser; it is written at most once a minute. Receiving messages does not count.
* *Sign out other devices* / *Sign out everywhere* (`POST /api/logout_all`) delete the sessions
  and cut their open sockets at once. Changing the password (`POST /api/change_password`)
  does the same for every other device. A stolen cookie dies at that point.
* The current password is required, and wrong attempts are capped at 5 per account per
  15 minutes (then HTTP 429, even for the right password), so a hijacked session cannot be
  used to guess the password through this endpoint.
* A socket re-checks its session every 30 seconds while it is active, and the housekeeping
  pass (every 10 minutes) disconnects sockets whose session is gone. A completely silent
  expired socket can therefore stay open for up to about 10 minutes; it cannot send anything
  that is accepted.
* Sessions store no IP address or device name, so there is no device list: the choice is "all
  others" or "everyone". That is deliberate (nothing to leak), and it is a limitation.
* The login code is not rotated by a password change. If the code itself leaked, the password
  is what still protects the account.

**Disk filling (C2).** Uploads were limited only by count (512) and size per file, so 512 x 50 MB
was possible. Now a total quota (`TERMINET_MAX_STORAGE_MB`, 1 GB), a per-user share
(`TERMINET_USER_STORAGE_PCT`, 20 %) and a free-disk floor (`TERMINET_MIN_FREE_MB`, 256 MB).
The quota check and the insert are one step under a lock, so parallel uploads cannot overshoot
(tested with 12 simultaneous uploads). One user cannot push other people's files out: their own
oldest files are evicted first. Files that fall off the 512-message window stay on disk and
count against the quota until the oldest-first rule removes them.

**Deleting messages (C3).** The author may delete their own message; the server owner may delete
any message of that server, including system lines. The server looks the message up through the
caller's membership, so a non-member gets the same "not found" for a real id and a made-up one.
For file messages the file is removed from disk and from the database. SQLite may keep the old
row in free pages of `terminet.db` until they are reused (the content is encrypted with the
data key either way); this is not a secure erase.

**Removed.** `/logs`, the Load Logs button and the `get_room_logs` event: a way to pull the whole
room history on demand that nothing needed.

**Upgrade safety (S0).** On start-up an older database is copied (`terminet.db.bak-v<N>`, 0600)
and upgraded in a single transaction. The key check runs first, so a wrong `TERMINET_KEY` can
neither start an upgrade nor be blamed for one. The backup holds the same encrypted data as the
database: protect it the same way, and remove it when you no longer need it.


* **`room_activity` is metadata.** Every member of a server is told that a room of that server has
  something new, with the room id and nothing else: no text, no author. Members can open every room of
  their server anyway, so this shows them nothing they could not see. It is sent through each member's
  own channel using the database membership at that moment, so a member who was kicked or left stops
  receiving it at once (tested). The author never receives it. System lines (joins, nick changes) are
  not announced. With a future client-side encryption (plan item L1) this event keeps working because it
  carries no content.
* **Desktop alerts** are opt-in, only fire while the tab is hidden and contain the room name only. The
  permission prompt never opens on page load.
* **`file_missing` / `file_gone`** carry only the file id and room id the room members already hold;
  they add no way to learn about files of other rooms (the client only reacts to ids it displays).
* **Links.** Only `https:` URLs without credentials become `<a>`; they are built with the DOM API and
  carry `rel="noopener noreferrer"` and `target="_blank"`. `javascript:`, `data:` and `http:` stay
  text (two independent checks: the matcher and `parseUrl`). Remote media is still click-to-load.
* **/me, @mention, day lines** are rendered through `textContent` like everything else. The mention test
  runs in the browser on text it already has: the server never reads message text for it.
* **Paste/drop upload** goes through the same `/upload` endpoint with the same checks (membership,
  lock, quota, rate limit); there is no new server route.
* **Browser storage** now holds two per-browser switches, `tn_sound` and `tn_notify`. No token, no
  identifier. Nothing is written until you press a switch.
* **Sign-up page.** The login code is shown once, with Copy/Download and a "saved it" gate. The
  downloaded `.txt` has the user name and the login code, never the password.


**Names are not credentials, and now they carry numbers (N1).** `Bill[#00001]`. Login is the code plus the
password; a name never opens anything. What the number protects is *recognition*: two people can hold the
same name, and the second is `Bill[#00002]`, so nobody can pass as the first by taking the same letters
(case, spaces and punctuation do not make a different name; the reserved-name list still applies). Numbers only
count up, inside one transaction, and are never handed out again, not even after the account is deleted:
a departed person's name and number cannot be taken over later. A name is closed after 99,999; changes that
take a new number are capped (10 per 24 h per account, in memory) so nobody can use up a name to lock others
out of it. What is *not* solved: a bare `@Bill` or a plain "Bill" in a sentence names every Bill.

**Roles are checked on the server for every event (M13, M4).** Owner = `servers.owner_id`; a moderator row only
adds: member list, kick of plain members, topic, delete any message. Everything else (roles, bans, invites,
hand-over, code rotation, rooms and their kinds, auto-delete, deleting the server) tests for the owner.
A moderator cannot remove the owner or another moderator, and cannot appoint moderators. The buttons the
client hides are cosmetic; the tests (`test_phase3.py`) send every owner-only event as a moderator and as a
plain member and check that nothing happened, not merely that an error came back.

**Invites (M9).** Random codes, expiry 1 h / 24 h / 7 d, uses 1 / 10 / unlimited, 20 active per server, sharing the
namespace of server codes (a code never means two things). Using one is a single atomic `UPDATE ... uses = uses + 1
WHERE` that must change one row: eight people racing for a one-use code, one gets in (tested). Checks that
refuse (already a member, banned, server full) run *before* the use is counted. A kick deletes every invite
of the server as well as renewing the server code; the price is that people holding a valid invite for the
same server need a new one.

**Bans (M5).** `bans(server_id, user_id)`: tied to the account, checked on server-code and invite joins,
removes the membership at once and drops the socket from the server's rooms. It does not stop a banned person
from registering a new account and joining with a new code; there is nothing to tie a person to beyond the
account (no e-mail, no phone, no IP stored). The owner sees and lifts bans in the Members dialog.

**Hand-over (M6).** The old owner has to type the server's exact name; the new owner must already be a member
and own fewer than 10 servers; one transaction moves `owner_id`. No time-delayed undo: whoever holds the owner's
session can do it, which is one more reason for the session rules of phase 1.

**Topics, auto-delete, replies (M8, M10, M2).** Topic text is stored encrypted like names and reaches the DOM
through `textContent` (tested with markup and `<img onerror>`). Auto-delete is a database delete (files
removed from disk too), plus an `messages_expired {room_id, ids}` notice with ids only; SQLite may keep old rows in
free pages until reused (as for message deletion, not a secure erase). A reply stores the id of a non-system message
of the *same room*; the server refuses an id from another room (so a reply cannot be used to probe other rooms) and
the quote is built in the browser from lines it already shows, so the server sends no extra text.

**Delete account (M7).** `POST /api/delete_account {password, confirm}`: session required, same-origin
check, password re-asked with its own limiter (5 failures per 15 minutes, then 429), the full tag typed as
confirmation, refused while the account owns servers. The user row goes (memberships, sessions, messages, bans
cascade), uploaded files are deleted from disk, every session is revoked, the other members are told
(`user_gone {user_id, server_id}`) and their screens drop that person's lines. Nothing of it is a secure
erase of SQLite free pages, and anything somebody copied stays copied.

**Upload allow-list (S14).** Scripts and source code (`html js py sh php rb go rs c cpp java ...`) and the old
binary Office formats (`doc xls ppt`) are refused. Files were already served as attachments with `nosniff` and a
`default-src 'none'; sandbox` CSP, so they never ran on this origin; the point is not to be the carrier that
hands them to somebody who opens them. Files already stored under an old extension stay and are still served
the same safe way.

**YouTube embed removed (M14).** The last place the page let a third party into a frame. The CSP is now
`default-src 'none'` with only the page's own script, style and font, its own WebSocket and (https) images and media re-allowed, and no
`frame-src`; a test checks that the header has none and that the client contains no YouTube code.

**Admin command line (S13).** `--backup FILE` (SQLite online backup, 0600, refuses to overwrite, integrity
checked; **the key is not in it**: a backup is useless without `terminet.secret`/`TERMINET_KEY`, which is the
point, and it is also why a backup kept beside the key is as exposed as the live data), `--stats`
(counts and sizes only, opened read-only, nothing decrypted), `--revoke-sessions` (delete every session).
None of them can be reached over the network.

**Production profile (S12).** One gunicorn worker (`create_app()`), because sessions are in the database but
presence, room membership of sockets and every limiter are in process memory: a second worker would split rooms
and halve every limit. Limitation, stated again: the limiters reset when the process restarts.

**Known limits of phase 3.** Limiters (including the daily name-change cap) are per process and in memory. Old
databases keep the unused `servers.description_encrypted` column (always NULL). Auto-delete by timer runs every
10 minutes (at once when a room is opened or the setting changed). The kick deletes all invites, not only the one used.

## Reporting / verifying

`tests/` reproduces the attacks above against a running server. The phase-3 suites were also run against
deliberately broken copies of the server and the client (44 one-line breakages: a ban not checked, an invite
not consumed, a moderator allowed to kick a moderator, a frame-src back in the CSP, a reply into another
room, a deleted account's files kept, ...); each was caught by at least one check. If you find a hole, open an
issue with the steps; a failing test is the best bug report.
