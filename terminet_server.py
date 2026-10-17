#!/usr/bin/env python3
"""
Terminet.IRC v2 - hardened rewrite of the v1.3 prototype.

Still one Python file, still no e-mail/phone, still tiny. What changed is that
the server no longer believes whatever the browser tells it:

  * real server-side sessions (random token, HttpOnly + SameSite=Strict cookie)
  * every Socket.IO / HTTP action is authorised against the DB using the
    identity of the session, never a user_id sent by the client
  * secrets are generated per install (data/terminet.secret), not hard-coded
  * the web root is a dedicated folder; DB, key and uploads live in data/
  * rate limits, size limits, input validation, CSP and friends

Run:  python3 terminet_server.py           (see README.md for env vars)
      python3 terminet_server.py --gen-cert 192.168.1.10   (self-signed TLS)
      python3 terminet_server.py --backup FILE | --stats | --revoke-sessions   (admin; see README.md)
"""
import argparse
import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import unicodedata
import uuid
from collections import deque
from contextlib import contextmanager
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, abort, jsonify, request, send_file, send_from_directory
from flask_socketio import SocketIO, disconnect, emit, join_room
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import safe_join

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, 'web')
DATA_DIR = os.path.abspath(os.environ.get('TERMINET_DATA') or os.path.join(BASE_DIR, 'data'))
DB_PATH = os.path.join(DATA_DIR, 'terminet.db')
SECRET_PATH = os.path.join(DATA_DIR, 'terminet.secret')
UPLOAD_ROOT = os.path.join(DATA_DIR, 'uploads')
TLS_DIR = os.path.join(DATA_DIR, 'tls')
SCHEMA_VERSION = 4


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


HOST = os.environ.get('TERMINET_HOST', '0.0.0.0')
PORT = _env_int('TERMINET_PORT', 8080)
TRUST_PROXY = os.environ.get('TERMINET_TRUST_PROXY') == '1'      # behind Caddy/nginx
FORCE_SECURE_COOKIE = os.environ.get('TERMINET_SECURE_COOKIE') == '1'
EXTRA_ORIGINS = [o.strip() for o in os.environ.get('TERMINET_ORIGINS', '').split(',') if o.strip()]
ACCESS_LOG = os.environ.get('TERMINET_ACCESS_LOG') == '1'        # off: we do not log IPs

MAX_FILE_SIZE = _env_int('TERMINET_MAX_FILE_MB', 50) * 1024 * 1024
MAX_TOTAL_FILES = 512
# Disk guard: 512 files x 50 MB would be ~25 GB, so the total is capped in bytes as well.
MAX_STORAGE_BYTES = _env_int('TERMINET_MAX_STORAGE_MB', 1024) * 1024 * 1024
USER_STORAGE_PCT = min(max(_env_int('TERMINET_USER_STORAGE_PCT', 20), 1), 100)   # one user's share of it
MIN_FREE_BYTES = _env_int('TERMINET_MIN_FREE_MB', 256) * 1024 * 1024             # refuse uploads below this
MAX_MESSAGES_PER_ROOM = 512
MAX_MESSAGE_CHARS = 1000
MAX_MESSAGE_LINES = 20
SESSION_TTL = _env_int('TERMINET_SESSION_HOURS', 72) * 3600      # hard lifetime of a login
SESSION_IDLE = _env_int('TERMINET_IDLE_HOURS', 24) * 3600        # logged out after this long without activity
SESSION_TOUCH = 60                                               # seconds between last_seen writes
MAX_SESSIONS_PER_USER = 10
MAX_SERVERS_PER_USER = 10
MAX_ROOMS_PER_SERVER = 50
MAX_MEMBERS_PER_SERVER = 200
MAX_CONNS_PER_IP = 30
REGISTER_PER_IP_HOUR = _env_int('TERMINET_REG_PER_IP_HOUR', 5)
REGISTER_GLOBAL_HOUR = _env_int('TERMINET_REG_GLOBAL_HOUR', 60)

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico',
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv', '3gp',
    'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma',
    'txt', 'pdf', 'docx', 'xlsx', 'pptx',
    'rtf', 'odt', 'ods', 'odp',
    'zip', 'rar', '7z', 'tar', 'gz',
    'json', 'xml', 'csv',
}
IMAGE_EXT = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'}
VIDEO_EXT = {'mp4', 'webm', 'mov', 'avi'}
AUDIO_EXT = {'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'}
TEXT_EXT = {'txt', 'json', 'xml', 'csv'}

# room kind (column is_locked): 0 open, 1 only the owner posts, 4 system room (nobody posts; the server announces
# joins and leaves there). Kind 3 (the old Rules room) was folded into 1 by the v4 migration.
LOCK_OPEN, LOCK_OWNER, LOCK_SYSTEM = 0, 1, 4
DEFAULT_ROOMS = (('general', LOCK_OPEN),)
MAX_DISC = 99999                         # numbers per name: Bill[#00001] ... Bill[#99999], then the name is closed
NICK_CHANGES_PER_DAY = _env_int('TERMINET_NICK_CHANGES_PER_DAY', 10)   # name changes that use up a number (stops people burning a name down)
MAX_TOPIC_CHARS = 200
RETENTION_CHOICES = (1, 24, 168)         # hours; no setting = keep the newest 512 messages only
INVITE_HOURS = (1, 24, 168)
INVITE_USES = (1, 10, 0)                 # 0 = unlimited
MAX_INVITES_PER_SERVER = 20
ROLES = ('member', 'moderator')

CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'   # no 0/O/1/I
ACCOUNT_CODE_LEN = 12
SERVER_CODE_LEN = 10
FILE_ID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

log = logging.getLogger('terminet')

# --------------------------------------------------------------------------
# Keys & encryption at rest (AES-256-GCM)
# --------------------------------------------------------------------------
_AES = None          # AESGCM for data at rest
_LOOKUP = None       # HMAC key for account-code lookup
DUMMY_HASH = None    # equalises login timing for unknown codes


def _load_root_key():
    """Per-install random key in data/terminet.secret (0600).

    If TERMINET_KEY is set, the key is derived from that passphrase instead and
    the random key on disk is ignored - keep the passphrase off the floppy.
    """
    if not os.path.exists(SECRET_PATH):
        if os.path.exists(DB_PATH):
            sys.exit('data/terminet.db exists but data/terminet.secret does not. '
                     'Refusing to create a new key over existing data.')
        fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(os.urandom(48))
    with open(SECRET_PATH, 'rb') as f:
        blob = f.read()
    if len(blob) != 48:
        sys.exit('data/terminet.secret is corrupt (expected 48 bytes).')
    salt, key = blob[:16], blob[16:]
    phrase = os.environ.get('TERMINET_KEY')
    if phrase:
        key = hashlib.scrypt(phrase.encode(), salt=salt, n=2 ** 15, r=8, p=1,
                             maxmem=64 * 1024 * 1024, dklen=32)
    return key


def _init_crypto():
    global _AES, _LOOKUP, DUMMY_HASH
    root = _load_root_key()
    sub = lambda label: hmac.new(root, label, hashlib.sha256).digest()  # noqa: E731
    _AES = AESGCM(sub(b'terminet/data/v1'))
    _LOOKUP = sub(b'terminet/lookup/v1')
    DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def enc(text):
    nonce = os.urandom(12)
    return 'v1.' + base64.urlsafe_b64encode(nonce + _AES.encrypt(nonce, text.encode('utf-8'), None)).decode()


def dec(blob):
    """Decrypt; on any failure return a placeholder (never the ciphertext)."""
    try:
        if not blob:
            return ''
        if not blob.startswith('v1.'):
            raise ValueError('bad version')
        raw = base64.urlsafe_b64decode(blob[3:])
        return _AES.decrypt(raw[:12], raw[12:], None).decode('utf-8')
    except Exception:
        return '[unreadable]'


def code_digest(code):
    return hmac.new(_LOOKUP, code.encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# Rate limiting (in memory, sliding window)
# --------------------------------------------------------------------------
class Limiter:
    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def allow(self, key, limit, window):
        """Record a hit and return True if still under `limit` per `window` s."""
        now = time.monotonic()
        with self._lock:
            q, _ = self._d.setdefault(key, (deque(), window))
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def hit(self, key, window):
        now = time.monotonic()
        with self._lock:
            self._d.setdefault(key, (deque(), window))[0].append(now)

    def count(self, key, window):
        now = time.monotonic()
        with self._lock:
            item = self._d.get(key)
            if not item:
                return 0
            q = item[0]
            while q and q[0] <= now - window:
                q.popleft()
            return len(q)

    def clear(self, key):
        with self._lock:
            self._d.pop(key, None)

    def gc(self):
        now = time.monotonic()
        with self._lock:
            for k in list(self._d):
                q, window = self._d[k]
                while q and q[0] <= now - window:
                    q.popleft()
                if not q:
                    del self._d[k]


RL = Limiter()
HASH_SEM = threading.BoundedSemaphore(4)     # scrypt is memory hungry; cap concurrency

# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
# control chars (except \t \n), bidi overrides, zero-width & other invisibles
_INVISIBLE = re.compile('[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u200b\u200e\u200f'
                        '\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufff9-\ufffb]')
RESERVED_NAMES = {'system', 'admin', 'administrator', 'moderator', 'owner', 'terminet', 'server', 'root'}
COMMON_PASSWORDS = {
    '12345678', '123456789', '1234567890', '0123456789', '11111111', '00000000', '88888888',
    'password', 'password1', 'password123', 'passw0rd', 'qwertyui', 'qwerty123', 'qwertyuiop',
    'abc12345', 'abcd1234', 'iloveyou', 'letmein1', 'welcome1', 'admin123', 'administrator',
    'terminet', 'terminet1', '1q2w3e4r', '1qaz2wsx', 'asdfghjk', 'zxcvbnm1', 'monkey123',
    'dragon123', 'football1', 'baseball1', 'superman1', 'trustno1', 'sunshine1',
}


def clean_text(s, multiline=False):
    s = unicodedata.normalize('NFC', s)
    s = _INVISIBLE.sub('', s).replace('\r\n', '\n').replace('\r', '\n')
    if not multiline:
        s = ' '.join(s.split())
    return s.strip()


def text_field(v, lo, hi, multiline=False):
    """Cleaned str with lo <= len <= hi, else None."""
    if not isinstance(v, str) or len(v) > hi * 4 + 16:
        return None
    s = clean_text(v, multiline)
    return s if lo <= len(s) <= hi else None


def as_int(v):
    return v if type(v) is int and 0 < v < 2 ** 53 else None


def valid_username(raw):
    """Return (display_name, uniqueness_key) or None."""
    name = text_field(raw, 2, 20)
    if not name:
        return None
    for ch in name:
        if unicodedata.category(ch)[0] not in 'LMN' and ch not in '_-. ':
            return None
    scripts = {unicodedata.name(ch, '').split(' ')[0] for ch in name if ch.isalpha()}
    if 'LATIN' in scripts and scripts & {'CYRILLIC', 'GREEK'}:      # homoglyph spoofing
        return None
    key = re.sub(r'[ _.\-]', '', unicodedata.normalize('NFKC', name).casefold())
    if len(key) < 2 or key in RESERVED_NAMES:
        return None
    return name, key


def tag_of(name, disc):
    return f'{name}[#{disc:05d}]'


def take_disc(c, key):
    """Next free number for the normalised name `key`, or None when the name is full. Numbers are never handed
    back, so a tag always means the same person. The caller holds BEGIN IMMEDIATE: two people choosing the
    same name at the same moment cannot get the same number."""
    row = c.execute('SELECT next_disc FROM name_counters WHERE name_key = ?', (key,)).fetchone()
    n = row['next_disc'] if row else 1
    if n > MAX_DISC:
        return None
    c.execute('INSERT OR REPLACE INTO name_counters (name_key, next_disc) VALUES (?, ?)', (key, n + 1))
    return n


def password_problem(pw, name):
    if not isinstance(pw, str) or not 8 <= len(pw) <= 128:
        return 'Password must be 8-128 characters.'
    if pw.lower() in COMMON_PASSWORDS or pw.lower() == name.lower():
        return 'That password is too easy to guess.'
    return None


def gen_code(n):
    return ''.join(secrets.choice(CODE_ALPHABET) for _ in range(n))


def norm_code(v):
    if not isinstance(v, str) or len(v) > 32:
        return None
    v = re.sub(r'[\s-]', '', v).upper()
    return v if 6 <= len(v) <= 16 and v.isascii() and v.isalnum() else None


def fmt_code(code):
    return '-'.join(code[i:i + 4] for i in range(0, len(code), 4))


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = '''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    username_key TEXT UNIQUE NOT NULL,           -- normalised name + '#' + number, e.g. bill#00001
    disc INTEGER NOT NULL DEFAULT 1,             -- the number shown after the name: Bill[#00001]
    password_hash TEXT NOT NULL,
    unique_code TEXT UNIQUE NOT NULL,            -- HMAC of the login code, not the code
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE name_counters (                      -- next free number per normalised name; only ever counts up
    name_key TEXT PRIMARY KEY,
    next_disc INTEGER NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_code TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    role TEXT NOT NULL DEFAULT 'member',         -- member | moderator (the owner is servers.owner_id)
    UNIQUE(server_id, user_id)
);
CREATE TABLE bans (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, user_id)
);
CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    expires_at INTEGER,                          -- unix seconds
    max_uses INTEGER,                            -- NULL = unlimited
    uses INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name_encrypted TEXT NOT NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_locked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    topic_encrypted TEXT,
    retention_hours INTEGER                      -- NULL = keep the newest 512 messages only
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username_encrypted TEXT NOT NULL,
    message_encrypted TEXT NOT NULL,
    message_type TEXT DEFAULT 'user',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    reply_to TEXT                                -- message_id of the line this one answers
);
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT UNIQUE NOT NULL,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT,
    file_type_category TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX idx_members_user ON server_members(user_id);
CREATE INDEX idx_rooms_server ON rooms(server_id);
CREATE INDEX idx_messages_room ON messages(room_id, id);
CREATE INDEX idx_files_room ON files(room_id);
CREATE INDEX idx_sessions_exp ON sessions(expires_at);
CREATE INDEX idx_invites_server ON invites(server_id);
'''


@contextmanager
def db():
    """Short-lived connection. NEVER open a second one while holding writes."""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---- schema migrations ----------------------------------------------------
# One function per step, keyed by the version it upgrades FROM. All pending
# steps and the version bump run in ONE transaction, so a failed upgrade leaves
# the database exactly as it was; a copy is taken first anyway.
# Rules for authors: plain c.execute() only (executescript() commits), and a
# change SQLite cannot ALTER in place (a table rebuild) needs foreign_keys=OFF
# outside the transaction - add that here when the first such step appears.
def _migrate_2_to_3(c):
    # C1: sessions get an activity clock; the old 7-day logins are cut to the new lifetime.
    c.execute('ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0')
    c.execute('UPDATE sessions SET last_seen = created_at, expires_at = MIN(expires_at, created_at + ?)',
              (SESSION_TTL,))


def _migrate_3_to_4(c):
    # N1: every existing name was unique, so each of them is #00001 of its own name and the counter continues at 2
    # (username_key stays UNIQUE but now carries the number, so no table rebuild is needed).
    c.execute('ALTER TABLE users ADD COLUMN disc INTEGER NOT NULL DEFAULT 1')
    c.execute('CREATE TABLE name_counters (name_key TEXT PRIMARY KEY, next_disc INTEGER NOT NULL)')
    c.execute('INSERT INTO name_counters SELECT username_key, 2 FROM users')
    c.execute("UPDATE users SET username_key = username_key || '#00001'")
    # M13 roles, M5 bans, M9 invites, M8 topic, M10 retention, M2 reply
    c.execute("ALTER TABLE server_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
    c.execute('CREATE TABLE bans (server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE, '
              'user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, '
              'banned_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (server_id, user_id))')
    c.execute('CREATE TABLE invites (code TEXT PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) '
              'ON DELETE CASCADE, expires_at INTEGER, max_uses INTEGER, uses INTEGER NOT NULL DEFAULT 0)')
    c.execute('CREATE INDEX idx_invites_server ON invites(server_id)')
    c.execute('ALTER TABLE rooms ADD COLUMN topic_encrypted TEXT')
    c.execute('ALTER TABLE rooms ADD COLUMN retention_hours INTEGER')
    c.execute('ALTER TABLE messages ADD COLUMN reply_to TEXT')
    # M1: the old Rules room (kind 3, owner posts) becomes plain "only the owner posts"; the Welcome room (4) is the system room
    c.execute('UPDATE rooms SET is_locked = 1 WHERE is_locked = 3')


MIGRATIONS = {2: _migrate_2_to_3, 3: _migrate_3_to_4}


def copy_db(dest):
    """Consistent copy of the live database (SQLite online-backup API); returns its integrity_check verdict."""
    src, dst = sqlite3.connect(DB_PATH, timeout=30), sqlite3.connect(dest)
    try:
        src.backup(dst)
        verdict = dst.execute('PRAGMA integrity_check').fetchone()[0]
    finally:
        src.close()
        dst.close()
    os.chmod(dest, 0o600)
    return verdict


def backup_db(tag):
    dest = f'{DB_PATH}.bak-{tag}'
    if os.path.exists(dest):
        dest = f'{dest}-{int(time.time())}'
    copy_db(dest)
    return dest


def migrate_db(ver):
    steps = list(range(ver, SCHEMA_VERSION))
    if any(v not in MIGRATIONS for v in steps):
        sys.exit(f'Database schema version {ver} cannot be upgraded to {SCHEMA_VERSION} by this program.')
    dest = backup_db(f'v{ver}')
    log.info('Upgrading database schema v%d -> v%d (backup: %s)', ver, SCHEMA_VERSION, dest)
    try:
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            for v in steps:
                MIGRATIONS[v](c)
            c.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
    except Exception as e:
        log.exception('database upgrade failed')
        sys.exit(f'Database upgrade failed ({e}). The database was left unchanged; backup copy: {dest}')


def init_db():
    with db() as c:
        c.execute('PRAGMA journal_mode = WAL')
        has_users = c.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone()
        ver = c.execute('PRAGMA user_version').fetchone()[0]
        if has_users and ver > SCHEMA_VERSION:
            sys.exit(f'Database schema version {ver} is newer than this program supports ({SCHEMA_VERSION}).')
        if not has_users:
            c.executescript(SCHEMA)
            c.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
            c.execute("INSERT INTO meta VALUES ('canary', ?)", (enc('terminet-ok'),))
            ver = SCHEMA_VERSION
        canary = c.execute("SELECT value FROM meta WHERE key='canary'").fetchone()
        if not canary or dec(canary['value']) != 'terminet-ok':
            sys.exit('Cannot decrypt the database: wrong TERMINET_KEY or wrong data/terminet.secret.')
    if ver < SCHEMA_VERSION:          # checked the key first: a wrong key must not trigger an upgrade
        migrate_db(ver)
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Flask app + headers
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder=WEB_DIR, static_url_path='/static', template_folder=None)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE + 1024 * 1024

socketio = SocketIO(
    app,
    async_mode='threading',
    cors_allowed_origins=EXTRA_ORIGINS or None,      # None = same origin only
    logger=False,
    engineio_logger=False,
    max_http_buffer_size=64 * 1024,                  # events are tiny; uploads use HTTP
    transports=['websocket', 'polling'],
)
if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    # applied after SocketIO() so it wraps both Flask and the Socket.IO endpoint
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def client_ip():
    return request.remote_addr or '?'


def is_secure_request():
    return FORCE_SECURE_COOKIE or request.is_secure


@app.after_request
def security_headers(resp):
    h = resp.headers
    host = request.host if re.fullmatch(r'[A-Za-z0-9.\-:\[\]]{1,255}', request.host) else 'invalid.host'
    h.setdefault('Content-Security-Policy',
                 "default-src 'none'; script-src 'self'; style-src 'self'; "
                 "img-src 'self' data: blob: https:; media-src 'self' blob: https:; "
                 f"connect-src 'self' ws://{host} wss://{host}; "
                 "font-src 'self'; "
                 "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    h['X-Content-Type-Options'] = 'nosniff'
    h['X-Frame-Options'] = 'DENY'
    h['Referrer-Policy'] = 'no-referrer'
    h['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    h['Cross-Origin-Opener-Policy'] = 'same-origin'
    h['Cross-Origin-Resource-Policy'] = 'same-origin'
    if is_secure_request():
        h['Strict-Transport-Security'] = 'max-age=31536000'
    if request.path.startswith('/api/') or request.path == '/upload':
        h['Cache-Control'] = 'no-store'
    return resp


def same_origin_ok():
    """CSRF belt-and-braces on top of SameSite=Strict."""
    origin = request.headers.get('Origin')
    if origin:
        host = urlparse(origin).netloc
        return host == request.host or any(urlparse(o).netloc == host for o in EXTRA_ORIGINS)
    return request.headers.get('Sec-Fetch-Site') in (None, 'same-origin', 'none')


def json_body(limit=4096):
    if request.content_length and request.content_length > limit:
        abort(413)
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def fail(msg, code=400, **extra):
    resp = jsonify(success=False, message=msg, error=msg)
    resp.status_code = code
    for k, v in extra.items():
        resp.headers[k] = str(v)
    return resp


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------
COOKIE = 'tn_session'


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def check_session(th):
    """User row for a live session, else None. A session dies at expires_at (hard lifetime) or after
    SESSION_IDLE seconds without activity; activity is recorded at most once per SESSION_TOUCH seconds."""
    now = int(time.time())
    with db() as c:
        row = c.execute('SELECT u.id, u.username, u.disc, s.created_at, s.expires_at, s.last_seen FROM sessions s '
                        'JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?', (th,)).fetchone()
        if not row:
            return None
        last = max(row['last_seen'], row['created_at'])
        if row['expires_at'] < now or now - last > SESSION_IDLE:
            c.execute('DELETE FROM sessions WHERE token_hash = ?', (th,))
            return None
        if now - last >= SESSION_TOUCH:
            c.execute('UPDATE sessions SET last_seen = ? WHERE token_hash = ?', (now, th))
    return row


def lookup_session(token):
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    th = _hash_token(token)
    row = check_session(th)
    # 'username' is the tag everybody sees (Bill[#00001]); 'plain' is the name alone, for the password check
    return {'id': row['id'], 'username': tag_of(row['username'], row['disc']), 'plain': row['username'],
            'th': th} if row else None


def revoke_sessions(uid, keep_th=None):
    """Delete every session of `uid` (except `keep_th`) and cut their open sockets."""
    with db() as c:
        if keep_th:
            c.execute('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', (uid, keep_th))
        else:
            c.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
    with LOCK:
        sids = [sid for sid, s in SIDS.items() if s['uid'] == uid and s['th'] != keep_th]
    for sid in sids:
        try:
            socketio.server.disconnect(sid)
        except Exception:
            pass


def reap_dead_sockets():
    """Disconnect sockets whose session no longer exists (expired, idle, revoked elsewhere)."""
    with LOCK:
        snapshot = [(sid, s['th']) for sid, s in SIDS.items()]
    if not snapshot:
        return
    with db() as c:
        alive = {r['token_hash'] for r in c.execute('SELECT token_hash FROM sessions')}
    for sid, th in snapshot:
        if th not in alive:
            try:
                socketio.server.disconnect(sid)
            except Exception:
                pass


def current_user():
    return lookup_session(request.cookies.get(COOKIE))


def need_user():
    u = current_user()
    if not u:
        abort(401)
    return u


def create_session(uid):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with db() as c:
        c.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
        c.execute('DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN '
                  '(SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)',
                  (uid, uid, MAX_SESSIONS_PER_USER - 1))
        c.execute('INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen) '
                  'VALUES (?, ?, ?, ?, ?)', (_hash_token(token), uid, now, now + SESSION_TTL, now))
    return token


# --------------------------------------------------------------------------
# HTTP routes
# --------------------------------------------------------------------------
@app.get('/')
def page_index():
    return send_from_directory(WEB_DIR, 'index.html', max_age=0)


@app.get('/chat')
def page_chat():
    return send_from_directory(WEB_DIR, 'chat.html', max_age=0)


@app.get('/health')
def health():
    return jsonify(status='ok')


@app.errorhandler(401)
def _e401(_):
    return fail('Not logged in.', 401)


@app.errorhandler(413)
def _e413(_):
    return fail('Request too large.', 413)


@app.errorhandler(404)
def _e404(_):
    return fail('Not found.', 404)


@app.errorhandler(405)
def _e405(_):
    return fail('Method not allowed.', 405)


@app.errorhandler(500)
def _e500(_):
    return fail('Internal error.', 500)


@app.get('/api/me')
def api_me():
    u = current_user()
    if not u:
        return fail('Not logged in.', 401)
    return jsonify(success=True, user={'user_id': u['id'], 'username': u['username']})


@app.post('/api/register')
def api_register():
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    data = json_body()
    ip = client_ip()
    if not RL.allow(('reg_ip', ip), REGISTER_PER_IP_HOUR, 3600) or \
            not RL.allow(('reg_all',), REGISTER_GLOBAL_HOUR, 3600):
        return fail('Too many registrations. Try again later.', 429, **{'Retry-After': 3600})
    parsed = valid_username(data.get('username'))
    if not parsed:
        return fail('Username: 2-20 letters/digits/space/_-. (no mixing Latin with Cyrillic/Greek, no reserved names).')
    name, key = parsed
    pw = data.get('password')
    problem = password_problem(pw, name)
    if problem:
        return fail(problem)
    with HASH_SEM:
        pw_hash = generate_password_hash(pw)
    for _ in range(10):
        code = gen_code(ACCOUNT_CODE_LEN)
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                disc = take_disc(c, key)
                if disc is None:
                    return fail(f'The name "{name}" is full ({MAX_DISC:,} numbers used). Choose another name.')
                c.execute('INSERT INTO users (username, username_key, disc, password_hash, unique_code) '
                          'VALUES (?, ?, ?, ?, ?)', (name, f'{key}#{disc:05d}', disc, pw_hash, code_digest(code)))
            return jsonify(success=True, unique_code=fmt_code(code), username=tag_of(name, disc))
        except sqlite3.IntegrityError:
            pass          # login-code collision (astronomically unlikely): the whole step rolled back, try a new code
    return fail('Registration failed.', 500)


@app.post('/api/login')
def api_login():
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    data = json_body()
    code = norm_code(data.get('unique_code'))
    pw = data.get('password')
    if not code or not isinstance(pw, str) or not pw:
        return fail('Unique code and password are required.')
    digest = code_digest(code)
    k_ip, k_code = ('login_ip', client_ip()), ('login_code', digest)
    if RL.count(k_ip, 600) >= 20 or RL.count(k_code, 900) >= 5:
        return fail('Too many failed attempts. Try again in a few minutes.', 429, **{'Retry-After': 900})
    with db() as c:
        row = c.execute('SELECT id, username, disc, password_hash FROM users WHERE unique_code = ?',
                        (digest,)).fetchone()
    ok = False
    if len(pw) <= 128:
        with HASH_SEM:
            ok = check_password_hash(row['password_hash'] if row else DUMMY_HASH, pw) and row is not None
    if not ok:
        RL.hit(k_ip, 600)
        RL.hit(k_code, 900)
        return fail('Invalid credentials.', 401)
    RL.clear(k_code)
    token = create_session(row['id'])
    resp = jsonify(success=True, user={'user_id': row['id'], 'username': tag_of(row['username'], row['disc'])})
    resp.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite='Strict',
                    secure=is_secure_request(), path='/')
    return resp


@app.post('/api/logout')
def api_logout():
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    token = request.cookies.get(COOKIE)
    if token:
        th = _hash_token(token)
        with db() as c:
            c.execute('DELETE FROM sessions WHERE token_hash = ?', (th,))
        with LOCK:
            sids = [sid for sid, s in SIDS.items() if s['th'] == th]
        for sid in sids:
            socketio.server.disconnect(sid)
    resp = jsonify(success=True)
    resp.delete_cookie(COOKIE, path='/', samesite='Strict', secure=is_secure_request(), httponly=True)
    return resp


@app.post('/api/logout_all')
def api_logout_all():
    """Log out of every device. With keep_current=true this browser stays signed in (the 'someone else is
    using my account' button); without it, this browser is logged out too."""
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    u = need_user()
    keep = json_body().get('keep_current') is True
    revoke_sessions(u['id'], u['th'] if keep else None)
    resp = jsonify(success=True, kept_current=keep)
    if not keep:
        resp.delete_cookie(COOKIE, path='/', samesite='Strict', secure=is_secure_request(), httponly=True)
    return resp


@app.post('/api/change_password')
def api_change_password():
    """New password for the logged-in user; every other session is revoked (a stolen cookie dies here)."""
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    u = need_user()
    data = json_body()
    old, new = data.get('old_password'), data.get('new_password')
    if not isinstance(old, str) or not old or not isinstance(new, str):
        return fail('Current and new password are required.')
    k_fail = ('pw_fail', u['id'])
    if RL.count(k_fail, 900) >= 5:
        return fail('Too many failed attempts. Try again in a few minutes.', 429, **{'Retry-After': 900})
    with db() as c:
        row = c.execute('SELECT password_hash FROM users WHERE id = ?', (u['id'],)).fetchone()
    ok = False
    if row and len(old) <= 128:
        with HASH_SEM:
            ok = check_password_hash(row['password_hash'], old)
    if not ok:
        RL.hit(k_fail, 900)
        return fail('Current password is wrong.', 403)
    problem = password_problem(new, u['plain'])
    if problem:
        return fail(problem)
    if new == old:
        return fail('The new password must be different from the current one.')
    with HASH_SEM:
        pw_hash = generate_password_hash(new)
    with db() as c:
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pw_hash, u['id']))
    RL.clear(k_fail)
    revoke_sessions(u['id'], u['th'])
    return jsonify(success=True)


@app.post('/api/delete_account')
def api_delete_account():
    """M7: the account, its messages and its uploaded files are removed for good. Needs the password and the full
    tag typed out. A server owner must delete or hand over their servers first: what happens to other people's
    rooms is not decided here. There is no undo and, by design, no recovery."""
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    u = need_user()
    data = json_body()
    pw, confirm = data.get('password'), data.get('confirm')
    if not isinstance(pw, str) or not pw or len(pw) > 128 or not isinstance(confirm, str):
        return fail('Password and confirmation are required.')
    k_fail = ('pw_fail', u['id'])
    if RL.count(k_fail, 900) >= 5:
        return fail('Too many failed attempts. Try again in a few minutes.', 429, **{'Retry-After': 900})
    with db() as c:
        row = c.execute('SELECT password_hash FROM users WHERE id = ?', (u['id'],)).fetchone()
    with HASH_SEM:
        ok = bool(row) and check_password_hash(row['password_hash'], pw)
    if not ok:
        RL.hit(k_fail, 900)
        return fail('Password is wrong.', 403)
    if confirm.strip() != u['username']:
        return fail(f"Type your full name to confirm: {u['username']}")
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT 1 FROM servers WHERE owner_id = ?', (u['id'],)).fetchone():
            return fail('You still own servers. Delete them or hand them over first.', 409)
        servers = [r['server_id'] for r in c.execute('SELECT server_id FROM server_members WHERE user_id = ?',
                                                     (u['id'],))]
        _drop_file_rows(c, c.execute('SELECT id, file_id, server_id, room_id, stored_filename FROM files '
                                     'WHERE user_id = ?', (u['id'],)).fetchall(), announce=False)
        c.execute('DELETE FROM users WHERE id = ?', (u['id'],))      # cascades: sessions, memberships, messages
    RL.clear(('pw_fail', u['id']))
    revoke_sessions(u['id'])
    for sv in servers:
        notify_members(sv, 'user_gone', {'user_id': u['id'], 'server_id': sv})
    resp = jsonify(success=True)
    resp.delete_cookie(COOKIE, path='/', samesite='Strict', secure=is_secure_request(), httponly=True)
    return resp


# ---- files ---------------------------------------------------------------
def file_category(ext):
    if ext in IMAGE_EXT:
        return 'image'
    if ext in VIDEO_EXT:
        return 'video'
    if ext in AUDIO_EXT:
        return 'audio'
    if ext in TEXT_EXT:
        return 'text'
    return 'file'


def clean_filename(raw):
    name = os.path.basename((raw or '').replace('\\', '/'))
    name = clean_text(name)
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', name).strip(' .')
    return name[-120:] or 'file'


def room_dir(server_id, room_id):
    return os.path.join(UPLOAD_ROOT, str(int(server_id)), str(int(room_id)))


def file_disk_path(row):
    p = safe_join(room_dir(row['server_id'], row['room_id']), row['stored_filename'])
    return p


UPLOAD_LOCK = threading.Lock()      # quota check + insert must be one step, or parallel uploads overshoot


def _drop_file_rows(c, rows, announce=True):
    """Remove files from disk and from the files table (rows need id, file_id, server_id, room_id, stored_filename).
    `announce` tells the room that the file is gone, so open clients swap the embed for a note instead of a broken
    picture. It is off when the message goes away too (nothing left to swap)."""
    for r in rows:
        p = file_disk_path(r)
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            log.exception('could not remove %s', p)
        c.execute('DELETE FROM files WHERE id = ?', (r['id'],))
        if announce:
            socketio.emit('file_gone', {'room_id': r['room_id'], 'file_id': r['file_id']}, to=f"room_{r['room_id']}")


def drop_message_file(c, m):
    """A file message takes its file with it, from disk too. `m` needs server_id, room_id, message_encrypted."""
    fd = parse_file_message(dec(m['message_encrypted']))
    if fd:
        _drop_file_rows(c, c.execute('SELECT id, file_id, server_id, room_id, stored_filename FROM files '
                                     'WHERE file_id = ? AND server_id = ? AND room_id = ?',
                                     (fd['file_id'], m['server_id'], m['room_id'])).fetchall(), announce=False)


def _delete_oldest_files():
    with db() as c:
        total = c.execute('SELECT COUNT(*) FROM files').fetchone()[0]
        if total <= MAX_TOTAL_FILES:
            return
        _drop_file_rows(c, c.execute('SELECT id, file_id, server_id, room_id, stored_filename FROM files '
                                     'ORDER BY id ASC LIMIT ?', (total - MAX_TOTAL_FILES,)).fetchall())


def make_room_for(c, uid, incoming):
    """Evict oldest files until `incoming` bytes fit under the per-user and the total cap.
    Returns None when it fits, else the reason it never can. The uploader's own files go first, so one
    person cannot push everybody else's files out."""
    user_cap = MAX_STORAGE_BYTES * USER_STORAGE_PCT // 100
    if incoming > MAX_STORAGE_BYTES:
        return 'File is larger than the whole storage quota of this server.'
    if incoming > user_cap:
        return f'File is larger than your storage quota ({user_cap // 1048576} MB).'
    cols = 'id, file_id, server_id, room_id, stored_filename, file_size'
    used = c.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = ?', (uid,)).fetchone()[0]
    if used + incoming > user_cap:
        drop = []
        for r in c.execute(f'SELECT {cols} FROM files WHERE user_id = ? ORDER BY id', (uid,)).fetchall():
            if used + incoming <= user_cap:
                break
            drop.append(r)
            used -= r['file_size']
        _drop_file_rows(c, drop)
    total = c.execute('SELECT COALESCE(SUM(file_size), 0) FROM files').fetchone()[0]
    if total + incoming > MAX_STORAGE_BYTES:
        drop = []
        for r in c.execute(f'SELECT {cols} FROM files ORDER BY id').fetchall():
            if total + incoming <= MAX_STORAGE_BYTES:
                break
            drop.append(r)
            total -= r['file_size']
        _drop_file_rows(c, drop)
    return None


def disk_free():
    try:
        return shutil.disk_usage(UPLOAD_ROOT).free
    except OSError:
        return MIN_FREE_BYTES * 2          # cannot tell: do not block uploads on a failed stat


@app.post('/upload')
def upload_file():
    if not same_origin_ok():
        return fail('Bad origin.', 403)
    u = need_user()
    uid = u['id']
    if not RL.allow(('upload', uid), 6, 60):
        return fail('Uploading too fast. Slow down.', 429)
    f = request.files.get('file')
    room_id = as_int(request.form.get('room_id', type=int))
    if not f or not room_id:
        return fail('No file or room.')
    name = clean_filename(f.filename)
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    if ext not in ALLOWED_EXTENSIONS:
        return fail('File type not allowed.')
    with db() as c:
        room = member_room(c, uid, room_id)
    if not room:
        return fail('Access denied to this room.', 403)
    ok, why = can_post(room, uid)
    if not ok:
        return fail(why, 403)
    # The declared body size is an upper bound for the file: refuse before reading it if the disk could not hold it.
    if disk_free() - (request.content_length or 0) < MIN_FREE_BYTES:
        return fail('The server is almost out of disk space; uploads are paused.', 507)

    file_id = str(uuid.uuid4())
    stored = f'{file_id}.{ext}'
    d = room_dir(room['server_id'], room_id)
    os.makedirs(d, exist_ok=True)
    final = os.path.join(d, stored)
    tmp = final + '.part'
    total = 0
    try:
        with open(tmp, 'wb') as out:
            while True:
                chunk = f.stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_SIZE:
                    break
                out.write(chunk)
        if total > MAX_FILE_SIZE:
            return fail(f'File too large (max {MAX_FILE_SIZE // 1048576} MB).', 413)
        if total == 0:
            return fail('Empty file not allowed.')
        if disk_free() < MIN_FREE_BYTES:
            return fail('The server is almost out of disk space; uploads are paused.', 507)

        category = file_category(ext)
        mime = {'svg': 'image/svg+xml'}.get(ext) or mimetypes.guess_type('x.' + ext)[0] or 'application/octet-stream'
        with UPLOAD_LOCK:
            with db() as c:
                why = make_room_for(c, uid, total)
                if not why:
                    c.execute('INSERT INTO files (file_id, server_id, room_id, user_id, original_filename, '
                              'stored_filename, file_size, mime_type, file_type_category) VALUES (?,?,?,?,?,?,?,?,?)',
                              (file_id, room['server_id'], room_id, uid, enc(name), stored, total, mime, category))
            if why:
                return fail(why, 413)
            try:
                os.replace(tmp, final)
            except OSError:
                with db() as c:
                    c.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
                raise
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    _delete_oldest_files()

    fdata = {'file_id': file_id, 'filename': name, 'file_type': category}
    mid = save_message(room_id, room['server_id'], uid, u['username'], 'FILE_EMBED:' + json.dumps(fdata), 'file')
    socketio.emit('new_message', {'id': mid, 'type': 'file', 'username': u['username'], 'user_id': uid,
                                  'ts': int(time.time() * 1000), 'file_data': fdata}, to=f'room_{room_id}')
    announce_activity(room['server_id'], room_id, uid)
    return jsonify(success=True, file_id=file_id)


@app.get('/files/<file_id>')
def download_file(file_id):
    u = need_user()
    if not FILE_ID_RE.match(file_id):
        abort(404)
    with db() as c:
        row = c.execute('SELECT f.* FROM files f JOIN server_members m '
                        'ON m.server_id = f.server_id AND m.user_id = ? WHERE f.file_id = ?',
                        (u['id'], file_id)).fetchone()
    if not row:
        abort(404)
    path = file_disk_path(row)
    if not path or not os.path.isfile(path):
        abort(404)
    resp = send_file(path, as_attachment=True, download_name=dec(row['original_filename']),
                     mimetype=row['mime_type'] or 'application/octet-stream', conditional=True, max_age=3600)
    resp.headers['Content-Security-Policy'] = "default-src 'none'; sandbox"
    resp.headers['Cache-Control'] = 'private, max-age=3600'
    return resp


# --------------------------------------------------------------------------
# Realtime state
# --------------------------------------------------------------------------
LOCK = threading.RLock()
SIDS = {}          # sid -> {uid, name, th, ip, room_id, server_id, checked}
ROOM_SIDS = {}     # room_id -> {sid}
CONNS = {}         # ip -> open connection count


def member_room(c, uid, room_id):
    """Room row if `uid` is a member of the room's server, else None."""
    return c.execute('SELECT r.id, r.server_id, r.is_locked, r.name_encrypted, r.topic_encrypted, r.retention_hours, '
                     's.owner_id, m.role FROM rooms r JOIN servers s ON s.id = r.server_id '
                     'JOIN server_members m ON m.server_id = r.server_id AND m.user_id = ? '
                     'WHERE r.id = ?', (uid, room_id)).fetchone()


def server_role(c, server_id, uid):
    """'owner', 'moderator' or 'member' when `uid` belongs to the server, else None."""
    r = c.execute('SELECT sv.owner_id, m.role FROM servers sv JOIN server_members m '
                  'ON m.server_id = sv.id AND m.user_id = ? WHERE sv.id = ?', (uid, server_id)).fetchone() \
        if server_id else None
    return None if not r else 'owner' if r['owner_id'] == uid else r['role']


def can_post(room, uid):
    lock = room['is_locked']
    if lock == LOCK_SYSTEM:
        return False, 'This channel is read-only.'
    if lock == LOCK_OWNER and uid != room['owner_id']:
        return False, 'Only the server owner can type in this channel.'
    return True, ''


def save_message(room_id, server_id, uid, username, text, mtype='user', reply_to=None):
    mid = str(uuid.uuid4())
    with db() as c:
        c.execute('INSERT INTO messages (message_id, room_id, server_id, user_id, username_encrypted, '
                  'message_encrypted, message_type, reply_to) VALUES (?,?,?,?,?,?,?,?)',
                  (mid, room_id, server_id, uid, enc(username), enc(text), mtype, reply_to))
        c.execute('DELETE FROM messages WHERE room_id = ? AND id NOT IN '
                  '(SELECT id FROM messages WHERE room_id = ? ORDER BY id DESC LIMIT ?)',
                  (room_id, room_id, MAX_MESSAGES_PER_ROOM))
    return mid


def post_system(room_id, server_id, uid, text):
    mid = save_message(room_id, server_id, uid, 'SYSTEM', text, 'system')
    socketio.emit('new_message', {'id': mid, 'type': 'system', 'message': text,
                                  'ts': int(time.time() * 1000)}, to=f'room_{room_id}')


def system_room_id(server_id):
    with db() as c:
        r = c.execute('SELECT id FROM rooms WHERE server_id = ? AND is_locked = ?',
                      (server_id, LOCK_SYSTEM)).fetchone()
    return r['id'] if r else None


def post_system_welcome(server_id, uid, text):
    """Join / leave / kick notices go to the server's system room, if it has one."""
    rid = system_room_id(server_id)
    if rid:
        post_system(rid, server_id, uid, text)


def parse_file_message(text):
    try:
        if not text.startswith('FILE_EMBED:'):
            return None
        d = json.loads(text[11:])
        fid, name, ft = d.get('file_id'), d.get('filename'), d.get('file_type')
        if not (isinstance(fid, str) and FILE_ID_RE.match(fid) and isinstance(name, str)
                and ft in ('image', 'video', 'audio', 'text', 'file')):
            return None
        return {'file_id': fid, 'filename': name[:255], 'file_type': ft}
    except Exception:
        return None


def files_on_disk(c, file_ids):
    """Which of these file ids still have both a row and a file on disk. History uses it to flag vanished files."""
    ids = list(file_ids)
    alive = set()
    for i in range(0, len(ids), 400):
        part = ids[i:i + 400]
        for r in c.execute('SELECT file_id, server_id, room_id, stored_filename FROM files WHERE file_id IN (%s)'
                           % ','.join('?' * len(part)), part):
            p = file_disk_path(r)
            if p and os.path.isfile(p):
                alive.add(r['file_id'])
    return alive


def load_messages(room_id, limit=MAX_MESSAGES_PER_ROOM):
    with db() as c:
        rows = c.execute("SELECT message_id, username_encrypted, message_encrypted, message_type, user_id, reply_to, "
                         "CAST(strftime('%s', timestamp) AS INTEGER) AS ts FROM messages "
                         "WHERE room_id = ? ORDER BY id DESC LIMIT ?", (room_id, limit)).fetchall()
    out = []
    for r in reversed(rows):
        text = dec(r['message_encrypted'])
        m = {'id': r['message_id'], 'type': r['message_type'], 'user_id': r['user_id'], 'ts': r['ts'] * 1000}
        if r['message_type'] == 'file':
            fd = parse_file_message(text)
            if not fd:
                continue
            m['file_data'] = fd
            m['username'] = dec(r['username_encrypted'])
        elif r['message_type'] == 'system':
            m['message'] = text
        else:
            m['type'] = 'user'
            m['message'] = text
            m['username'] = dec(r['username_encrypted'])
            if r['reply_to']:
                m['reply_to'] = r['reply_to']
        out.append(m)
    want = [m['file_data']['file_id'] for m in out if m.get('file_data')]
    if want:
        with db() as c:
            alive = files_on_disk(c, want)
        for m in out:
            if m.get('file_data') and m['file_data']['file_id'] not in alive:
                m['file_missing'] = True
    return out


def uemit(uid, event, data):
    socketio.emit(event, data, to=f'user_{uid}')


def notify_members(server_id, event, data, exclude=None):
    with db() as c:
        ids = [r['user_id'] for r in c.execute('SELECT user_id FROM server_members WHERE server_id = ?',
                                               (server_id,))]
    for uid in ids:
        if uid != exclude:
            uemit(uid, event, data)


def announce_activity(server_id, room_id, author_id):
    """M3: tell the other members that a room has something new. No text, no author: the client only counts.
    Membership comes from the database, so a member who was kicked a moment ago gets nothing."""
    notify_members(server_id, 'room_activity', {'server_id': server_id, 'room_id': room_id}, exclude=author_id)


def push_users(room_id):
    if not room_id:
        return
    with LOCK:
        seen = {}
        for sid in ROOM_SIDS.get(room_id, ()):
            s = SIDS.get(sid)
            if s:
                seen[s['uid']] = s['name']
    users = [{'id': k, 'name': v} for k, v in sorted(seen.items(), key=lambda kv: kv[1].lower())]
    socketio.emit('users_list', {'room_id': room_id, 'users': users}, to=f'room_{room_id}')


def drop_from_room(sid):
    """Remove a socket from its current room; returns the room id it left."""
    with LOCK:
        s = SIDS.get(sid)
        rid = s.get('room_id') if s else None
        if s:
            s['room_id'] = None
        if rid and rid in ROOM_SIDS:
            ROOM_SIDS[rid].discard(sid)
            if not ROOM_SIDS[rid]:
                del ROOM_SIDS[rid]
    if rid:
        try:
            socketio.server.leave_room(sid, f'room_{rid}', namespace='/')
        except Exception:
            pass
    return rid


def evict(uid, server_id, message):
    """Pull every socket of `uid` out of `server_id` (kick / leave / delete)."""
    with LOCK:
        sids = [sid for sid, s in SIDS.items() if s['uid'] == uid and s.get('server_id') == server_id]
    for sid in sids:
        rid = drop_from_room(sid)
        with LOCK:
            if sid in SIDS:
                SIDS[sid]['server_id'] = None
        socketio.emit('kicked_from_server_reload', {'message': message, 'server_id': server_id}, to=sid)
        push_users(rid)
    uemit(uid, 'servers_changed', {})


def wipe_uploads(server_id, room_id=None):
    p = room_dir(server_id, room_id) if room_id else os.path.join(UPLOAD_ROOT, str(int(server_id)))
    shutil.rmtree(p, ignore_errors=True)


def purge_expired(room_id=None):
    """M10: in rooms with a retention window, messages older than it are deleted, files included. Runs when a room is
    opened, when the window is set, and every 10 minutes. Open clients are told which lines to drop."""
    sql = ("SELECT m.id, m.message_id, m.room_id, m.server_id, m.message_type, m.message_encrypted FROM messages m "
           "JOIN rooms r ON r.id = m.room_id WHERE r.retention_hours IS NOT NULL "
           "AND m.timestamp < datetime('now', '-' || r.retention_hours || ' hours')")
    gone = {}
    with db() as c:
        for m in c.execute(sql + (' AND m.room_id = ?' if room_id else ''), (room_id,) if room_id else ()).fetchall():
            if m['message_type'] == 'file':
                drop_message_file(c, m)
            c.execute('DELETE FROM messages WHERE id = ?', (m['id'],))
            gone.setdefault(m['room_id'], []).append(m['message_id'])
    for rid, ids in gone.items():
        socketio.emit('messages_expired', {'room_id': rid, 'ids': ids}, to=f'room_{rid}')


def still_valid(s):
    """Re-check the session at most every 30 s; this is also what counts as 'activity' for the idle timer."""
    now = time.time()
    if now - s['checked'] < 30:
        return True
    ok = check_session(s['th']) is not None
    if ok:
        s['checked'] = now
    return ok


# --------------------------------------------------------------------------
# Socket.IO
# --------------------------------------------------------------------------
@socketio.on('connect')
def on_connect(auth=None):
    u = current_user()
    if not u:
        raise ConnectionRefusedError('unauthorized')
    ip = client_ip()
    with LOCK:
        if CONNS.get(ip, 0) >= MAX_CONNS_PER_IP:
            raise ConnectionRefusedError('too many connections')
        CONNS[ip] = CONNS.get(ip, 0) + 1
        SIDS[request.sid] = {'uid': u['id'], 'name': u['username'], 'th': u['th'], 'ip': ip,
                             'room_id': None, 'server_id': None, 'checked': time.time()}
    join_room(f"user_{u['id']}")
    emit('connection_confirmed', {'user_id': u['id'], 'username': u['username']})


@socketio.on('disconnect')
def on_disconnect(*_):
    sid = request.sid
    rid = drop_from_room(sid)
    with LOCK:
        s = SIDS.pop(sid, None)
        if s:
            CONNS[s['ip']] = max(0, CONNS.get(s['ip'], 1) - 1)
            if CONNS[s['ip']] == 0:
                del CONNS[s['ip']]
    RL.clear(('ev', sid))
    push_users(rid)


def sock_event(name, rate=(40, 10)):
    """Register a handler that only ever sees an authenticated session `s`."""
    def deco(fn):
        @socketio.on(name)
        @functools.wraps(fn)
        def wrapper(data=None):
            s = SIDS.get(request.sid)
            if not s or not still_valid(s):
                disconnect()
                return
            if not RL.allow(('ev', request.sid), *rate):
                emit('app_error', {'error': 'Too many requests, slow down.'})
                return
            try:
                fn(s, data if isinstance(data, dict) else {})
            except Exception:
                log.exception('socket event %s failed', name)
                emit('app_error', {'error': 'Internal error.'})
        return wrapper
    return deco


@sock_event('get_user_servers')
def h_get_user_servers(s, d):
    uid = s['uid']
    with db() as c:
        owned = c.execute('SELECT id, name_encrypted, server_code FROM servers '
                          'WHERE owner_id = ? ORDER BY id DESC', (uid,)).fetchall()
        joined = c.execute('SELECT sv.id, sv.name_encrypted FROM servers sv '
                           'JOIN server_members m ON m.server_id = sv.id '
                           'WHERE m.user_id = ? AND sv.owner_id != ? ORDER BY m.id DESC', (uid, uid)).fetchall()
    emit('servers_list', {
        'owned_servers': [{'id': r['id'], 'name': dec(r['name_encrypted']), 'code': r['server_code']} for r in owned],
        'joined_servers': [{'id': r['id'], 'name': dec(r['name_encrypted'])} for r in joined],
    })


@sock_event('create_server')
def h_create_server(s, d):
    uid = s['uid']
    name = text_field(d.get('name'), 1, 100)
    if name is None:
        emit('server_created', {'success': False, 'error': 'Invalid server name.'})
        return
    if not RL.allow(('mk_server', uid), 5, 3600):
        emit('server_created', {'success': False, 'error': 'Too many servers created. Try later.'})
        return
    with db() as c:
        if c.execute('SELECT COUNT(*) FROM servers WHERE owner_id = ?', (uid,)).fetchone()[0] >= MAX_SERVERS_PER_USER:
            emit('server_created', {'success': False, 'error': f'Limit: {MAX_SERVERS_PER_USER} servers per user.'})
            return
        code = new_server_code(c)
        sid_ = c.execute('INSERT INTO servers (name_encrypted, owner_id, server_code) VALUES (?,?,?)',
                         (enc(name), uid, code)).lastrowid
        c.execute('INSERT INTO server_members (server_id, user_id) VALUES (?, ?)', (sid_, uid))
        for rname, lock in DEFAULT_ROOMS:
            c.execute('INSERT INTO rooms (server_id, name_encrypted, created_by, is_locked) VALUES (?,?,?,?)',
                      (sid_, enc(rname), uid, lock))
    emit('server_created', {'success': True, 'server_id': sid_})


def new_server_code(c):
    """A code nobody uses yet, as a server code or as an invite (both are typed into the same box)."""
    for _ in range(20):
        code = gen_code(SERVER_CODE_LEN)
        if not c.execute('SELECT 1 FROM servers WHERE server_code = ? UNION SELECT 1 FROM invites WHERE code = ?',
                         (code, code)).fetchone():
            return code
    raise RuntimeError('could not allocate server code')


def members_changed(server_id):
    notify_members(server_id, 'members_changed', {'server_id': server_id})


@sock_event('join_server')
def h_join_server(s, d):
    uid = s['uid']

    def refuse(msg):
        emit('server_joined', {'success': False, 'error': msg})

    code = norm_code(d.get('server_code'))
    if RL.count(('join_fail', uid), 600) >= 5 or not RL.allow(('join_ip', s['ip']), 30, 600):
        return refuse('Too many attempts. Try again in a few minutes.')
    if not code:
        RL.hit(('join_fail', uid), 600)
        return refuse('Invalid server code.')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')       # "is the invite still good" and "I am in" are one step: a one-use link cannot be used twice
        srv = c.execute('SELECT id, name_encrypted FROM servers WHERE server_code = ?', (code,)).fetchone()
        invite = False
        if not srv:
            inv = c.execute('SELECT server_id FROM invites WHERE code = ?', (code,)).fetchone()
            srv = inv and c.execute('SELECT id, name_encrypted FROM servers WHERE id = ?', (inv['server_id'],)).fetchone()
            invite = bool(srv)
        if not srv:
            RL.hit(('join_fail', uid), 600)
            return refuse('Invalid server code.')
        if c.execute('SELECT 1 FROM bans WHERE server_id = ? AND user_id = ?', (srv['id'], uid)).fetchone():
            return refuse('You are banned from this server.')
        if c.execute('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                     (srv['id'], uid)).fetchone():
            return refuse('Already a member of this server.')
        if c.execute('SELECT COUNT(*) FROM server_members WHERE server_id = ?',
                     (srv['id'],)).fetchone()[0] >= MAX_MEMBERS_PER_SERVER:
            return refuse('This server is full.')
        if invite and c.execute('UPDATE invites SET uses = uses + 1 WHERE code = ? AND (max_uses IS NULL OR '
                                'uses < max_uses) AND (expires_at IS NULL OR expires_at > ?)',
                                (code, int(time.time()))).rowcount != 1:
            RL.hit(('join_fail', uid), 600)
            return refuse('This invite has expired or was used up.')
        c.execute('INSERT INTO server_members (server_id, user_id) VALUES (?, ?)', (srv['id'], uid))
    post_system_welcome(srv['id'], uid, f"{s['name']} joined the server")
    members_changed(srv['id'])
    emit('server_joined', {'success': True, 'server_id': srv['id'], 'server_name': dec(srv['name_encrypted'])})


@sock_event('leave_server')
def h_leave_server(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        srv = c.execute('SELECT owner_id FROM servers WHERE id = ?', (server_id,)).fetchone() if server_id else None
        member = srv and c.execute('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                                   (server_id, uid)).fetchone()
        if not member:
            emit('server_left', {'success': False, 'error': 'Not a member of this server.'})
            return
        if srv['owner_id'] == uid:
            emit('server_left', {'success': False,
                                 'error': 'Server owners cannot leave. Transfer the server or delete it instead.'})
            return
        c.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', (server_id, uid))
    evict(uid, server_id, 'You left this server.')
    post_system_welcome(server_id, uid, f"{s['name']} left the server")
    members_changed(server_id)
    emit('server_left', {'success': True, 'message': 'Successfully left server', 'server_id': server_id})


@sock_event('get_server_data')
def h_get_server_data(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        row = c.execute('SELECT sv.id, sv.name_encrypted, sv.owner_id, sv.server_code, m.role '
                        'FROM servers sv JOIN server_members m ON m.server_id = sv.id AND m.user_id = ? '
                        'WHERE sv.id = ?', (uid, server_id)).fetchone() if server_id else None
        if not row:
            emit('server_data', {'success': False, 'error': 'Not a member of this server.'})
            return
        rooms = c.execute('SELECT id, name_encrypted, is_locked, topic_encrypted, retention_hours FROM rooms '
                          'WHERE server_id = ? ORDER BY id', (server_id,)).fetchall()
    with LOCK:
        s['server_id'] = server_id
    server = {'id': row['id'], 'name': dec(row['name_encrypted']), 'owner_id': row['owner_id'],
              'role': 'owner' if row['owner_id'] == uid else row['role']}
    if row['owner_id'] == uid:
        server['server_code'] = row['server_code']
    emit('server_data', {'success': True, 'server': server, 'rooms': [
        {'id': r['id'], 'name': dec(r['name_encrypted']), 'is_locked': r['is_locked'],
         'topic': dec(r['topic_encrypted']), 'retention_hours': r['retention_hours']} for r in rooms]})


@sock_event('join_room')
def h_join_room(s, d):
    uid = s['uid']
    rid = as_int(d.get('room_id'))
    with db() as c:
        room = member_room(c, uid, rid) if rid else None
    if not room:
        emit('room_error', {'error': 'Access denied to this room.'})
        return
    purge_expired(rid)
    prev = drop_from_room(request.sid)
    push_users(prev)
    join_room(f'room_{rid}')
    with LOCK:
        s['room_id'] = rid
        s['server_id'] = room['server_id']
        ROOM_SIDS.setdefault(rid, set()).add(request.sid)
    emit('room_joined', {'room_id': rid, 'server_id': room['server_id'], 'room_name': dec(room['name_encrypted']),
                         'messages': load_messages(rid), 'is_locked': room['is_locked'],
                         'topic': dec(room['topic_encrypted']), 'retention_hours': room['retention_hours']})
    push_users(rid)


@sock_event('send_message', rate=(60, 10))
def h_send_message(s, d):
    uid = s['uid']
    text = text_field(d.get('message'), 1, MAX_MESSAGE_CHARS, multiline=True)
    if text is None or text.count('\n') >= MAX_MESSAGE_LINES:
        emit('message_error', {'error': f'Message must be 1-{MAX_MESSAGE_CHARS} characters.'})
        return
    reply = d.get('reply_to')
    if reply is not None and not (isinstance(reply, str) and FILE_ID_RE.match(reply)):
        emit('message_error', {'error': 'Invalid reply.'})
        return
    rid = s['room_id']
    if not rid:
        emit('message_error', {'error': 'Join a room first.'})
        return
    if not RL.allow(('msg', uid), 8, 5):
        emit('message_error', {'error': 'You are sending messages too fast.'})
        return
    with db() as c:
        room = member_room(c, uid, rid)
        # the answered line must sit in this very room (not another one, not a system notice) and still exist
        gone = reply and not c.execute("SELECT 1 FROM messages WHERE message_id = ? AND room_id = ? AND "
                                       "message_type != 'system'", (reply, rid)).fetchone()
    if not room:
        emit('message_error', {'error': 'You are not a member of this server.'})
        return
    ok, why = can_post(room, uid)
    if not ok:
        emit('message_error', {'error': why})
        return
    if gone:
        emit('message_error', {'error': 'The message you are replying to is gone.'})
        return
    mid = save_message(rid, room['server_id'], uid, s['name'], text, reply_to=reply)
    out = {'id': mid, 'type': 'user', 'username': s['name'], 'user_id': uid, 'message': text,
           'ts': int(time.time() * 1000)}
    if reply:
        out['reply_to'] = reply
    socketio.emit('new_message', out, to=f'room_{rid}')
    announce_activity(room['server_id'], rid, uid)


@sock_event('delete_message')
def h_delete_message(s, d):
    """Author deletes their own message; the server owner and moderators delete any (system lines included).
    A file message takes its file with it, from disk too."""
    uid = s['uid']
    mid = d.get('message_id')

    def refuse(msg):
        emit('delete_result', {'success': False, 'error': msg})

    if not isinstance(mid, str) or not FILE_ID_RE.match(mid):
        return refuse('Message not found.')
    with db() as c:
        # the join on server_members means non-members cannot even learn that a message id exists
        m = c.execute('SELECT m.id, m.room_id, m.server_id, m.user_id, m.message_type, m.message_encrypted, '
                      'sv.owner_id, sm.role FROM messages m JOIN servers sv ON sv.id = m.server_id '
                      'JOIN server_members sm ON sm.server_id = m.server_id AND sm.user_id = ? '
                      'WHERE m.message_id = ?', (uid, mid)).fetchone()
        if not m:
            return refuse('Message not found.')
        staff = m['owner_id'] == uid or m['role'] == 'moderator'
        if not (staff or (m['user_id'] == uid and m['message_type'] != 'system')):
            return refuse('You can only delete your own messages.')
        if m['message_type'] == 'file':
            drop_message_file(c, m)
        c.execute('DELETE FROM messages WHERE id = ?', (m['id'],))
    socketio.emit('message_deleted', {'id': mid, 'room_id': m['room_id']}, to=f"room_{m['room_id']}")
    emit('delete_result', {'success': True, 'id': mid})


@sock_event('change_nickname')
def h_change_nickname(s, d):
    uid = s['uid']
    parsed = valid_username(d.get('new_nick'))
    if not parsed:
        emit('nickname_error', {'error': 'Invalid nickname (2-20 letters/digits/space/_-.).'})
        return
    if not RL.allow(('nick', uid), 3, 300):
        emit('nickname_error', {'error': 'Changing nickname too often.'})
        return
    new, key = parsed
    old = s['name']
    try:
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            cur = c.execute('SELECT username_key, disc FROM users WHERE id = ?', (uid,)).fetchone()
            same = cur['username_key'].rsplit('#', 1)[0] == key
            if same:                                   # only the spelling changes (Bill -> BILL): the number stays
                disc = cur['disc']
            else:
                if RL.count(('nick_day', uid), 86400) >= NICK_CHANGES_PER_DAY:
                    emit('nickname_error', {'error': 'Too many name changes today. Try again tomorrow.'})
                    return
                disc = take_disc(c, key)
                if disc is None:
                    emit('nickname_error', {'error': f'The name "{new}" is full. Choose another one.'})
                    return
            c.execute('UPDATE users SET username = ?, username_key = ?, disc = ? WHERE id = ?',
                      (new, f'{key}#{disc:05d}', disc, uid))
    except sqlite3.IntegrityError:
        emit('nickname_error', {'error': 'Could not change the nickname.'})
        return
    if not same:
        RL.hit(('nick_day', uid), 86400)
    tag = tag_of(new, disc)
    rooms = set()
    with LOCK:
        for other in SIDS.values():
            if other['uid'] == uid:
                other['name'] = tag
                if other['room_id']:
                    rooms.add(other['room_id'])
    emit('nickname_changed', {'success': True, 'new_nick': tag})
    if s['room_id'] and old != tag:
        post_system(s['room_id'], s['server_id'], uid, f'{old} is now known as {tag}')
    for rid in rooms:
        push_users(rid)
    for sv in servers_of(uid):
        members_changed(sv)


def servers_of(uid):
    with db() as c:
        return [r['server_id'] for r in c.execute('SELECT server_id FROM server_members WHERE user_id = ?', (uid,))]


@sock_event('create_room')
def h_create_room(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    name = text_field(d.get('room_name'), 1, 50)
    if not server_id or name is None:
        emit('room_created', {'success': False, 'error': 'Invalid room name.'})
        return
    if not RL.allow(('mk_room', uid), 10, 60):
        emit('room_created', {'success': False, 'error': 'Creating rooms too fast.'})
        return
    with db() as c:
        srv = c.execute('SELECT owner_id FROM servers WHERE id = ?', (server_id,)).fetchone()
        if not srv or srv['owner_id'] != uid:
            emit('room_created', {'success': False, 'error': 'Only server owners can create rooms.'})
            return
        existing = c.execute('SELECT name_encrypted FROM rooms WHERE server_id = ?', (server_id,)).fetchall()
        if len(existing) >= MAX_ROOMS_PER_SERVER:
            emit('room_created', {'success': False, 'error': f'Limit: {MAX_ROOMS_PER_SERVER} rooms per server.'})
            return
        if any(dec(r['name_encrypted']).lower() == name.lower() for r in existing):
            emit('room_created', {'success': False, 'error': 'Room name already exists.'})
            return
        rid = c.execute('INSERT INTO rooms (server_id, name_encrypted, created_by, is_locked) VALUES (?,?,?,0)',
                        (server_id, enc(name), uid)).lastrowid
    notify_members(server_id, 'rooms_changed', {'server_id': server_id})
    emit('room_created', {'success': True, 'room_id': rid, 'room_name': name})


@sock_event('delete_room')
def h_delete_room(s, d):
    uid = s['uid']
    rid = as_int(d.get('room_id'))
    with db() as c:
        row = c.execute('SELECT r.server_id, sv.owner_id FROM rooms r JOIN servers sv '
                        'ON sv.id = r.server_id WHERE r.id = ?', (rid,)).fetchone() if rid else None
        if not row or row['owner_id'] != uid:
            emit('room_deleted', {'success': False, 'error': 'Only server owners can delete rooms.'})
            return
        if c.execute('SELECT COUNT(*) FROM rooms WHERE server_id = ?', (row['server_id'],)).fetchone()[0] <= 1:
            emit('room_deleted', {'success': False, 'error': 'A server needs at least one room.'})
            return
        c.execute('DELETE FROM rooms WHERE id = ?', (rid,))          # cascades to messages + files
    with LOCK:
        sids = list(ROOM_SIDS.get(rid, ()))
    for sid in sids:
        drop_from_room(sid)
        socketio.emit('room_closed', {'room_id': rid}, to=sid)
    wipe_uploads(row['server_id'], rid)
    notify_members(row['server_id'], 'rooms_changed', {'server_id': row['server_id']})
    emit('room_deleted', {'success': True, 'message': 'Room deleted.'})


@sock_event('delete_server')
def h_delete_server(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        srv = c.execute('SELECT owner_id FROM servers WHERE id = ?', (server_id,)).fetchone() if server_id else None
        if not srv or srv['owner_id'] != uid:
            emit('server_deleted', {'success': False, 'error': 'Only the server owner can delete this server.'})
            return
        members = [r['user_id'] for r in c.execute('SELECT user_id FROM server_members WHERE server_id = ?',
                                                   (server_id,))]
        c.execute('DELETE FROM servers WHERE id = ?', (server_id,))
    for m in members:
        evict(m, server_id, 'This server was deleted by its owner.')
    wipe_uploads(server_id)
    emit('server_deleted', {'success': True, 'server_id': server_id})


@sock_event('kick_user')
def h_kick_user(s, d):
    """The owner removes anyone; a moderator removes ordinary members only."""
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    target = as_int(d.get('user_id'))

    def refuse(msg):
        emit('kick_result', {'success': False, 'error': msg})

    if not server_id or not target:
        return refuse('Invalid request.')
    if target == uid:
        return refuse('Cannot kick yourself.')
    with db() as c:
        role = server_role(c, server_id, uid)
        if role not in ('owner', 'moderator'):
            return refuse('Only the server owner or a moderator can kick users.')
        victim = c.execute('SELECT u.username, u.disc, m.role, sv.owner_id FROM server_members m '
                           'JOIN users u ON u.id = m.user_id JOIN servers sv ON sv.id = m.server_id '
                           'WHERE m.server_id = ? AND m.user_id = ?', (server_id, target)).fetchone()
        if not victim:
            return refuse('User is not a member of this server.')
        if victim['owner_id'] == target:
            return refuse('The server owner cannot be removed.')
        if role == 'moderator' and victim['role'] == 'moderator':
            return refuse('Moderators cannot remove each other.')
        c.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', (server_id, target))
        # Renew the server code and drop the invites, otherwise the kicked user just walks back in with the one he knows.
        new_code = new_server_code(c)
        c.execute('UPDATE servers SET server_code = ? WHERE id = ?', (new_code, server_id))
        c.execute('DELETE FROM invites WHERE server_id = ?', (server_id,))
    who = tag_of(victim['username'], victim['disc'])
    evict(target, server_id, 'You have been removed from this server.')
    post_system_welcome(server_id, target, f"{who} was removed from the server by {s['name']}")
    uemit(victim['owner_id'], 'servers_changed', {})
    members_changed(server_id)
    emit('kick_result', {'success': True, 'message': f'{who} was removed. The server code was renewed and the invite codes revoked.'})


@sock_event('rotate_code')
def h_rotate_code(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        srv = c.execute('SELECT owner_id FROM servers WHERE id = ?', (server_id,)).fetchone() if server_id else None
        if not srv or srv['owner_id'] != uid:
            emit('code_rotated', {'success': False, 'error': 'Only the server owner can do that.'})
            return
        code = new_server_code(c)
        c.execute('UPDATE servers SET server_code = ? WHERE id = ?', (code, server_id))
    uemit(uid, 'servers_changed', {})
    emit('code_rotated', {'success': True, 'server_id': server_id, 'code': code})


def _owner_of(c, server_id, uid):
    srv = c.execute('SELECT owner_id, name_encrypted FROM servers WHERE id = ?', (server_id,)).fetchone() \
        if server_id else None
    return srv if srv and srv['owner_id'] == uid else None


@sock_event('get_members')
def h_get_members(s, d):
    """Everyone in the server, online first. Owner and moderators only: presence is not for the whole server."""
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        if server_role(c, server_id, uid) not in ('owner', 'moderator'):
            emit('members_list', {'success': False, 'error': 'Only the server owner or a moderator can see this list.'})
            return
        rows = c.execute('SELECT u.id, u.username, u.disc, m.role, sv.owner_id FROM server_members m '
                         'JOIN users u ON u.id = m.user_id JOIN servers sv ON sv.id = m.server_id '
                         'WHERE m.server_id = ?', (server_id,)).fetchall()
    with LOCK:
        online = {x['uid'] for x in SIDS.values()}
    members = [{'user_id': r['id'], 'name': tag_of(r['username'], r['disc']), 'online': r['id'] in online,
                'role': 'owner' if r['owner_id'] == r['id'] else r['role']} for r in rows]
    members.sort(key=lambda m: (not m['online'], m['name'].lower()))
    emit('members_list', {'success': True, 'server_id': server_id, 'members': members})


@sock_event('set_role')
def h_set_role(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    target = as_int(d.get('user_id'))
    role = d.get('role')

    def refuse(msg):
        emit('role_result', {'success': False, 'error': msg})

    if not target or role not in ROLES:
        return refuse('Invalid request.')
    with db() as c:
        if not _owner_of(c, server_id, uid):
            return refuse('Only the server owner can appoint moderators.')
        if target == uid:
            return refuse('The owner already has every right.')
        if c.execute('UPDATE server_members SET role = ? WHERE server_id = ? AND user_id = ?',
                     (role, server_id, target)).rowcount != 1:
            return refuse('User is not a member of this server.')
    notify_members(server_id, 'rooms_changed', {'server_id': server_id})      # members re-read their own role
    members_changed(server_id)
    emit('role_result', {'success': True, 'user_id': target, 'role': role})


@sock_event('ban_user')
def h_ban_user(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    target = as_int(d.get('user_id'))

    def refuse(msg):
        emit('ban_result', {'success': False, 'error': msg})

    if not target or target == uid:
        return refuse('Invalid request.')
    with db() as c:
        if not _owner_of(c, server_id, uid):
            return refuse('Only the server owner can ban users.')
        victim = c.execute('SELECT u.username, u.disc FROM server_members m JOIN users u ON u.id = m.user_id '
                           'WHERE m.server_id = ? AND m.user_id = ?', (server_id, target)).fetchone()
        if not victim:
            return refuse('User is not a member of this server.')
        c.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', (server_id, target))
        c.execute('INSERT OR IGNORE INTO bans (server_id, user_id) VALUES (?, ?)', (server_id, target))
    who = tag_of(victim['username'], victim['disc'])
    evict(target, server_id, 'You have been banned from this server.')
    post_system_welcome(server_id, target, f"{who} was banned from the server by {s['name']}")
    members_changed(server_id)
    emit('ban_result', {'success': True, 'message': f'{who} was banned.'})


@sock_event('unban_user')
def h_unban_user(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    target = as_int(d.get('user_id'))
    with db() as c:
        if not _owner_of(c, server_id, uid):
            emit('ban_result', {'success': False, 'error': 'Only the server owner can do that.'})
            return
        n = c.execute('DELETE FROM bans WHERE server_id = ? AND user_id = ?', (server_id, target)).rowcount if target else 0
    emit('ban_result', {'success': bool(n), 'message': 'Ban lifted.', 'error': 'That user is not banned.'})


@sock_event('get_bans')
def h_get_bans(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        if not _owner_of(c, server_id, uid):
            emit('bans_list', {'success': False, 'error': 'Only the server owner can see the ban list.'})
            return
        rows = c.execute('SELECT u.id, u.username, u.disc FROM bans b JOIN users u ON u.id = b.user_id '
                         'WHERE b.server_id = ? ORDER BY b.rowid DESC', (server_id,)).fetchall()
    emit('bans_list', {'success': True, 'server_id': server_id,
                       'bans': [{'user_id': r['id'], 'name': tag_of(r['username'], r['disc'])} for r in rows]})


@sock_event('transfer_owner')
def h_transfer_owner(s, d):
    """The owner hands the server to a member. The old owner stays on as an ordinary member."""
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    target = as_int(d.get('user_id'))
    confirm = d.get('confirm')

    def refuse(msg):
        emit('transfer_result', {'success': False, 'error': msg})

    if not target or target == uid:
        return refuse('Choose another member.')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        srv = _owner_of(c, server_id, uid)
        if not srv:
            return refuse('Only the server owner can transfer ownership.')
        if not isinstance(confirm, str) or confirm.strip() != dec(srv['name_encrypted']):
            return refuse('Type the server name exactly to confirm.')
        new = c.execute('SELECT u.username, u.disc FROM server_members m JOIN users u ON u.id = m.user_id '
                        'WHERE m.server_id = ? AND m.user_id = ?', (server_id, target)).fetchone()
        if not new:
            return refuse('The new owner must be a member of the server.')
        if c.execute('SELECT COUNT(*) FROM servers WHERE owner_id = ?', (target,)).fetchone()[0] >= MAX_SERVERS_PER_USER:
            return refuse('That user already owns the maximum number of servers.')
        c.execute('UPDATE servers SET owner_id = ? WHERE id = ?', (target, server_id))
        c.execute("UPDATE server_members SET role = 'member' WHERE server_id = ? AND user_id = ?", (server_id, target))
    who = tag_of(new['username'], new['disc'])
    post_system_welcome(server_id, target, f"{s['name']} handed the server over to {who}")
    notify_members(server_id, 'rooms_changed', {'server_id': server_id})
    members_changed(server_id)
    for u in (uid, target):
        uemit(u, 'servers_changed', {})
    emit('transfer_result', {'success': True, 'message': f'{who} is the new owner.'})


@sock_event('set_topic')
def h_set_topic(s, d):
    """Owner or moderator. An empty topic clears it."""
    uid = s['uid']
    rid = as_int(d.get('room_id'))
    topic = text_field(d.get('topic') or '', 0, MAX_TOPIC_CHARS)
    if not rid or topic is None:
        emit('topic_result', {'success': False, 'error': f'The topic can be up to {MAX_TOPIC_CHARS} characters.'})
        return
    with db() as c:
        room = member_room(c, uid, rid)
        if not room or not (room['owner_id'] == uid or room['role'] == 'moderator'):
            emit('topic_result', {'success': False, 'error': 'Only the server owner or a moderator can set the topic.'})
            return
        c.execute('UPDATE rooms SET topic_encrypted = ? WHERE id = ?', (enc(topic) if topic else None, rid))
    socketio.emit('topic_changed', {'room_id': rid, 'topic': topic}, to=f'room_{rid}')
    notify_members(room['server_id'], 'rooms_changed', {'server_id': room['server_id']})
    emit('topic_result', {'success': True})


@sock_event('set_retention')
def h_set_retention(s, d):
    """Owner: messages in this room vanish after N hours (0 = off). The newest-512 rule always applies."""
    uid = s['uid']
    rid = as_int(d.get('room_id'))
    hours = d.get('hours')
    if not rid or type(hours) is not int or (hours and hours not in RETENTION_CHOICES):
        emit('retention_result', {'success': False, 'error': 'Invalid request.'})
        return
    with db() as c:
        row = c.execute('SELECT r.server_id, sv.owner_id FROM rooms r JOIN servers sv ON sv.id = r.server_id '
                        'WHERE r.id = ?', (rid,)).fetchone()
        if not row or row['owner_id'] != uid:
            emit('retention_result', {'success': False, 'error': 'Only the server owner can do that.'})
            return
        c.execute('UPDATE rooms SET retention_hours = ? WHERE id = ?', (hours or None, rid))
    purge_expired(rid)
    socketio.emit('retention_changed', {'room_id': rid, 'hours': hours or None}, to=f'room_{rid}')
    notify_members(row['server_id'], 'rooms_changed', {'server_id': row['server_id']})
    emit('retention_result', {'success': True})


def _set_kind(s, rid, kind, result_event):
    uid = s['uid']
    with db() as c:
        row = c.execute('SELECT r.server_id, sv.owner_id FROM rooms r JOIN servers sv ON sv.id = r.server_id '
                        'WHERE r.id = ?', (rid,)).fetchone() if rid else None
        if not row or row['owner_id'] != uid:
            emit(result_event, {'success': False, 'error': 'Only server owners can change a channel.'})
            return
        if kind == LOCK_SYSTEM and c.execute('SELECT 1 FROM rooms WHERE server_id = ? AND is_locked = ? AND id != ?',
                                             (row['server_id'], LOCK_SYSTEM, rid)).fetchone():
            emit(result_event, {'success': False, 'error': 'This server already has a system room.'})
            return
        c.execute('UPDATE rooms SET is_locked = ? WHERE id = ?', (kind, rid))
    what = {LOCK_OPEN: 'opened for everyone', LOCK_OWNER: 'locked to the owner', LOCK_SYSTEM: 'made a read-only system room'}[kind]
    socketio.emit('channel_lock_status', {
        'room_id': rid, 'locked': kind != LOCK_OPEN, 'kind': kind,
        'message': f'Channel has been {what} by the server owner'}, to=f'room_{rid}')
    notify_members(row['server_id'], 'rooms_changed', {'server_id': row['server_id']})
    emit(result_event, {'success': True, 'locked': kind != LOCK_OPEN, 'kind': kind})


@sock_event('lock_channel')
def h_lock_channel(s, d):
    rid = as_int(d.get('room_id'))
    lock = d.get('lock')
    if not rid or not isinstance(lock, bool):
        emit('lock_result', {'success': False, 'error': 'Invalid request.'})
        return
    _set_kind(s, rid, LOCK_OWNER if lock else LOCK_OPEN, 'lock_result')


@sock_event('set_room_kind')
def h_set_room_kind(s, d):
    rid = as_int(d.get('room_id'))
    kind = d.get('kind')
    if not rid or type(kind) is not int or kind not in (LOCK_OPEN, LOCK_OWNER, LOCK_SYSTEM):
        emit('kind_result', {'success': False, 'error': 'Invalid request.'})
        return
    _set_kind(s, rid, kind, 'kind_result')


def _active_invites(c, server_id):
    return c.execute('SELECT code, expires_at, max_uses, uses FROM invites WHERE server_id = ? AND '
                     '(expires_at IS NULL OR expires_at > ?) AND (max_uses IS NULL OR uses < max_uses) '
                     'ORDER BY rowid DESC', (server_id, int(time.time()))).fetchall()


def _invite_json(r):
    return {'code': r['code'], 'expires_at': r['expires_at'], 'max_uses': r['max_uses'], 'uses': r['uses']}


@sock_event('create_invite')
def h_create_invite(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    hours, uses = d.get('hours'), d.get('uses')
    if type(hours) is not int or hours not in INVITE_HOURS or type(uses) is not int or uses not in INVITE_USES:
        emit('invite_created', {'success': False, 'error': 'Invalid request.'})
        return
    with db() as c:
        if not _owner_of(c, server_id, uid):
            emit('invite_created', {'success': False, 'error': 'Only the server owner can create invite links.'})
            return
        if len(_active_invites(c, server_id)) >= MAX_INVITES_PER_SERVER:
            emit('invite_created', {'success': False,
                                    'error': f'Limit: {MAX_INVITES_PER_SERVER} active invites. Revoke one first.'})
            return
        code = new_server_code(c)
        c.execute('INSERT INTO invites (code, server_id, expires_at, max_uses) VALUES (?,?,?,?)',
                  (code, server_id, int(time.time()) + hours * 3600, uses or None))
    emit('invite_created', {'success': True, 'server_id': server_id, 'code': code})


@sock_event('list_invites')
def h_list_invites(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    with db() as c:
        if not _owner_of(c, server_id, uid):
            emit('invites_list', {'success': False, 'error': 'Only the server owner can see invite links.'})
            return
        rows = _active_invites(c, server_id)
    emit('invites_list', {'success': True, 'server_id': server_id, 'invites': [_invite_json(r) for r in rows]})


@sock_event('revoke_invite')
def h_revoke_invite(s, d):
    uid = s['uid']
    server_id = as_int(d.get('server_id'))
    code = norm_code(d.get('code'))
    with db() as c:
        if not _owner_of(c, server_id, uid) or not code:
            emit('invite_revoked', {'success': False, 'error': 'Only the server owner can do that.'})
            return
        c.execute('DELETE FROM invites WHERE code = ? AND server_id = ?', (code, server_id))
    emit('invite_revoked', {'success': True, 'server_id': server_id})


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------
def sweep_partial_uploads(max_age=3600):
    """Remove *.part files a crashed upload left behind (they would silently eat the disk)."""
    cutoff = time.time() - max_age
    for root, _dirs, files in os.walk(UPLOAD_ROOT):
        for name in files:
            if name.endswith('.part'):
                p = os.path.join(root, name)
                try:
                    if os.path.getmtime(p) < cutoff:
                        os.remove(p)
                except OSError:
                    pass


def housekeeping():
    while True:
        time.sleep(600)
        try:
            now = int(time.time())
            with db() as c:
                c.execute('DELETE FROM sessions WHERE expires_at < ? OR MAX(last_seen, created_at) < ?',
                          (now, now - SESSION_IDLE))
                c.execute('DELETE FROM invites WHERE expires_at < ? OR (max_uses IS NOT NULL AND uses >= max_uses)',
                          (now,))
            purge_expired()
            reap_dead_sockets()
            sweep_partial_uploads()
            RL.gc()
        except Exception:
            log.exception('housekeeping failed')


def gen_cert(host):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    os.makedirs(TLS_DIR, mode=0o700, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    sans = []
    for h in dict.fromkeys((host, 'localhost', '127.0.0.1')):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))
    now = datetime.datetime.now(datetime.timezone.utc)
    pub = key.public_key()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pub)
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pub), critical=False)
            .sign(key, hashes.SHA256()))
    kp, cp = os.path.join(TLS_DIR, 'key.pem'), os.path.join(TLS_DIR, 'cert.pem')
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cp, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f'Self-signed certificate written to {TLS_DIR} (valid 365 days, CN={host}).')
    print('Browsers will warn once; for a public domain put Caddy/nginx in front instead.')


def bootstrap():
    os.umask(0o077)
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.makedirs(UPLOAD_ROOT, mode=0o700, exist_ok=True)
    if os.path.commonpath([DATA_DIR, WEB_DIR]) == WEB_DIR:
        sys.exit('TERMINET_DATA must not be inside the web/ folder.')
    _init_crypto()
    init_db()


def create_app():
    """S12: the entry point for a production WSGI server (see README):
    gunicorn -w 1 --threads 100 'terminet_server:create_app()'   (ONE worker: sessions, limiters and room state live in memory)"""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    bootstrap()
    threading.Thread(target=housekeeping, daemon=True).start()
    return app


def cli_backup(dest):
    """S13: a consistent copy of the database while the server runs (SQLite online backup, not a file copy).
    Messages stay encrypted: the copy is useless without data/terminet.secret, which is NOT included."""
    if not os.path.isfile(DB_PATH):
        sys.exit(f'No database at {DB_PATH}')
    if os.path.exists(dest):
        sys.exit(f'{dest} already exists; refusing to overwrite it.')
    os.umask(0o077)
    os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    try:
        verdict = copy_db(dest)
    except BaseException:
        os.remove(dest)
        raise
    if verdict != 'ok':
        os.remove(dest)
        sys.exit(f'Backup failed its integrity check ({verdict}); nothing was written.')
    print(f'Backup written to {dest} ({os.path.getsize(dest):,} bytes, integrity ok).')
    print(f'Keep {SECRET_PATH} next to it: without that file the backup cannot be read.')


def cli_stats():
    """S13: counts and sizes only. Nothing is decrypted, nothing is created."""
    if not os.path.isfile(DB_PATH):
        sys.exit(f'No database at {DB_PATH}')
    c = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True, timeout=30)
    try:
        print(f'schema version : {c.execute("PRAGMA user_version").fetchone()[0]}')
        for label, table in (('users', 'users'), ('sessions', 'sessions'), ('servers', 'servers'),
                             ('rooms', 'rooms'), ('messages', 'messages'), ('files', 'files'),
                             ('invites', 'invites'), ('bans', 'bans')):
            print(f'{label:<15}: {c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:,}')
        print(f'file bytes     : {c.execute("SELECT COALESCE(SUM(file_size), 0) FROM files").fetchone()[0]:,}')
    finally:
        c.close()
    print(f'database size  : {os.path.getsize(DB_PATH):,} bytes')
    free = shutil.disk_usage(DATA_DIR).free
    print(f'disk free      : {free:,} bytes')


def cli_revoke_sessions():
    """S13: log everybody out (a running server drops their sockets within about 30 s)."""
    if not os.path.isfile(DB_PATH):
        sys.exit(f'No database at {DB_PATH}')
    c = sqlite3.connect(DB_PATH, timeout=30)
    try:
        n = c.execute('DELETE FROM sessions').rowcount
        c.commit()
    finally:
        c.close()
    print(f'{n} session(s) revoked. Everybody has to log in again.')


def main():
    ap = argparse.ArgumentParser(description='Terminet.IRC server')
    ap.add_argument('--gen-cert', metavar='HOST', help='create a self-signed TLS cert for HOST (name or IP)')
    ap.add_argument('--backup', metavar='FILE', help='write a consistent copy of the database to FILE and exit')
    ap.add_argument('--stats', action='store_true', help='print counts and sizes and exit')
    ap.add_argument('--revoke-sessions', action='store_true', help='log every user out and exit')
    args = ap.parse_args()
    if args.gen_cert:
        os.umask(0o077)
        gen_cert(args.gen_cert)
        return
    if args.backup:
        return cli_backup(args.backup)
    if args.stats:
        return cli_stats()
    if args.revoke_sessions:
        return cli_revoke_sessions()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    wlog = logging.getLogger('werkzeug')
    if not ACCESS_LOG:
        wlog.setLevel(logging.WARNING)

    class _DropWsNoise(logging.Filter):
        # Werkzeug's dev server tries to parse the tail of closed WebSocket streams as HTTP; harmless noise.
        def filter(self, record):
            m = record.getMessage()
            return not ('Bad request' in m or 'Bad HTTP/0.9' in m)
    wlog.addFilter(_DropWsNoise())
    bootstrap()
    threading.Thread(target=housekeeping, daemon=True).start()

    cert = os.environ.get('TERMINET_CERT') or os.path.join(TLS_DIR, 'cert.pem')
    key = os.environ.get('TERMINET_CERT_KEY') or os.path.join(TLS_DIR, 'key.pem')
    ssl_context = (cert, key) if os.path.isfile(cert) and os.path.isfile(key) else None
    scheme = 'https' if ssl_context else 'http'
    log.info('Terminet.IRC v2 listening on %s://%s:%d  (data: %s)', scheme, HOST, PORT, DATA_DIR)
    if not ssl_context and HOST not in ('127.0.0.1', 'localhost', '::1') and not TRUST_PROXY:
        log.warning('NO TLS: passwords and session cookies cross the network in clear text. '
                    'Run with --gen-cert HOST, or put Caddy/nginx in front and set TERMINET_TRUST_PROXY=1.')
    socketio.run(app, host=HOST, port=PORT, ssl_context=ssl_context, debug=False, use_reloader=False,
                 allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    main()
