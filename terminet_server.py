from flask import Flask, render_template, request, jsonify, send_from_directory, abort, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import string
import secrets
import os
from datetime import datetime
import logging
import threading
import time
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import uuid
from werkzeug.utils import secure_filename
import mimetypes
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', template_folder='.')
app.config['SECRET_KEY'] = 'DefualtSecretKeyForTerminetV1.2'  # Change this in production!  

UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 50 * 1024 * 1024  
MAX_TOTAL_FILES = 512
ALLOWED_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico',
    # Videos
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv', '3gp',
    # Audio
    'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma',
    # Documents
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'rtf', 'odt', 'ods', 'odp',
    # Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    # Code
    'py', 'js', 'html', 'css', 'json', 'xml', 'csv',
    'c', 'cpp', 'java', 'php', 'rb', 'go', 'rs', 'sh'
}

EMBEDDABLE_IMAGE_TYPES = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'}
EMBEDDABLE_VIDEO_TYPES = {'mp4', 'webm', 'mov', 'avi'}
EMBEDDABLE_AUDIO_TYPES = {'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'}
EMBEDDABLE_TEXT_TYPES = {'txt', 'json', 'xml', 'csv', 'py', 'js', 'html', 'css'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# SocketIO Configuration for HTTP
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=120,
    ping_interval=60,
    logger=True,
    engineio_logger=True,
    transports=['polling', 'websocket'],
    allow_upgrades=True
)


DATABASE = 'terminet.db'

# ENCRYPTION CONFIGURATION - AES-GCM
CUSTOM_ENCRYPTION_KEY = "Defualt"  # change your own key,
SALT = b'defualt'  # change your own salt, must be bytes

class AESGCMManager:
    def __init__(self, custom_key: str):
        self.custom_key = custom_key
        self._key = None
        self._setup_key()
    
    def _setup_key(self):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  
                salt=SALT,
                iterations=100000,
                backend=default_backend()
            )
            self._key = kdf.derive(self.custom_key.encode('utf-8'))
            logger.info("AES-GCM encryption manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to setup AES-GCM encryption: {e}")
            raise
    
    def encrypt_data(self, data: str) -> str:
        try:
            if not data:
                return ""
            nonce = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            encrypted_data = nonce + encryptor.tag + ciphertext
            
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES-GCM encryption error: {e}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        try:
            if not encrypted_data:
                return ""
            raw_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            nonce = raw_data[:12]
            tag = raw_data[12:28]
            ciphertext = raw_data[28:]
            cipher = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES-GCM decryption error: {e}")
            return encrypted_data
    
    def encrypt_json(self, data: dict) -> str:
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            return self.encrypt_data(json_str)
        except Exception as e:
            logger.error(f"JSON encryption error: {e}")
            return json.dumps(data)
    
    def decrypt_json(self, encrypted_data: str) -> dict:
        try:
            decrypted_str = self.decrypt_data(encrypted_data)
            return json.loads(decrypted_str)
        except Exception as e:
            logger.error(f"JSON decryption error: {e}")
            return {}
encryption_manager = AESGCMManager(CUSTOM_ENCRYPTION_KEY)

def get_db():
    try:
        conn = sqlite3.connect(DATABASE, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA busy_timeout = 30000')
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_db():
    try:
        db_exists = os.path.exists(DATABASE)
        logger.info(f"Database file exists: {db_exists}")
        
        with get_db() as conn:
            conn.execute('PRAGMA foreign_keys = ON')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    unique_code TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            

            conn.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_encrypted TEXT NOT NULL,
                    description_encrypted TEXT,
                    owner_id INTEGER NOT NULL,
                    server_code TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            

            conn.execute('''
                CREATE TABLE IF NOT EXISTS server_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(server_id, user_id)
                )
            ''')
            

            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_server_join_map (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    server_id INTEGER NOT NULL,
                    is_first_join INTEGER DEFAULT 0,
                    last_join_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    UNIQUE(user_id, server_id)
                )
            ''')
            
       
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    name_encrypted TEXT NOT NULL,
                    created_by INTEGER NOT NULL,
                    is_locked INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
                )
            ''')
            
        
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT UNIQUE NOT NULL,
                    room_id INTEGER NOT NULL,
                    server_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username_encrypted TEXT NOT NULL,
                    message_encrypted TEXT NOT NULL,
                    message_type TEXT DEFAULT 'user',
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT UNIQUE NOT NULL,
                    server_id INTEGER NOT NULL,
                    room_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type TEXT,
                    file_type_category TEXT,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
       
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_users_unique_code ON users(unique_code)',
                'CREATE INDEX IF NOT EXISTS idx_servers_code ON servers(server_code)',
                'CREATE INDEX IF NOT EXISTS idx_server_members_server ON server_members(server_id)',
                'CREATE INDEX IF NOT EXISTS idx_server_members_user ON server_members(user_id)',
                'CREATE INDEX IF NOT EXISTS idx_user_server_join_map ON user_server_join_map(user_id, server_id)',
                'CREATE INDEX IF NOT EXISTS idx_user_server_join_first ON user_server_join_map(is_first_join)',
                'CREATE INDEX IF NOT EXISTS idx_rooms_server ON rooms(server_id)',
                'CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id)',
                'CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id)',
                'CREATE INDEX IF NOT EXISTS idx_files_uploaded_at ON files(uploaded_at)',
                'CREATE INDEX IF NOT EXISTS idx_files_server ON files(server_id)',
                'CREATE INDEX IF NOT EXISTS idx_files_room ON files(room_id)',
            ]
            
            for index in indexes:
                conn.execute(index)
            
            conn.commit()
            
        
            tables = ['users', 'servers', 'server_members', 'user_server_join_map', 'rooms', 'messages', 'files']
            for table in tables:
                count = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                logger.info(f"Table {table}: {count} records")
            
            logger.info("Database initialized successfully with AES-GCM encryption + DATABASE-ONLY storage")
            
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

def generate_unique_code(length=8):

    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def allowed_file(filename):

    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type_category(filename):
   
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in EMBEDDABLE_IMAGE_TYPES:
        return 'image'
    elif ext in EMBEDDABLE_VIDEO_TYPES:
        return 'video'
    elif ext in EMBEDDABLE_AUDIO_TYPES:
        return 'audio'
    elif ext in EMBEDDABLE_TEXT_TYPES:
        return 'text'
    else:
        return 'file'

def cleanup_old_files():

    try:
        with get_db() as conn:
            count = conn.execute('SELECT COUNT(*) as count FROM files').fetchone()['count']
            
            if count >= MAX_TOTAL_FILES:
                files_to_delete = count - MAX_TOTAL_FILES + 1  # +1 for the new file
                
                old_files = conn.execute('''
                    SELECT id, file_path FROM files 
                    ORDER BY uploaded_at ASC 
                    LIMIT ?
                ''', (files_to_delete,)).fetchall()
                
                for file_record in old_files:
                    try:
                        # Delete from disk
                        if os.path.exists(file_record['file_path']):
                            os.remove(file_record['file_path'])
                            logger.info(f"Deleted old file from disk: {file_record['file_path']}")
                        
                        # Delete from database
                        conn.execute('DELETE FROM files WHERE id = ?', (file_record['id'],))
                        
                    except Exception as e:
                        logger.error(f"Error deleting old file {file_record['id']}: {e}")
                
                conn.commit()
                logger.info(f"Cleaned up {len(old_files)} old files")
                
    except Exception as e:
        logger.error(f"Error in cleanup_old_files: {e}")

def ensure_unique_code(table, column, length=8, max_attempts=50):

    for attempt in range(max_attempts):
        code = generate_unique_code(length)
        try:
            with get_db() as conn:
                result = conn.execute(f'SELECT 1 FROM {table} WHERE {column} = ?', (code,)).fetchone()
                if not result:
                    logger.info(f"Generated unique code: {code} (attempt {attempt + 1})")
                    return code
        except Exception as e:
            logger.error(f"Error checking unique code: {e}")
            continue
    

    import time
    fallback_code = f"{int(time.time() * 1000) % 100000000:08d}"
    logger.warning(f"Using fallback code: {fallback_code}")
    return fallback_code

def is_first_join_to_server(user_id, server_id):
    try:
        with get_db() as conn:
            result = conn.execute('''
                SELECT is_first_join FROM user_server_join_map 
                WHERE user_id = ? AND server_id = ?
            ''', (user_id, server_id)).fetchone()
            
            if not result:
                conn.execute('''
                    INSERT OR IGNORE INTO user_server_join_map (user_id, server_id, is_first_join)
                    VALUES (?, ?, 0)
                ''', (user_id, server_id))
                conn.commit()
                return True
            
            return result['is_first_join'] == 0
    except Exception as e:
        logger.error(f"Error checking first join: {e}")
        return True  # Default to showing join message on error

def mark_user_joined_server(user_id, server_id):
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO user_server_join_map (user_id, server_id, is_first_join, last_join_at)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
            ''', (user_id, server_id))
            conn.commit()
            logger.debug(f"Marked user {user_id} as joined server {server_id}")
    except Exception as e:
        logger.error(f"Error marking user joined: {e}")

def cleanup_user_join_status_on_disconnect(user_id):
    try:
        with get_db() as conn:
            # Reset is_first_join to 0 for all servers this user is in
            conn.execute('''
                UPDATE user_server_join_map 
                SET is_first_join = 0, last_join_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (user_id,))
            conn.commit()
            logger.debug(f"Reset all join statuses for disconnected user {user_id}")
    except Exception as e:
        logger.error(f"Error cleaning up join status: {e}")


active_users = {}
room_users = {}

def save_message_to_db(room_id, server_id, user_id, username, message, message_type='user', message_id=None):

    try:
        if not message_id:
            message_id = str(uuid.uuid4())
            
        with get_db() as conn:
            
            username_encrypted = encryption_manager.encrypt_data(username)
            message_encrypted = encryption_manager.encrypt_data(message)
            
           
            existing = conn.execute(
                'SELECT 1 FROM messages WHERE message_id = ?',
                (message_id,)
            ).fetchone()
            
            if not existing:
               
                message_count = conn.execute(
                    'SELECT COUNT(*) as count FROM messages WHERE room_id = ?',
                    (room_id,)
                ).fetchone()['count']
                
                
                if message_count >= 512:
                    
                    messages_to_delete = message_count - 511  
                    
                    
                    conn.execute('''
                        DELETE FROM messages 
                        WHERE room_id = ? 
                        AND id IN (
                            SELECT id FROM messages 
                            WHERE room_id = ? 
                            ORDER BY timestamp ASC 
                            LIMIT ?
                        )
                    ''', (room_id, room_id, messages_to_delete))
                    
                    logger.info(f"Deleted {messages_to_delete} oldest messages from room {room_id} to maintain 512 limit")
                
                
                conn.execute('''
                    INSERT INTO messages (message_id, room_id, server_id, user_id, username_encrypted, message_encrypted, message_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (message_id, room_id, server_id, user_id, username_encrypted, message_encrypted, message_type))
                
                
                conn.commit()
                
                logger.debug(f"Saved AES-GCM encrypted message from {username} in room {room_id} with ID {message_id}")
            else:
                logger.debug(f"Message {message_id} already exists, skipping duplicate")
                
    except Exception as e:
        logger.error(f"Error saving AES-GCM encrypted message to database: {e}")

def load_room_messages(room_id, limit=512):
    
    try:
        with get_db() as conn:
            messages = conn.execute('''
                SELECT message_id, username_encrypted, message_encrypted, message_type,
                       strftime('%H:%M:%S', timestamp) as time, user_id
                FROM messages
                WHERE room_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (room_id, limit)).fetchall()

            result = []
           
            for msg in reversed(messages):
                try:
                    
                    username = encryption_manager.decrypt_data(msg['username_encrypted'])
                    message_text = encryption_manager.decrypt_data(msg['message_encrypted'])

                    
                    if msg['message_type'] == 'file':
                        if message_text.startswith('FILE_EMBED:'):
                            file_data_json = message_text[11:]
                            file_data = json.loads(file_data_json)
                            file_data['download_url'] = f"/files/{file_data.get('file_id')}"

                            result.append({
                                'id': msg['message_id'],
                                'type': 'file_embed',
                                'username': username,
                                'message': f"{username} uploaded {file_data.get('file_type', 'file')}: {file_data.get('filename', 'unknown')}",
                                'file_data': file_data,
                                'timestamp': msg['time'],
                                'user_id': msg['user_id']
                            })
                        elif message_text.startswith('FILE_DOWNLOAD:'):
                            parts = message_text.split(':', 3)
                            if len(parts) >= 4:
                                file_id, filename, download_url = parts[1], parts[2], parts[3]
                                result.append({
                                    'id': msg['message_id'],
                                    'type': 'file',
                                    'username': username,
                                    'message': f"{username} uploaded a file: {filename} - Click to download",
                                    'file_id': file_id,
                                    'filename': filename,
                                    'download_url': download_url,
                                    'timestamp': msg['time'],
                                    'user_id': msg['user_id']
                                })
                            else:
                                raise ValueError("Malformed FILE_DOWNLOAD message")
                        else:
                            result.append({
                                'id': msg['message_id'],
                                'type': 'file',
                                'username': username,
                                'message': message_text,
                                'timestamp': msg['time'],
                                'user_id': msg['user_id']
                            })
                    else:
                        
                        result.append({
                            'id': msg['message_id'],
                            'type': msg['message_type'],
                            'username': username,
                            'message': message_text,
                            'timestamp': msg['time'],
                            'user_id': msg['user_id']  # <<< THIS IS THE FIX
                        })
                except Exception as e:
                    
                    logger.error(f"Skipping corrupted or unreadable message (ID: {msg['message_id']}): {e}")
                    continue  # Move to the next message
            return result
    except Exception as e:
        
        logger.error(f"Error loading messages for room {room_id}: {e}")
        return []
    
def leave_server(server_id, user_id):
    
    try:
        with get_db() as conn:
            
            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?', 
                (server_id,)
            ).fetchone()
            
            if server and server['owner_id'] == user_id:
                return False, "Server owners cannot leave their own servers. Transfer ownership or delete the server."
            
            
            conn.execute('''
                DELETE FROM server_members 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, user_id))
            
            #
            conn.execute('''
                DELETE FROM user_server_join_map 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, user_id))
            
            conn.commit()
            logger.info(f"User {user_id} left server {server_id}")
            return True, "Successfully left server"
    except Exception as e:
        logger.error(f"Error leaving server: {e}")
        return False, f"Error leaving server: {str(e)}"

def disconnect_user_from_server(user_id, server_id):
    
    try:
        sids_to_disconnect = []
        rooms_to_update = set()
        
        
        for sid, user_data in active_users.items():
            if (user_data.get('user_id') == user_id and 
                str(user_data.get('server_id')) == str(server_id)):
                sids_to_disconnect.append(sid)
                if user_data.get('room_id'):
                    rooms_to_update.add(user_data.get('room_id'))

        
        for sid in sids_to_disconnect:
            try:
                # Notify the user they've been removed
                socketio.emit('kicked_from_server_reload', {
                    'message': 'You have been removed from this server.',
                    'server_id': server_id,
                    'reload': True
                }, room=sid)
                
                if sid in active_users:
                    user_data = active_users.pop(sid)
                    room_id = user_data.get('room_id')
                    
                    if room_id in room_users:
                        room_users[room_id].discard(sid)
                    
                    if room_id:
                        socketio.server.leave_room(sid, f'room_{room_id}')
            except Exception as e:
                logger.error(f"Error during socket cleanup for {sid}: {e}")

        
        for room_id in rooms_to_update:
            if room_id in room_users:
                users_in_room = [active_users[sid]['username'] for sid in room_users[room_id] if sid in active_users]
                socketio.emit('users_list', {'users': sorted(list(set(users_in_room)))}, room=f'room_{room_id}')
        
        return True
        
    except Exception as e:
        logger.error(f"Error disconnecting user from server: {e}")
        return False

def broadcast_to_all_server_members(server_id, event_name, data):
    
    try:
        with get_db() as conn:
          
            members = conn.execute('''
                SELECT user_id FROM server_members WHERE server_id = ?
            ''', (server_id,)).fetchall()
            
            member_ids = {member['user_id'] for member in members}
           
            target_sids = []
            for sid, user_data in active_users.items():
                if user_data.get('user_id') in member_ids:
                    target_sids.append(sid)
            
          
            for sid in target_sids:
                socketio.emit(event_name, data, room=sid)
            
            logger.info(f"Broadcasted {event_name} to {len(target_sids)} members of server {server_id}")
            
    except Exception as e:
        logger.error(f"Error broadcasting to server members: {e}")

@app.route('/')
def index():
  
    return send_from_directory('templates', 'index.html')

@app.route('/chat')
def chat():
    
    return send_from_directory('templates', 'IRC.html')

@app.route('/health')
def health():
    
    try:
        with get_db() as conn:
            conn.execute('SELECT 1').fetchone()
        return jsonify({
            'status': 'healthy', 
            'database': 'connected', 
            'encryption': 'AES-GCM',
            'storage': 'database-only',
            'join_tracking': 'enabled',
            'duplicate_prevention': 'enabled'
        })
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'database': 'disconnected', 
            'error': str(e)
        }), 500

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password are required'}), 400
        
        if len(username) > 20:
            return jsonify({'success': False, 'message': 'Username must be 20 characters or less'}), 400
            
        unique_code = ensure_unique_code('users', 'unique_code')
        password_hash = generate_password_hash(password)
        
        with get_db() as conn:
            try:
                cursor = conn.execute(
                    'INSERT INTO users (username, password_hash, unique_code) VALUES (?, ?, ?)',
                    (username, password_hash, unique_code)
                )
                user_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"User registered: {username} -> {unique_code} (ID: {user_id})")
                return jsonify({'success': True, 'unique_code': unique_code})
            except sqlite3.IntegrityError:
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
                
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
  
    try:
        data = request.get_json() or {}
        unique_code = data.get('unique_code', '').strip().upper()
        password = data.get('password', '')
        
        if not unique_code or not password:
            return jsonify({'success': False, 'message': 'Unique code and password are required'}), 400
        
        with get_db() as conn:
            user = conn.execute(
                'SELECT id, username, password_hash, unique_code FROM users WHERE unique_code = ?',
                (unique_code,)
            ).fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                logger.info(f"User logged in: {user['username']} ({unique_code})")
                return jsonify({
                    'success': True,
                    'user': {
                        'user_id': user['id'],
                        'username': user['username'],
                        'unique_code': user['unique_code']
                    }
                })
            else:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
                
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500
    
@app.route('/upload', methods=['POST'])
def upload_file():

    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        user_id = request.form.get('user_id')
        server_id = request.form.get('server_id')
        room_id = request.form.get('room_id')
        
        if not all([user_id, server_id, room_id]):
            return jsonify({'success': False, 'error': 'Missing required data'}), 400
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400
        
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'success': False, 'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB'}), 400
        
        if file_size == 0:
            return jsonify({'success': False, 'error': 'Empty file not allowed'}), 400
        
        with get_db() as conn:
            access = conn.execute('''
                SELECT 1 FROM rooms r
                JOIN server_members sm ON r.server_id = sm.server_id
                WHERE r.id = ? AND r.server_id = ? AND sm.user_id = ?
            ''', (room_id, server_id, user_id)).fetchone()
            
            if not access:
                return jsonify({'success': False, 'error': 'Access denied to this room'}), 403
        
        file_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        stored_filename = f"{file_id}_{original_filename}"
        
        server_room_path = os.path.join(UPLOAD_FOLDER, str(server_id), str(room_id))
        os.makedirs(server_room_path, exist_ok=True)
        file_path = os.path.join(server_room_path, stored_filename)
        
        mime_type, _ = mimetypes.guess_type(original_filename)
        file_type_category = get_file_type_category(original_filename)
        
        
        cleanup_old_files()
        
        file.save(file_path)
        
        
        with get_db() as conn:
            conn.execute('''
                INSERT INTO files (file_id, server_id, room_id, user_id, original_filename, 
                                 stored_filename, file_path, file_size, mime_type, file_type_category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (file_id, server_id, room_id, user_id, original_filename, 
                  stored_filename, file_path, file_size, mime_type or 'application/octet-stream', file_type_category))
            conn.commit()
        
        logger.info(f"File uploaded successfully: {original_filename} ({file_size} bytes) by user {user_id}")
        
        return jsonify({
            'success': True,
            'file_id': file_id,
        })
        
    except Exception as e:
        logger.error(f"File upload error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500


def get_user_by_id(user_id):
    try:
        with get_db() as conn:
            user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None

@app.route('/files/<file_id>')
def download_file(file_id):

    try:
        with get_db() as conn:
            file_record = conn.execute('''
                SELECT original_filename, stored_filename, file_path, mime_type
                FROM files WHERE file_id = ?
            ''', (file_id,)).fetchone()
            
            if not file_record:
                abort(404)
            
            if not os.path.exists(file_record['file_path']):
                logger.error(f"File not found on disk: {file_record['file_path']}")
                
                fallback_path = os.path.join(UPLOAD_FOLDER, file_record['stored_filename'])
                if not os.path.exists(fallback_path):
                    abort(404)
                file_path_to_serve = fallback_path
            else:
                file_path_to_serve = file_record['file_path']

            return send_file(
                file_path_to_serve,
                as_attachment=True,
                download_name=file_record['original_filename'],
                mimetype=file_record['mime_type']
            )
            
    except Exception as e:
        logger.error(f"File download error: {e}")
        abort(500)


@socketio.on('connect')
def on_connect():
    logger.info(f'Client connected: {request.sid}')
    emit('connection_confirmed', {
        'status': 'connected', 
        'server': 'terminet_aes_gcm_database_only',
        'message': 'Socket connection established with AES-GCM encryption and database-only storage'
    })

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f'Client disconnected: {request.sid}')
    
    try:
        if request.sid in active_users:
            user_data = active_users.pop(request.sid) # Pop the user
            user_id = user_data.get('user_id')
            server_id = user_data.get('server_id')
            room_id = user_data.get('room_id')

            
            if user_id:
                cleanup_user_join_status_on_disconnect(user_id)
            
            if room_id and room_id in room_users:
                room_users[room_id].discard(request.sid)
                
                users_in_room = [active_users[sid]['username'] for sid in room_users[room_id] if sid in active_users]
                emit('users_list', {'users': sorted(list(set(users_in_room)))}, room=f'room_{room_id}')

                if not room_users[room_id]:
                    del room_users[room_id]

    except Exception as e:
        logger.error(f"Error in disconnect handler: {e}")

@socketio.on('get_user_servers')
def on_get_user_servers(data):
    try:
        user_id = data.get('user_id')
        logger.info(f"Getting servers for user {user_id}")
        
        if not user_id:
            logger.warning("No user_id provided")
            emit('servers_list', {'owned_servers': [], 'joined_servers': [], 'error': 'No user ID provided'})
            return
        
        with get_db() as conn:
            owned_servers_raw = conn.execute('''
                SELECT id, name_encrypted, description_encrypted, server_code as code 
                FROM servers 
                WHERE owner_id = ?
                ORDER BY created_at DESC
            ''', (user_id,)).fetchall()
            
            owned_servers = []
            for server in owned_servers_raw:
                owned_servers.append({
                    'id': server['id'],
                    'name': encryption_manager.decrypt_data(server['name_encrypted']),
                    'description': encryption_manager.decrypt_data(server['description_encrypted'] or ''),
                    'code': server['code']
                })

            joined_servers_raw = conn.execute('''
                SELECT s.id, s.name_encrypted, s.description_encrypted, s.server_code as code 
                FROM servers s
                JOIN server_members sm ON s.id = sm.server_id
                WHERE sm.user_id = ? AND s.owner_id != ?
                ORDER BY sm.joined_at DESC
            ''', (user_id, user_id)).fetchall()
            
            joined_servers = []
            for server in joined_servers_raw:
                joined_servers.append({
                    'id': server['id'],
                    'name': encryption_manager.decrypt_data(server['name_encrypted']),
                    'description': encryption_manager.decrypt_data(server['description_encrypted'] or ''),
                    'code': server['code']
                })
            
            result = {
                'owned_servers': owned_servers,
                'joined_servers': joined_servers
            }
            
            logger.info(f"Found {len(result['owned_servers'])} owned, {len(result['joined_servers'])} joined servers for user {user_id}")
            emit('servers_list', result)
            
    except Exception as e:
        logger.error(f"Error getting user servers: {e}")
        emit('servers_list', {'owned_servers': [], 'joined_servers': [], 'error': str(e)})

@socketio.on('create_server')
def on_create_server(data):
    try:
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        owner_id = data.get('owner_id')
        
        logger.info(f"Creating server '{name}' for user {owner_id}")
        
        if not name or not owner_id:
            emit('server_created', {'success': False, 'error': 'Name and owner are required'})
            return
        
        if len(name) > 100:
            emit('server_created', {'success': False, 'error': 'Server name must be 100 characters or less'})
            return
        
        server_code = ensure_unique_code('servers', 'server_code')
        name_encrypted = encryption_manager.encrypt_data(name)
        description_encrypted = encryption_manager.encrypt_data(description)
        
        with get_db() as conn:
            cursor = conn.execute(
                'INSERT INTO servers (name_encrypted, description_encrypted, owner_id, server_code) VALUES (?, ?, ?, ?)',
                (name_encrypted, description_encrypted, owner_id, server_code)
            )
            server_id = cursor.lastrowid
            
            conn.execute(
                'INSERT INTO server_members (server_id, user_id) VALUES (?, ?)',
                (server_id, owner_id)
            )
            
            default_rooms = [
                ('welcome[Read-only]', 4),  # Hard-locked room type (system only, no one can type)
                ('rules[Read-only]', 3)     # Special room type 3 (owner only)
            ]
            
            for room_name, room_type in default_rooms:
                room_name_encrypted = encryption_manager.encrypt_data(room_name)
                conn.execute(
                    'INSERT INTO rooms (server_id, name_encrypted, created_by, is_locked) VALUES (?, ?, ?, ?)',
                    (server_id, room_name_encrypted, owner_id, room_type)
                )
            
            conn.commit()
            
            broadcast_to_all_server_members(server_id, 'server_created_broadcast', {
                'server_id': server_id,
                'server_name': name,
                'message': f'Server "{name}" has been created'
            })
            
            emit('server_created', {'success': True, 'server_id': server_id, 'server_code': server_code})
            logger.info(f"Server created successfully: {name} ({server_code}) ID:{server_id} by user {owner_id}")
            
    except Exception as e:
        logger.error(f"Error creating server: {e}")
        emit('server_created', {'success': False, 'error': f'Server creation failed: {str(e)}'})

@socketio.on('create_room')
def on_create_room(data):
    try:
        room_name = data.get('room_name', '').strip()
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        
        logger.info(f"Creating room '{room_name}' in server {server_id} by user {user_id}")
        
        if not all([room_name, server_id, user_id]):
            emit('room_created', {'success': False, 'error': 'Missing required data'})
            return
        
        if len(room_name) > 50:
            emit('room_created', {'success': False, 'error': 'Room name must be 50 characters or less'})
            return
        
        if room_name.lower() in ['welcome', 'rules']:
            emit('room_created', {'success': False, 'error': 'Cannot use reserved room names'})
            return
        
        with get_db() as conn:
            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server or server['owner_id'] != user_id:
                emit('room_created', {'success': False, 'error': 'Only server owners can create rooms'})
                return
            
            existing_rooms = conn.execute('''
                SELECT name_encrypted FROM rooms WHERE server_id = ?
            ''', (server_id,)).fetchall()
            
            for room in existing_rooms:
                existing_name = encryption_manager.decrypt_data(room['name_encrypted'])
                if existing_name.lower() == room_name.lower():
                    emit('room_created', {'success': False, 'error': 'Room name already exists'})
                    return
            
            room_name_encrypted = encryption_manager.encrypt_data(room_name)
            cursor = conn.execute(
                'INSERT INTO rooms (server_id, name_encrypted, created_by, is_locked) VALUES (?, ?, ?, ?)',
                (server_id, room_name_encrypted, user_id, 0)  # 0 = unlocked regular room
            )
            room_id = cursor.lastrowid
            conn.commit()
            
            broadcast_to_all_server_members(server_id, 'room_created_broadcast', {
                'room_id': room_id,
                'room_name': room_name,
                'server_id': server_id,
                'message': f'Room #{room_name} has been created'
            })
            
            emit('room_created', {'success': True, 'room_id': room_id, 'room_name': room_name})
            logger.info(f"Room '{room_name}' (ID: {room_id}) created successfully in server {server_id}")
            
    except Exception as e:
        logger.error(f"Error creating room: {e}")
        emit('room_created', {'success': False, 'error': f'Failed to create room: {str(e)}'})

@socketio.on('join_server')
def on_join_server(data):
    try:
        server_code = data.get('server_code', '').strip().upper()
        user_id = data.get('user_id')
        username = data.get('username')
        
        logger.info(f"User {username} ({user_id}) trying to join server {server_code}")
        
        if not all([server_code, user_id, username]):
            emit('server_joined', {'success': False, 'error': 'Server code, user ID, and username are required'})
            return
        
        with get_db() as conn:
            server = conn.execute(
                'SELECT id, name_encrypted, owner_id FROM servers WHERE server_code = ?',
                (server_code,)
            ).fetchone()
            
            if not server:
                emit('server_joined', {'success': False, 'error': 'Invalid server code'})
                return
            existing = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server['id'], user_id)
            ).fetchone()
            
            if existing:
                emit('server_joined', {'success': False, 'error': 'Already a member of this server'})
                return
            
            conn.execute(
                'INSERT INTO server_members (server_id, user_id) VALUES (?, ?)',
                (server['id'], user_id)
            )
            conn.commit()
            
            server_name = encryption_manager.decrypt_data(server['name_encrypted'])
            server_id = server['id']
            

            active_users[request.sid] = {
                'user_id': user_id,
                'username': username,
                'server_id': server_id,
                'room_id': None  
            }
            
            should_show_join_message = is_first_join_to_server(user_id, server_id)
            
            if should_show_join_message:
                mark_user_joined_server(user_id, server_id)

                broadcast_to_all_server_members(server_id, 'server_member_joined', {
                    'username': username,
                    'server_name': server_name,
                    'message': f'{username} joined the server',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })
            
            emit('server_joined', {'success': True, 'server_name': server_name, 'server_id': server_id})
            logger.info(f"User {username} successfully joined server {server_name} ({server_code})")
            
    except Exception as e:
        logger.error(f"Error joining server: {e}")
        emit('server_joined', {'success': False, 'error': f'Failed to join server: {str(e)}'})
        
@socketio.on('leave_server')
def on_leave_server(data):
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        username = data.get('username')
        
        logger.info(f"User {username} ({user_id}) trying to leave server {server_id}")
        
        if not all([server_id, user_id, username]):
            emit('server_left', {'success': False, 'error': 'Server ID, user ID, and username are required'})
            return
        
        with get_db() as conn:
            server = conn.execute(
                'SELECT name_encrypted FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            server_name = encryption_manager.decrypt_data(server['name_encrypted']) if server else 'Unknown Server'
            

            welcome_room = conn.execute(
                'SELECT id FROM rooms WHERE server_id = ? AND is_locked = 4',  # 4 = welcome room
                (server_id,)
            ).fetchone()
            
            if welcome_room:
                welcome_room_id = welcome_room['id']
                leave_message = f'{username} left the server'
                message_id = str(uuid.uuid4())
                

                save_message_to_db(
                    welcome_room_id, 
                    server_id, 
                    user_id, 
                    'SYSTEM', 
                    leave_message,
                    'system',
                    message_id
                )
                
                system_msg = {
                    'id': message_id,
                    'type': 'system',
                    'message': leave_message,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                emit('system_message', system_msg, room=f'room_{welcome_room_id}')
        
        success, message = leave_server(server_id, user_id)
        
        if success:
            disconnect_user_from_server(user_id, server_id)
            emit('server_left', {'success': True, 'message': message})
            logger.info(f"User {username} successfully left server {server_id}")
        else:
            emit('server_left', {'success': False, 'error': message})
            
    except Exception as e:
        logger.error(f"Error leaving server: {e}")
        emit('server_left', {'success': False, 'error': f'Failed to leave server: {str(e)}'})
        
@socketio.on('file_uploaded')
def handle_file_upload_notification(data):

    try:
        file_id = data.get('file_id')
        user_id = data.get('user_id')
        room_id = data.get('room_id')
        server_id = data.get('server_id')

        if not all([file_id, user_id, room_id, server_id]):
            logger.warning("Missing data in file_uploaded event. Aborting.")
            return

        with get_db() as conn:

            user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            file_info = conn.execute(
                '''SELECT original_filename, mime_type, file_type_category 
                   FROM files WHERE file_id = ?''', (file_id,)).fetchone()

            if not user or not file_info:
                logger.error(f"Could not find user({user_id}) or file({file_id}) info.")
                return

            username = user['username']
            filename = file_info['original_filename']
            file_type_category = file_info['file_type_category']

            file_data_for_message = {
                'file_id': file_id,
                'filename': filename,
                'file_type': file_type_category,
                'mime_type': file_info['mime_type']
            }
            
            if file_type_category in ['image', 'video', 'audio', 'text']:
                message_content = f"FILE_EMBED:{json.dumps(file_data_for_message)}"
            else:
                download_url = f"/files/{file_id}"
                message_content = f"FILE_DOWNLOAD:{file_id}:{filename}:{download_url}"
            
            message_id = str(uuid.uuid4())
            save_message_to_db(room_id, server_id, user_id, username, message_content, 'file', message_id)

            file_data_for_message['download_url'] = f'/files/{file_id}'

            message_to_emit = {
                'id': message_id,
                'username': username,
                'user_id': int(user_id),
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'type': 'file_embed' if file_type_category in ['image', 'video', 'audio', 'text'] else 'file',
                'message': f"{username} uploaded a file: {filename}",
                'file_data': file_data_for_message
            }

            socketio.emit('new_message', message_to_emit, room=f'room_{room_id}')
            
            logger.info(f"Processed and broadcasted file upload for {filename} in room {room_id}")

    except Exception as e:
        logger.error(f"Error in handle_file_upload_notification: {e}", exc_info=True)
        socketio.emit('file_upload_error', {'error': 'Failed to process file upload notification on server.'})

@socketio.on('get_server_data')
def on_get_server_data(data):
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        sid = request.sid
        
        logger.info(f"Getting server data for server {server_id}, user {user_id}")
        
        if not server_id or not user_id:
            emit('server_data', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            member = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server_id, user_id)
            ).fetchone()
            
            if not member:
                emit('server_data', {'success': False, 'error': 'Not a member of this server'})
                return

            user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                emit('server_data', {'success': False, 'error': 'User not found in database'})
                return
            username = user['username']

            active_users[sid] = {
                'user_id': int(user_id),
                'username': username,
                'server_id': int(server_id),
                'room_id': None  
            }
            logger.info(f"Registered active session {sid} for user '{username}' in server {server_id}")

            server_raw = conn.execute(
                'SELECT id, name_encrypted, description_encrypted, owner_id, server_code FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server_raw:
                emit('server_data', {'success': False, 'error': 'Server not found'})
                return
            
            server = {
                'id': server_raw['id'],
                'name': encryption_manager.decrypt_data(server_raw['name_encrypted']),
                'description': encryption_manager.decrypt_data(server_raw['description_encrypted'] or ''),
                'owner_id': server_raw['owner_id'],
                'server_code': server_raw['server_code']
            }
            
            rooms_raw = conn.execute(
                'SELECT id, name_encrypted, is_locked, created_at FROM rooms WHERE server_id = ? ORDER BY created_at',
                (server_id,)
            ).fetchall()
            
            rooms = []
            for room in rooms_raw:
                room_name = encryption_manager.decrypt_data(room['name_encrypted'])
                rooms.append({
                    'id': room['id'],
                    'name': room_name,
                    'is_locked': room['is_locked'],
                    'created_at': room['created_at'],
                    'is_special': room['is_locked'] in [3, 4],
                    'special_type': 'welcome' if room['is_locked'] == 4 else 'rules' if room['is_locked'] == 3 else None
                })
            
            result = {
                'success': True,
                'server': server,
                'rooms': rooms
            }
            
            logger.info(f"Sending server data: {server['name']} with {len(rooms)} rooms")
            emit('server_data', result)
            
    except Exception as e:
        logger.error(f"Error getting server data: {e}")
        emit('server_data', {'success': False, 'error': f'Failed to get server data: {str(e)}'})

@socketio.on('join_server')
def on_join_server(data):
    try:
        server_code = data.get('server_code', '').strip().upper()
        user_id = data.get('user_id')
        username = data.get('username')
        
        logger.info(f"User {username} ({user_id}) trying to join server {server_code}")
        
        if not all([server_code, user_id, username]):
            emit('server_joined', {'success': False, 'error': 'Server code, user ID, and username are required'})
            return
        
        with get_db() as conn:
            server = conn.execute(
                'SELECT id, name_encrypted, owner_id FROM servers WHERE server_code = ?',
                (server_code,)
            ).fetchone()
            
            if not server:
                emit('server_joined', {'success': False, 'error': 'Invalid server code'})
                return
            
            existing = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server['id'], user_id)
            ).fetchone()
            
            if existing:
                emit('server_joined', {'success': False, 'error': 'Already a member of this server'})
                return
            
            conn.execute(
                'INSERT INTO server_members (server_id, user_id) VALUES (?, ?)',
                (server['id'], user_id)
            )
            conn.commit()
            
            server_name = encryption_manager.decrypt_data(server['name_encrypted'])
            server_id = server['id']

            active_users[request.sid] = {
                'user_id': user_id,
                'username': username,
                'server_id': server_id,
                'room_id': None
            }

            should_show_join_message = is_first_join_to_server(user_id, server_id)
            
            if should_show_join_message:
                mark_user_joined_server(user_id, server_id)
                
            
                welcome_room = conn.execute(
                    'SELECT id FROM rooms WHERE server_id = ? AND is_locked = 4',  # 4 = welcome room
                    (server_id,)
                ).fetchone()
                
                if welcome_room:
                    welcome_room_id = welcome_room['id']
                    join_message = f'{username} joined the server'
                    message_id = str(uuid.uuid4())

                    save_message_to_db(
                        welcome_room_id, 
                        server_id, 
                        user_id, 
                        'SYSTEM', 
                        join_message,
                        'system',
                        message_id
                    )

                    system_msg = {
                        'id': message_id,
                        'type': 'system',
                        'message': join_message,
                        'timestamp': datetime.now().strftime('%H:%M:%S')
                    }
                    emit('system_message', system_msg, room=f'room_{welcome_room_id}')
            
            emit('server_joined', {'success': True, 'server_name': server_name, 'server_id': server_id})
            logger.info(f"User {username} successfully joined server {server_name} ({server_code})")
            
    except Exception as e:
        logger.error(f"Error joining server: {e}")
        emit('server_joined', {'success': False, 'error': f'Failed to join server: {str(e)}'})

@socketio.on('join_room')
def on_join_room(data):
    try:
        room_id = data.get('room_id')
        user_id = data.get('user_id')
        username = data.get('username')
        sid = request.sid

        if not all([room_id, user_id, username, sid in active_users]):
            emit('room_error', {'error': 'Missing required data for joining room'})
            return
        
        user_data = active_users[sid]
        server_id = user_data.get('server_id')
 
        previous_room_id = user_data.get('room_id')
        if previous_room_id:
            if previous_room_id in room_users and sid in room_users[previous_room_id]:
                room_users[previous_room_id].discard(sid)
                
                # Update the user list for the room they left
                old_room_users = [active_users[s]['username'] for s in room_users[previous_room_id] if s in active_users]
                emit('users_list', {'users': sorted(list(set(old_room_users)))}, room=f'room_{previous_room_id}')
                
                if not room_users[previous_room_id]:
                    del room_users[previous_room_id]
                    
            leave_room(f'room_{previous_room_id}', sid=sid)
            logger.info(f"User {username} left room {previous_room_id}")

        with get_db() as conn:
            # Verify user has access
            access = conn.execute('''
                SELECT r.name_encrypted, r.is_locked FROM rooms r
                JOIN server_members sm ON r.server_id = sm.server_id
                WHERE r.id = ? AND sm.user_id = ?
            ''', (room_id, user_id)).fetchone()
            
            if not access:
                emit('room_error', {'error': 'Access denied to this room'})
                return
            
            room_name = encryption_manager.decrypt_data(access['name_encrypted'])
            room_lock_status = access['is_locked']

        join_room(f'room_{room_id}', sid=sid)

        active_users[sid]['room_id'] = room_id
        if room_id not in room_users:
            room_users[room_id] = set()
        room_users[room_id].add(sid)
        
        logger.info(f"User {username} ({user_id}) joined room {room_name} ({room_id})")

        messages = load_room_messages(room_id)
        users_in_room = [active_users[s]['username'] for s in room_users[room_id] if s in active_users]
        emit('room_joined', {
            'room_id': room_id,
            'room_name': room_name,
            'messages': messages,
            'is_locked': room_lock_status, # Send lock status to client
        })
        
        emit('users_list', {'users': sorted(list(set(users_in_room)))}, room=f'room_{room_id}')

    except Exception as e:
        logger.error(f"Error joining room: {e}")
        emit('room_error', {'error': f'Failed to join room: {str(e)}'})

@socketio.on('send_message')
def on_send_message(data):

    try:
        message = data.get('message', '').strip()
        room_id = data.get('room_id')
        server_id = data.get('server_id')

        if not message:
            emit('message_error', {'error': 'Message cannot be empty'})
            return

        if request.sid not in active_users:
            emit('message_error', {'error': 'User not active'})
            return

        user_data = active_users[request.sid]
        user_id = user_data['user_id']
        username = user_data['username']

        
        if not room_id: room_id = user_data.get('room_id')
        if not server_id: server_id = user_data.get('server_id')
        
        if not all([room_id, server_id]):
            emit('message_error', {'error': 'Cannot send message, not in a valid room context'})
            return

        
        with get_db() as conn:
            
            room_info = conn.execute('''
                SELECT r.is_locked, s.owner_id 
                FROM rooms r
                JOIN servers s ON r.server_id = s.id
                WHERE r.id = ? AND r.server_id = ?
            ''', (room_id, server_id)).fetchone()

            if not room_info:
                emit('message_error', {'error': 'Room not found or invalid server context'})
                return

            lock_status = room_info['is_locked']
            owner_id = room_info['owner_id']
            is_owner = (user_id == owner_id)

           
            if lock_status == 4:
                emit('message_error', {'error': 'This channel is read-only.'})
                return # Stop processing the message

            if lock_status == 3 and not is_owner:
                emit('message_error', {'error': 'Only the server owner can type in this channel.'})
                return # Stop processing the message


            if lock_status == 1 and not is_owner:
                emit('message_error', {'error': 'This channel is currently locked.'})
                return 

        message_id = str(uuid.uuid4())
        save_message_to_db(room_id, server_id, user_id, username, message, 'user', message_id)

        emit('new_message', {
            'id': message_id,
            'type': 'user',
            'username': username,
            'message': message,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_id': user_id
        }, room=f'room_{room_id}')

    except Exception as e:
        logger.error(f"Error sending message: {e}", exc_info=True)
        emit('message_error', {'error': f"Failed to send message: {str(e)}"})


@socketio.on('kick_user')
def on_kick_user(data):

    try:
        username = data.get('username')
        kicked_by = data.get('kicked_by')
        server_id = data.get('server_id')
        
        logger.info(f"Kick request: {username} from server {server_id} by user {kicked_by}")
        
        if not all([username, kicked_by, server_id]):
            emit('kick_result', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            
            server_raw = conn.execute(
                'SELECT owner_id, name_encrypted FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server_raw or server_raw['owner_id'] != kicked_by:
                emit('kick_result', {'success': False, 'error': 'Only server owner can kick users'})
                return
            
            server_name = encryption_manager.decrypt_data(server_raw['name_encrypted'])
            
            
            user_to_kick = conn.execute(
                'SELECT id FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            if not user_to_kick:
                emit('kick_result', {'success': False, 'error': 'User not found'})
                return
            
            kicked_user_id = user_to_kick['id']
            
            
            if kicked_user_id == kicked_by:
                emit('kick_result', {'success': False, 'error': 'Cannot kick yourself'})
                return
            
            
            member = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server_id, kicked_user_id)
            ).fetchone()
            
            if not member:
                emit('kick_result', {'success': False, 'error': 'User is not a member of this server'})
                return
            
            
            kicker = conn.execute('SELECT username FROM users WHERE id = ?', (kicked_by,)).fetchone()
            kicker_name = kicker['username'] if kicker else 'Admin'
            
            
            welcome_room = conn.execute(
                'SELECT id FROM rooms WHERE server_id = ? AND is_locked = 4',  # 4 = welcome room
                (server_id,)
            ).fetchone()
            
            if welcome_room:
                welcome_room_id = welcome_room['id']
                kick_message = f'{username} was removed from the server by {kicker_name}'
                message_id = str(uuid.uuid4())
                
               
                save_message_to_db(
                    welcome_room_id, 
                    server_id, 
                    kicked_user_id, 
                    'SYSTEM', 
                    kick_message,
                    'system',
                    message_id
                )
                
              
                system_msg = {
                    'id': message_id,
                    'type': 'system',
                    'message': kick_message,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                emit('system_message', system_msg, room=f'room_{welcome_room_id}')
            
            
            conn.execute('''
                DELETE FROM server_members 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, kicked_user_id))
            
            
            conn.execute('''
                DELETE FROM user_server_join_map 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, kicked_user_id))
            
            conn.commit()
            
            
            disconnect_user_from_server(kicked_user_id, server_id)

            emit('kick_result', {'success': True, 'message': f'{username} has been completely removed from the server'})
            logger.info(f"User {username} COMPLETELY REMOVED from server {server_name} by {kicker_name}")
                
    except Exception as e:
        logger.error(f"Error kicking user: {e}")
        emit('kick_result', {'success': False, 'error': f'Failed to kick user: {str(e)}'})

@socketio.on('delete_room')
def on_delete_room(data):
    try:
        room_id = data.get('room_id')
        user_id = data.get('user_id')
        
        logger.info(f"Delete room request: room {room_id} by user {user_id}")
        
        if not room_id or not user_id:
            emit('room_deleted', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            # Get room and server info - decrypt room name
            room_info_raw = conn.execute('''
                SELECT r.id, r.name_encrypted, r.server_id, s.owner_id
                FROM rooms r
                JOIN servers s ON r.server_id = s.id
                WHERE r.id = ?
            ''', (room_id,)).fetchone()
            
            if not room_info_raw:
                emit('room_deleted', {'success': False, 'error': 'Room not found'})
                return
            
            
            room_name = encryption_manager.decrypt_data(room_info_raw['name_encrypted'])
            
           
            if room_info_raw['owner_id'] != user_id:
                emit('room_deleted', {'success': False, 'error': 'Only server owners can delete rooms'})
                return
          
            if room_name.lower() in ['welcome', 'rules']:
                emit('room_deleted', {'success': False, 'error': f'Cannot delete the {room_name} room'})
                return
            
            server_id = room_info_raw['server_id']
            
            users_to_notify = []
            if room_id in room_users:
                users_to_notify = list(room_users[room_id])

            for sid in users_to_notify:
                try:
                    if sid in active_users:
                        socketio.emit('system_message', {
                            'id': str(uuid.uuid4()),
                            'type': 'system',
                            'message': f'Room #{room_name} has been deleted by the server owner',
                            'timestamp': datetime.now().strftime('%H:%M:%S')
                        }, room=sid)

                        active_users[sid]['room_id'] = None
                        leave_room(f'room_{room_id}', sid=sid)
                
                except Exception as e:
                    logger.error(f"Error notifying user {sid} about room deletion: {e}")
            
            
            if room_id in room_users:
                del room_users[room_id]
            
            conn.execute('DELETE FROM messages WHERE room_id = ?', (room_id,))
            
            
            conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
            
            conn.commit()
            
            
            broadcast_to_all_server_members(server_id, 'room_deleted_broadcast', {
                'room_id': room_id,
                'room_name': room_name,
                'server_id': server_id,
                'message': f'Room #{room_name} has been deleted'
            })
            
            emit('room_deleted', {'success': True, 'message': f'Room #{room_name} has been deleted'})
            logger.info(f"Room '{room_name}' (ID: {room_id}) deleted successfully by user {user_id}")
            
    except Exception as e:
        logger.error(f"Error deleting room: {e}")
        emit('room_deleted', {'success': False, 'error': f'Failed to delete room: {str(e)}'})

@socketio.on('delete_server')
def on_delete_server(data):
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        
        logger.info(f"Delete server request: server {server_id} by user {user_id}")
        
        if not server_id or not user_id:
            emit('server_deleted', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
           
            server = conn.execute(
                'SELECT owner_id, name_encrypted FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server:
                emit('server_deleted', {'success': False, 'error': 'Server not found'})
                return
            
            if server['owner_id'] != user_id:
                emit('server_deleted', {'success': False, 'error': 'Only the server owner can delete this server'})
                return

            
            server_name = encryption_manager.decrypt_data(server['name_encrypted'])
            
            broadcast_to_all_server_members(server_id, 'server_deleted_broadcast', {
                'server_id': server_id,
                'server_name': server_name,
                'message': f'Server "{server_name}" has been deleted by the owner'
            })

            conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
            conn.commit()
            
            emit('server_deleted', {'success': True, 'server_id': server_id})
            logger.info(f"Server {server_name} (ID: {server_id}) deleted successfully by owner {user_id}")

    except Exception as e:
        logger.error(f"Error deleting server: {e}")
        emit('server_deleted', {'success': False, 'error': f'Failed to delete server: {str(e)}'})

@socketio.on('get_room_logs')
def on_get_room_logs(data):
    try:
        user_id = data.get('user_id')
        server_id = data.get('server_id')
        room_id = data.get('room_id')
        room_name = data.get('room_name')
        limit = data.get('limit', 100)

        logger.info(f"Loading logs for room {room_name} (ID: {room_id}) for user {user_id}")
        
        if not all([user_id, server_id, room_id]):
            emit('room_logs', {'success': False, 'error': 'Missing required data'})
            return
        with get_db() as conn:
            access = conn.execute('''
                SELECT 1 FROM rooms r
                JOIN server_members sm ON r.server_id = sm.server_id
                WHERE r.id = ? AND sm.user_id = ?
            ''', (room_id, user_id)).fetchone()
            
            if not access:
                emit('room_logs', {'success': False, 'error': 'Access denied to this room'})
                return
        messages = load_room_messages(room_id, limit)
        
        emit('room_logs', {'success': True, 'messages': messages})
        logger.info(f"Loaded {len(messages)} log messages for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error loading room logs: {e}")
        emit('room_logs', {'success': False, 'error': f'Failed to load logs: {str(e)}'})

@socketio.on('change_nickname')
def on_change_nickname(data):
    try:
        user_id = data.get('user_id')
        new_nick = data.get('new_nick', '').strip()
        room_id = data.get('room_id')
        
        logger.info(f"Nickname change request: user {user_id} to '{new_nick}' in room {room_id}")

        if not user_id or not new_nick or not room_id:
            emit('nickname_error', {'error': 'Invalid nickname change data'})
            return

        if len(new_nick) > 20:
            emit('nickname_error', {'error': 'Nickname must be 20 characters or less'})
            return

        with get_db() as conn:

            existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (new_nick,)).fetchone()
            if existing_user:
                emit('nickname_error', {'error': 'Nickname is already taken'})
                return

            user = conn.execute(
                'SELECT username FROM users WHERE id = ?',
                (user_id,)
            ).fetchone()
            
            if not user:
                emit('nickname_error', {'error': 'User not found'})
                return
                
            old_nick = user['username']

            conn.execute('UPDATE users SET username = ? WHERE id = ?', (new_nick, user_id))

            room_info = conn.execute(
                'SELECT server_id FROM rooms WHERE id = ?',
                (room_id,)
            ).fetchone()
            
            if not room_info:
                emit('nickname_error', {'error': 'Room not found'})
                return
                
            server_id = room_info['server_id']
            conn.commit()

        for sid, user_data in active_users.items():
            if user_data.get('user_id') == user_id:
                user_data['username'] = new_nick

        message_id = str(uuid.uuid4())

        system_message = f"{old_nick} is now known as {new_nick}"

        save_message_to_db(
            room_id, 
            server_id, 
            user_id, 
            'SYSTEM', 
            system_message,
            'system',
            message_id
        )

        system_msg = {
            'id': message_id,
            'type': 'system',
            'message': system_message,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        emit('system_message', system_msg, room=f'room_{room_id}')

        if room_id in room_users:
            users_in_room = [active_users[sid]['username'] for sid in room_users[room_id] if sid in active_users]
            emit('users_list', {'users': sorted(list(set(users_in_room)))}, room=f'room_{room_id}')
        
        logger.info(f"Nickname changed: {old_nick} -> {new_nick} in room {room_id}")
        emit('nickname_changed', {'success': True, 'new_nick': new_nick})
        
    except Exception as e:
        logger.error(f"Error changing nickname: {e}")
        emit('nickname_error', {'error': f'Failed to change nickname: {str(e)}'})
    

@socketio.on('lock_channel')
def on_lock_channel(data):
    try:
        room_id = data.get('room_id')
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        lock = data.get('lock')
        
        logger.info(f"Lock channel request: room {room_id} by user {user_id}, lock={lock}")
        
        if not all([room_id, server_id, user_id, lock is not None]):
            emit('lock_result', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:

            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server or server['owner_id'] != user_id:
                emit('lock_result', {'success': False, 'error': 'Only server owners can lock/unlock channels'})
                return
            
            room_info = conn.execute(
                'SELECT name_encrypted, is_locked FROM rooms WHERE id = ? AND server_id = ?',
                (room_id, server_id)
            ).fetchone()
            
            if not room_info:
                emit('lock_result', {'success': False, 'error': 'Room not found'})
                return
            
            room_name = encryption_manager.decrypt_data(room_info['name_encrypted'])
            
            if room_info['is_locked'] in [3, 4]:  # Rules or Welcome rooms
                emit('lock_result', {'success': False, 'error': f'Cannot modify lock status of the {room_name} room'})
                return
            
            lock_status = 1 if lock else 0
            conn.execute(
                'UPDATE rooms SET is_locked = ? WHERE id = ?',
                (lock_status, room_id)
            )
            conn.commit()

            emit('channel_lock_status', {
                'room_id': room_id,
                'locked': lock,
                'message': f'Channel has been {"locked" if lock else "unlocked"} by the server owner'
            }, room=f'room_{room_id}')
            
            emit('lock_result', {'success': True, 'locked': lock})
            logger.info(f"Channel {room_id} {'locked' if lock else 'unlocked'} by user {user_id}")
            
    except Exception as e:
        logger.error(f"Error locking channel: {e}")
        emit('lock_result', {'success': False, 'error': f'Failed to lock channel: {str(e)}'})

@socketio.on('get_room_lock_status')
def on_get_room_lock_status(data):

    try:
        room_id = data.get('room_id')
        server_id = data.get('server_id')
        
        if not all([room_id, server_id]):
            emit('room_lock_status', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            room_info = conn.execute(
                'SELECT is_locked FROM rooms WHERE id = ? AND server_id = ?',
                (room_id, server_id)
            ).fetchone()
            
            if room_info:
                lock_status = room_info['is_locked']
                is_special = lock_status in [3, 4]
                is_locked = lock_status == 1  # Regular locked room
                is_hard_locked = lock_status == 4  # Welcome room (hard locked)
                is_owner_only = lock_status == 3  # Rules room (owner only)
                
                emit('room_lock_status', {
                    'success': True,
                    'room_id': room_id,
                    'locked': is_locked,
                    'special': is_special,
                    'hard_locked': is_hard_locked,
                    'owner_only': is_owner_only,
                    'special_type': lock_status
                })
            else:
                emit('room_lock_status', {'success': False, 'error': 'Room not found'})
                
    except Exception as e:
        logger.error(f"Error getting room lock status: {e}")
        emit('room_lock_status', {'success': False, 'error': f'Failed to get lock status: {str(e)}'})

# Socket.IO Error handling
@socketio.on_error_default
def default_error_handler(e):
    logger.error(f'Socket.IO error: {e}')
    emit('error', {'error': 'An unexpected error occurred'})

if __name__ == '__main__':
    # Initialize database
    logger.info("Initializing database with AES-GCM encryption...")
    init_db()
    
    logger.info("="*60)
    logger.info("TERMINET IRC SERVER V1.3 - AES-GCM & DATABASE ONLY")
    logger.info("="*60)
    logger.info(f"Database: {DATABASE} (AES-GCM ENCRYPTED + MESSAGE IDs)")
    logger.info(f"Storage: Database-only (no log files)")
    logger.info(f"Encryption: AES-256-GCM")
    logger.info(f"Encryption Key: {CUSTOM_ENCRYPTION_KEY[:30]}...")
    logger.info("NEW FEATURES V1.3:")
    logger.info("- Default rooms: Welcome (hard-locked) + Rules (owner-only)")
    logger.info("- NO general room by default")
    logger.info("- Real-time server/room creation/deletion broadcasts")
    logger.info("- Join/Leave server events instead of room events")
    logger.info("- Welcome room: System messages only (NO ONE can type)")
    logger.info("- Rules room: Owner-only messages")
    
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=80,
            debug=False,
            use_reloader=False,
            log_output=True
        )
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        if "Permission denied" in str(e):
            logger.info("Try running as administrator or use a different port")
        elif "cryptography" in str(e):
            logger.info("Please install cryptography: pip install cryptography")
