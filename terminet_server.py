# terminet_server.py - Enhanced Flask Server with AES-GCM & Database-Only Storage
from flask import Flask, render_template, request, jsonify, send_from_directory
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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', template_folder='.')
app.config['SECRET_KEY'] = 'terminet_secret_key_2024_http' #change this as you needed

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

# Database configuration (NO LOG FILES)
DATABASE = 'terminet.db'

# ENCRYPTION CONFIGURATION - AES-GCM
CUSTOM_ENCRYPTION_KEY = "https://www.youtube.com/watch?v=zgoz4qKKdV8"  # change this as your key, is that daisy bell?
SALT = b'terminet_salt_2024'  # change this as you needed

class AESGCMManager:
    """Handles all AES-GCM encryption/decryption operations"""
    
    def __init__(self, custom_key: str):
        self.custom_key = custom_key
        self._key = None
        self._setup_key()
    
    def _setup_key(self):
        """Derive AES key from custom string using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES-256
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
        """Encrypt string data using AES-GCM and return base64 encoded result"""
        try:
            if not data:
                return ""
            
            # Generate random 96-bit (12 bytes) nonce for GCM
            nonce = os.urandom(12)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            
            # Combine nonce + tag + ciphertext
            encrypted_data = nonce + encryptor.tag + ciphertext
            
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES-GCM encryption error: {e}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt AES-GCM data and return original string"""
        try:
            if not encrypted_data:
                return ""
            
            # Decode from base64
            raw_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            
            # Extract nonce (12 bytes), tag (16 bytes), and ciphertext
            nonce = raw_data[:12]
            tag = raw_data[12:28]
            ciphertext = raw_data[28:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES-GCM decryption error: {e}")
            return encrypted_data
    
    def encrypt_json(self, data: dict) -> str:
        """Encrypt JSON data"""
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            return self.encrypt_data(json_str)
        except Exception as e:
            logger.error(f"JSON encryption error: {e}")
            return json.dumps(data)
    
    def decrypt_json(self, encrypted_data: str) -> dict:
        """Decrypt JSON data"""
        try:
            decrypted_str = self.decrypt_data(encrypted_data)
            return json.loads(decrypted_str)
        except Exception as e:
            logger.error(f"JSON decryption error: {e}")
            return {}

# Initialize AES-GCM encryption manager
encryption_manager = AESGCMManager(CUSTOM_ENCRYPTION_KEY)

def get_db():
    """Get database connection with proper error handling and foreign keys enabled"""
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
    """Initialize database with required tables - AES-GCM encrypted, database-only storage"""
    try:
        db_exists = os.path.exists(DATABASE)
        logger.info(f"Database file exists: {db_exists}")
        
        with get_db() as conn:
            conn.execute('PRAGMA foreign_keys = ON')
            
            # Users table - passwords and sensitive data encrypted
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    unique_code TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Servers table - names and descriptions encrypted
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
            
            # Server members table
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
            
            # User-Server join tracking table
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
            
            # Rooms table - room names encrypted
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    name_encrypted TEXT NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
                    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
                )
            ''')
            
            # Messages table - all content encrypted + UNIQUE MESSAGE IDs (DATABASE ONLY)
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
            
            # Create indexes for better performance
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
                'CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id)'
            ]
            
            for index in indexes:
                conn.execute(index)
            
            conn.commit()
            
            # Check table counts
            tables = ['users', 'servers', 'server_members', 'user_server_join_map', 'rooms', 'messages']
            for table in tables:
                count = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                logger.info(f"Table {table}: {count} records")
            
            logger.info("Database initialized successfully with AES-GCM encryption + DATABASE-ONLY storage")
            
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

def generate_unique_code(length=8):
    """Generate cryptographically secure unique code"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def ensure_unique_code(table, column, length=8, max_attempts=50):
    """Ensure generated code is unique in database"""
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
    
    # Fallback: use timestamp-based code
    import time
    fallback_code = f"{int(time.time() * 1000) % 100000000:08d}"
    logger.warning(f"Using fallback code: {fallback_code}")
    return fallback_code

def is_first_join_to_server(user_id, server_id):
    """Check if this is user's first time joining server rooms"""
    try:
        with get_db() as conn:
            result = conn.execute('''
                SELECT is_first_join FROM user_server_join_map 
                WHERE user_id = ? AND server_id = ?
            ''', (user_id, server_id)).fetchone()
            
            if not result:
                # First time - create record with is_first_join = 0 (will show join message)
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
    """Mark user as having joined server (set is_first_join = 1)"""
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
    """Reset ALL server join statuses for disconnected user"""
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

# Active connections tracking
active_users = {}
room_users = {}

def save_message_to_db(room_id, server_id, user_id, username, message, message_type='user', message_id=None):
    """Save AES-GCM encrypted message to database with UNIQUE MESSAGE ID"""
    try:
        if not message_id:
            message_id = str(uuid.uuid4())
            
        with get_db() as conn:
            # Encrypt sensitive data using AES-GCM
            username_encrypted = encryption_manager.encrypt_data(username)
            message_encrypted = encryption_manager.encrypt_data(message)
            
            # Check if message already exists (prevent duplicates)
            existing = conn.execute(
                'SELECT 1 FROM messages WHERE message_id = ?',
                (message_id,)
            ).fetchone()
            
            if not existing:
                conn.execute('''
                    INSERT INTO messages (message_id, room_id, server_id, user_id, username_encrypted, message_encrypted, message_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (message_id, room_id, server_id, user_id, username_encrypted, message_encrypted, message_type))
                logger.debug(f"Saved AES-GCM encrypted message from {username} in room {room_id} with ID {message_id}")
            else:
                logger.debug(f"Message {message_id} already exists, skipping duplicate")
                
    except Exception as e:
        logger.error(f"Error saving AES-GCM encrypted message to database: {e}")

def load_room_messages(room_id, limit=100):
    """Load recent messages for a room from database - AES-GCM decrypt with IDs"""
    try:
        with get_db() as conn:
            messages = conn.execute('''
                SELECT message_id, username_encrypted, message_encrypted, message_type, 
                       strftime('%H:%M:%S', timestamp) as time
                FROM messages 
                WHERE room_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (room_id, limit)).fetchall()
            
            result = []
            for msg in reversed(messages):
                # Decrypt the data using AES-GCM
                username = encryption_manager.decrypt_data(msg['username_encrypted'])
                message_text = encryption_manager.decrypt_data(msg['message_encrypted'])
                
                result.append({
                    'id': msg['message_id'],
                    'type': msg['message_type'],
                    'username': username,
                    'message': message_text,
                    'timestamp': msg['time']
                })
            return result
    except Exception as e:
        logger.error(f"Error loading AES-GCM encrypted messages: {e}")
        return []

def leave_server(server_id, user_id):
    """User leaves server voluntarily"""
    try:
        with get_db() as conn:
            # Check if user is the owner
            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?', 
                (server_id,)
            ).fetchone()
            
            if server and server['owner_id'] == user_id:
                return False, "Server owners cannot leave their own servers. Transfer ownership or delete the server."
            
            # Remove from server_members
            conn.execute('''
                DELETE FROM server_members 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, user_id))
            
            # Clean up join tracking
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
    """Disconnect user from all rooms in a server"""
    try:
        # Find all socket connections for this user
        user_sockets = []
        for sid, user_data in active_users.items():
            if (user_data.get('user_id') == user_id and 
                user_data.get('server_id') == server_id):
                user_sockets.append(sid)
        
        # Disconnect each socket
        for sid in user_sockets:
            try:
                # Notify the user they've been kicked
                socketio.emit('kicked_from_server', {
                    'message': 'You have been removed from this server',
                    'server_id': server_id
                }, room=sid)
                
                # Remove from active users and rooms
                if sid in active_users:
                    user_data = active_users[sid]
                    room_id = user_data.get('room_id')
                    
                    # Remove from room users tracking
                    if room_id and room_id in room_users:
                        room_users[room_id].discard(sid)
                    
                    # Leave socket room
                    if room_id:
                        socketio.server.leave_room(sid, f'room_{room_id}')
                    
                    del active_users[sid]
                
            except Exception as e:
                logger.error(f"Error disconnecting socket {sid}: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error disconnecting user from server: {e}")
        return False

# Routes
@app.route('/')
def index():
    """Serve main login page"""
    return send_from_directory('templates', 'index.html')

@app.route('/chat')
def chat():
    """Serve IRC chat interface"""
    return send_from_directory('templates', 'IRC.html')

@app.route('/health')
def health():
    """Health check endpoint"""
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
    """User registration endpoint"""
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
    """User login endpoint"""
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

# Socket.IO Events
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
            user_data = active_users[request.sid]
            user_id = user_data.get('user_id')
            
            # CLEANUP: Reset join status for ALL servers when user disconnects
            if user_id:
                cleanup_user_join_status_on_disconnect(user_id)
            
            for room_id, users in list(room_users.items()):
                if request.sid in users:
                    users.discard(request.sid)
                    if user_data.get('room_id') == room_id:
                        message_id = str(uuid.uuid4())
                        save_message_to_db(
                            room_id, 
                            user_data.get('server_id', 0), 
                            user_data['user_id'], 
                            'SYSTEM', 
                            f'{user_data["username"]} left the room',
                            'system',
                            message_id
                        )
                        
                        system_msg = {
                            'id': message_id,
                            'type': 'system',
                            'message': f'{user_data["username"]} left the room',
                            'timestamp': datetime.now().strftime('%H:%M:%S')
                        }
                        emit('system_message', system_msg, room=f'room_{room_id}')
                        
                        users_in_room = [active_users[sid]['username'] for sid in users if sid in active_users]
                        emit('users_list', {'users': users_in_room}, room=f'room_{room_id}')
            
            empty_rooms = [k for k, v in room_users.items() if not v]
            for k in empty_rooms:
                del room_users[k]
    except Exception as e:
        logger.error(f"Error in disconnect handler: {e}")

@socketio.on('get_user_servers')
def on_get_user_servers(data):
    """Get user's servers - AES-GCM decryption"""
    try:
        user_id = data.get('user_id')
        logger.info(f"Getting servers for user {user_id}")
        
        if not user_id:
            logger.warning("No user_id provided")
            emit('servers_list', {'owned_servers': [], 'joined_servers': [], 'error': 'No user ID provided'})
            return
        
        with get_db() as conn:
            # Get owned servers - decrypt names and descriptions
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
            
            # Get joined servers (excluding owned ones) - decrypt
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
    """Create new server - AES-GCM encryption"""
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
        
        # Encrypt server data using AES-GCM
        name_encrypted = encryption_manager.encrypt_data(name)
        description_encrypted = encryption_manager.encrypt_data(description)
        
        with get_db() as conn:
            # Create server with encrypted data
            cursor = conn.execute(
                'INSERT INTO servers (name_encrypted, description_encrypted, owner_id, server_code) VALUES (?, ?, ?, ?)',
                (name_encrypted, description_encrypted, owner_id, server_code)
            )
            server_id = cursor.lastrowid
            
            # Add owner as member
            conn.execute(
                'INSERT INTO server_members (server_id, user_id) VALUES (?, ?)',
                (server_id, owner_id)
            )
            
            # Create default general room with encrypted name
            general_name_encrypted = encryption_manager.encrypt_data('general')
            room_cursor = conn.execute(
                'INSERT INTO rooms (server_id, name_encrypted, created_by) VALUES (?, ?, ?)',
                (server_id, general_name_encrypted, owner_id)
            )
            room_id = room_cursor.lastrowid
            
            conn.commit()
            
            emit('server_created', {'success': True, 'server_id': server_id, 'server_code': server_code})
            logger.info(f"Server created successfully: {name} ({server_code}) ID:{server_id} by user {owner_id}")
            
    except Exception as e:
        logger.error(f"Error creating server: {e}")
        emit('server_created', {'success': False, 'error': f'Server creation failed: {str(e)}'})

@socketio.on('join_server')
def on_join_server(data):
    """Join an existing server - AES-GCM decryption"""
    try:
        server_code = data.get('server_code', '').strip().upper()
        user_id = data.get('user_id')
        
        logger.info(f"User {user_id} trying to join server {server_code}")
        
        if not server_code or not user_id:
            emit('server_joined', {'success': False, 'error': 'Server code and user ID are required'})
            return
        
        with get_db() as conn:
            # Find server
            server = conn.execute(
                'SELECT id, name_encrypted, owner_id FROM servers WHERE server_code = ?',
                (server_code,)
            ).fetchone()
            
            if not server:
                emit('server_joined', {'success': False, 'error': 'Invalid server code'})
                return
            
            # Check if already a member
            existing = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server['id'], user_id)
            ).fetchone()
            
            if existing:
                emit('server_joined', {'success': False, 'error': 'Already a member of this server'})
                return
            
            # Add as member
            conn.execute(
                'INSERT INTO server_members (server_id, user_id) VALUES (?, ?)',
                (server['id'], user_id)
            )
            conn.commit()
            
            # Decrypt server name for response
            server_name = encryption_manager.decrypt_data(server['name_encrypted'])
            
            emit('server_joined', {'success': True, 'server_name': server_name})
            logger.info(f"User {user_id} successfully joined server {server_name} ({server_code})")
            
    except Exception as e:
        logger.error(f"Error joining server: {e}")
        emit('server_joined', {'success': False, 'error': f'Failed to join server: {str(e)}'})

@socketio.on('leave_server')
def on_leave_server(data):
    """Leave a server"""
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        
        logger.info(f"User {user_id} trying to leave server {server_id}")
        
        if not server_id or not user_id:
            emit('server_left', {'success': False, 'error': 'Server ID and user ID are required'})
            return
        
        success, message = leave_server(server_id, user_id)
        
        if success:
            # Disconnect user from server
            disconnect_user_from_server(user_id, server_id)
            emit('server_left', {'success': True, 'message': message})
            logger.info(f"User {user_id} successfully left server {server_id}")
        else:
            emit('server_left', {'success': False, 'error': message})
            
    except Exception as e:
        logger.error(f"Error leaving server: {e}")
        emit('server_left', {'success': False, 'error': f'Failed to leave server: {str(e)}'})

@socketio.on('get_server_data')
def on_get_server_data(data):
    """Get server data including rooms - AES-GCM decryption"""
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        
        logger.info(f"Getting server data for server {server_id}, user {user_id}")
        
        if not server_id or not user_id:
            emit('server_data', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            # Verify membership
            member = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server_id, user_id)
            ).fetchone()
            
            if not member:
                emit('server_data', {'success': False, 'error': 'Not a member of this server'})
                return
            
            # Get server info - decrypt
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
            
            # Get rooms - decrypt names
            rooms_raw = conn.execute(
                'SELECT id, name_encrypted, created_at FROM rooms WHERE server_id = ? ORDER BY created_at',
                (server_id,)
            ).fetchall()
            
            rooms = []
            for room in rooms_raw:
                rooms.append({
                    'id': room['id'],
                    'name': encryption_manager.decrypt_data(room['name_encrypted']),
                    'created_at': room['created_at']
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

@socketio.on('join_room')
def on_join_room(data):
    """Join a chat room - DATABASE ONLY storage"""
    try:
        room_id = data.get('room_id')
        user_id = data.get('user_id')
        username = data.get('username')
        
        logger.info(f"User {username} ({user_id}) joining room {room_id}")
        
        if not all([room_id, user_id, username]):
            emit('room_error', {'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            # Verify room access - decrypt room name
            room_access_raw = conn.execute('''
                SELECT r.id, r.name_encrypted, r.server_id
                FROM rooms r
                JOIN server_members sm ON sm.server_id = r.server_id
                WHERE r.id = ? AND sm.user_id = ?
            ''', (room_id, user_id)).fetchone()
            
            if not room_access_raw:
                emit('room_error', {'error': 'Access denied to this room'})
                return
            
            # Decrypt room name
            room_name = encryption_manager.decrypt_data(room_access_raw['name_encrypted'])
            room_access = {
                'id': room_access_raw['id'],
                'name': room_name,
                'server_id': room_access_raw['server_id']
            }
        
        # Leave previous room if any
        if request.sid in active_users:
            old_room_id = active_users[request.sid].get('room_id')
            if old_room_id and old_room_id != room_id:
                leave_room(f'room_{old_room_id}')
                if old_room_id in room_users and request.sid in room_users[old_room_id]:
                    room_users[old_room_id].discard(request.sid)
        
        # Join new room
        join_room(f'room_{room_id}')
        
        # Update active users
        active_users[request.sid] = {
            'user_id': user_id,
            'username': username,
            'room_id': room_id,
            'server_id': room_access['server_id']
        }
        
        # Update room users
        if room_id not in room_users:
            room_users[room_id] = set()
        room_users[room_id].add(request.sid)
        
        # Load messages from database only
        messages = load_room_messages(room_id)
        
        emit('room_joined', {
            'room_id': room_id,
            'room_name': room_access['name'],
            'messages': messages
        })
        
        # Use database join tracking to determine if join message should be shown
        should_show_join_message = is_first_join_to_server(user_id, room_access['server_id'])
        
        if should_show_join_message:
            # Mark user as having joined this server
            mark_user_joined_server(user_id, room_access['server_id'])
            
            message_id = str(uuid.uuid4())
            
            # Save join message to database
            save_message_to_db(
                room_id, 
                room_access['server_id'], 
                user_id, 
                'SYSTEM', 
                f'{username} joined the room',
                'system',
                message_id
            )
            
            system_msg = {
                'id': message_id,
                'type': 'system',
                'message': f'{username} joined the room',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }
            
            emit('system_message', system_msg, room=f'room_{room_id}')
            logger.info(f"FIRST JOIN: Showed join message for {username} in server {room_access['server_id']}")
        else:
            logger.info(f"REPEAT JOIN: Skipped join message for {username} in server {room_access['server_id']}")
        
        users_in_room = [active_users[sid]['username'] for sid in room_users[room_id] if sid in active_users]
        emit('users_list', {'users': users_in_room}, room=f'room_{room_id}')
        
        logger.info(f"User {username} joined room {room_access['name']} (ID: {room_id})")
        
    except Exception as e:
        logger.error(f"Error joining room: {e}")
        emit('room_error', {'error': f'Failed to join room: {str(e)}'})

@socketio.on('send_message')
def on_send_message(data):
    """Send a chat message - DATABASE ONLY storage"""
    try:
        message_text = data.get('message', '').strip()
        user_id = data.get('user_id')
        
        if not message_text or not user_id or request.sid not in active_users:
            emit('message_error', {'error': 'Invalid message data'})
            return
        
        user_data = active_users[request.sid]
        room_id = user_data.get('room_id')
        server_id = user_data.get('server_id')
        
        if not room_id:
            emit('message_error', {'error': 'Not in a room'})
            return
        
        if len(message_text) > 1000:
            emit('message_error', {'error': 'Message too long'})
            return
        
        # Generate unique message ID to prevent duplicates
        message_id = str(uuid.uuid4())
        
        # Save to database (AES-GCM encrypted) with unique ID
        save_message_to_db(room_id, server_id, user_id, user_data['username'], message_text, 'user', message_id)
        
        message_obj = {
            'id': message_id,
            'type': 'user',
            'username': user_data['username'],
            'message': message_text,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_id': user_id
        }
        
        emit('new_message', message_obj, room=f'room_{room_id}')
        
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        emit('message_error', {'error': f'Failed to send message: {str(e)}'})

@socketio.on('kick_user')
def on_kick_user(data):
    """Kick user from server - COMPLETELY REMOVE FROM SERVER"""
    try:
        username = data.get('username')
        kicked_by = data.get('kicked_by')
        server_id = data.get('server_id')
        
        logger.info(f"Kick request: {username} from server {server_id} by user {kicked_by}")
        
        if not all([username, kicked_by, server_id]):
            emit('kick_result', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            # Verify kicker is server owner - decrypt server name
            server_raw = conn.execute(
                'SELECT owner_id, name_encrypted FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server_raw or server_raw['owner_id'] != kicked_by:
                emit('kick_result', {'success': False, 'error': 'Only server owner can kick users'})
                return
            
            server_name = encryption_manager.decrypt_data(server_raw['name_encrypted'])
            
            # Get user to kick
            user_to_kick = conn.execute(
                'SELECT id FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            if not user_to_kick:
                emit('kick_result', {'success': False, 'error': 'User not found'})
                return
            
            kicked_user_id = user_to_kick['id']
            
            # Don't allow kicking the owner
            if kicked_user_id == kicked_by:
                emit('kick_result', {'success': False, 'error': 'Cannot kick yourself'})
                return
            
            # Check if user is in the server
            member = conn.execute(
                'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
                (server_id, kicked_user_id)
            ).fetchone()
            
            if not member:
                emit('kick_result', {'success': False, 'error': 'User is not a member of this server'})
                return
            
            # COMPLETELY REMOVE USER FROM SERVER
            conn.execute('''
                DELETE FROM server_members 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, kicked_user_id))
            
            # CLEAN UP: Remove join tracking for kicked user
            conn.execute('''
                DELETE FROM user_server_join_map 
                WHERE server_id = ? AND user_id = ?
            ''', (server_id, kicked_user_id))
            
            conn.commit()
            
            # Get kicker username for system message
            kicker = conn.execute('SELECT username FROM users WHERE id = ?', (kicked_by,)).fetchone()
            kicker_name = kicker['username'] if kicker else 'Admin'
            
            # Find and disconnect all sockets for the kicked user from this server
            kicked_sockets = []
            for sid, user_data in list(active_users.items()):
                if (user_data.get('user_id') == kicked_user_id and 
                    user_data.get('server_id') == server_id):
                    kicked_sockets.append(sid)
            
            # Notify kicked user with page reload instruction
            for sid in kicked_sockets:
                try:
                    # Send kick notification with reload instruction
                    socketio.emit('kicked_from_server_reload', {
                        'message': f'You have been removed from "{server_name}" by {kicker_name}',
                        'server_id': server_id,
                        'reload': True
                    }, room=sid)
                    
                    # Clean up user data
                    if sid in active_users:
                        user_data = active_users[sid]
                        room_id = user_data.get('room_id')
                        
                        # Remove from room users tracking
                        if room_id and room_id in room_users:
                            room_users[room_id].discard(sid)
                        
                        # Leave socket room
                        if room_id:
                            leave_room(f'room_{room_id}', sid=sid)
                        
                        del active_users[sid]
                    
                except Exception as e:
                    logger.error(f"Error notifying kicked user {sid}: {e}")
            
            # Broadcast system message to remaining users in all rooms
            rooms_raw = conn.execute('SELECT id, name_encrypted FROM rooms WHERE server_id = ?', (server_id,)).fetchall()
            
            for room_raw in rooms_raw:
                room_name = encryption_manager.decrypt_data(room_raw['name_encrypted'])
                message_id = str(uuid.uuid4())
                
                system_msg = {
                    'id': message_id,
                    'type': 'system',
                    'message': f'{username} was removed from the server by {kicker_name}',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                emit('system_message', system_msg, room=f'room_{room_raw["id"]}')
                
                # Save system message to database
                save_message_to_db(
                    room_raw['id'], 
                    server_id, 
                    kicked_by, 
                    'SYSTEM', 
                    f'{username} was removed from the server by {kicker_name}',
                    'system',
                    message_id
                )
                
                # Update users list for each room (kicked user will be gone)
                if room_raw['id'] in room_users:
                    users_in_room = [active_users[sid]['username'] for sid in room_users[room_raw['id']] if sid in active_users]
                    emit('users_list', {'users': users_in_room}, room=f'room_{room_raw["id"]}')
            
            emit('kick_result', {'success': True, 'message': f'{username} has been completely removed from the server'})
            logger.info(f"User {username} COMPLETELY REMOVED from server {server_name} by {kicker_name}")
                
    except Exception as e:
        logger.error(f"Error kicking user: {e}")
        emit('kick_result', {'success': False, 'error': f'Failed to kick user: {str(e)}'})

@socketio.on('delete_room')
def on_delete_room(data):
    """Delete a room - Only server owners can delete rooms"""
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
            
            # Decrypt room name
            room_name = encryption_manager.decrypt_data(room_info_raw['name_encrypted'])
            
            # Check if user is server owner
            if room_info_raw['owner_id'] != user_id:
                emit('room_deleted', {'success': False, 'error': 'Only server owners can delete rooms'})
                return
            
            # Prevent deletion of 'general' room
            if room_name.lower() == 'general':
                emit('room_deleted', {'success': False, 'error': 'Cannot delete the general room'})
                return
            
            server_id = room_info_raw['server_id']
            
            # Get all users currently in this room to notify them
            users_to_notify = []
            if room_id in room_users:
                users_to_notify = list(room_users[room_id])
            
            # Kick all users from the room first
            for sid in users_to_notify:
                try:
                    if sid in active_users:
                        # Notify user that room is being deleted
                        socketio.emit('system_message', {
                            'id': str(uuid.uuid4()),
                            'type': 'system',
                            'message': f'Room #{room_name} has been deleted by the server owner',
                            'timestamp': datetime.now().strftime('%H:%M:%S')
                        }, room=sid)
                        
                        # Remove from room tracking
                        active_users[sid]['room_id'] = None
                        leave_room(f'room_{room_id}', sid=sid)
                
                except Exception as e:
                    logger.error(f"Error notifying user {sid} about room deletion: {e}")
            
            # Clear room users tracking
            if room_id in room_users:
                del room_users[room_id]
            
            # Delete all messages in this room from database
            conn.execute('DELETE FROM messages WHERE room_id = ?', (room_id,))
            
            # Delete the room from database
            conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
            
            conn.commit()
            
            emit('room_deleted', {'success': True, 'message': f'Room #{room_name} has been deleted'})
            logger.info(f"Room '{room_name}' (ID: {room_id}) deleted successfully by user {user_id}")
            
    except Exception as e:
        logger.error(f"Error deleting room: {e}")
        emit('room_deleted', {'success': False, 'error': f'Failed to delete room: {str(e)}'})

@socketio.on('delete_server')
def on_delete_server(data):
    """Delete a server - Only server owners can delete their servers"""
    try:
        server_id = data.get('server_id')
        user_id = data.get('user_id')
        
        logger.info(f"Delete server request: server {server_id} by user {user_id}")
        
        if not server_id or not user_id:
            emit('server_deleted', {'success': False, 'error': 'Missing required data'})
            return
        
        with get_db() as conn:
            # Verify user is the server owner
            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server:
                emit('server_deleted', {'success': False, 'error': 'Server not found'})
                return
            
            if server['owner_id'] != user_id:
                emit('server_deleted', {'success': False, 'error': 'Only the server owner can delete this server'})
                return

            # Delete the server. ON DELETE CASCADE in the database will handle removing members, rooms, messages, etc.
            conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
            conn.commit()
            
            emit('server_deleted', {'success': True, 'server_id': server_id})
            logger.info(f"Server {server_id} deleted successfully by owner {user_id}")

    except Exception as e:
        logger.error(f"Error deleting server: {e}")
        emit('server_deleted', {'success': False, 'error': f'Failed to delete server: {str(e)}'})

@socketio.on('create_room')
def on_create_room(data):
    """Create new room - Enhanced with proper validation"""
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
        
        # Validate room name (no special characters except underscore and dash)
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', room_name):
            emit('room_created', {'success': False, 'error': 'Room name can only contain letters, numbers, underscore, and dash'})
            return
        
        with get_db() as conn:
            # Verify user is server owner
            server = conn.execute(
                'SELECT owner_id FROM servers WHERE id = ?',
                (server_id,)
            ).fetchone()
            
            if not server or server['owner_id'] != user_id:
                emit('room_created', {'success': False, 'error': 'Only server owners can create rooms'})
                return
            
            # Check if room name already exists in this server
            existing_rooms = conn.execute(
                'SELECT name_encrypted FROM rooms WHERE server_id = ?',
                (server_id,)
            ).fetchall()
            
            for existing_room in existing_rooms:
                existing_name = encryption_manager.decrypt_data(existing_room['name_encrypted']).lower()
                if existing_name == room_name.lower():
                    emit('room_created', {'success': False, 'error': 'A room with this name already exists'})
                    return
            
            # Create room with encrypted name
            room_name_encrypted = encryption_manager.encrypt_data(room_name)
            cursor = conn.execute(
                'INSERT INTO rooms (server_id, name_encrypted, created_by) VALUES (?, ?, ?)',
                (server_id, room_name_encrypted, user_id)
            )
            room_id = cursor.lastrowid
            conn.commit()
            
            emit('room_created', {'success': True, 'room_id': room_id, 'room_name': room_name})
            logger.info(f"Room '{room_name}' created successfully in server {server_id}")
            
    except Exception as e:
        logger.error(f"Error creating room: {e}")
        emit('room_created', {'success': False, 'error': f'Failed to create room: {str(e)}'})

@socketio.on('get_room_logs')  
def on_get_room_logs(data):
    """Get room chat logs from database"""
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
        
        # Verify user has access to this room
        with get_db() as conn:
            access = conn.execute('''
                SELECT 1 FROM rooms r
                JOIN server_members sm ON r.server_id = sm.server_id
                WHERE r.id = ? AND sm.user_id = ?
            ''', (room_id, user_id)).fetchone()
            
            if not access:
                emit('room_logs', {'success': False, 'error': 'Access denied to this room'})
                return
        
        # Load messages from database
        messages = load_room_messages(room_id, limit)
        
        emit('room_logs', {'success': True, 'messages': messages})
        logger.info(f"Loaded {len(messages)} log messages for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error loading room logs: {e}")
        emit('room_logs', {'success': False, 'error': f'Failed to load logs: {str(e)}'})

@socketio.on('change_nickname')
def on_change_nickname(data):
    """Handle nickname change requests"""
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
            # Get current username
            user = conn.execute(
                'SELECT username FROM users WHERE id = ?',
                (user_id,)
            ).fetchone()
            
            if not user:
                emit('nickname_error', {'error': 'User not found'})
                return
                
            old_nick = user['username']
            
            # Update database
            conn.execute('UPDATE users SET username = ? WHERE id = ?', (new_nick, user_id))
            
            # Get server_id
            room_info = conn.execute(
                'SELECT server_id, name_encrypted FROM rooms WHERE id = ?',
                (room_id,)
            ).fetchone()
            
            if not room_info:
                emit('nickname_error', {'error': 'Room not found'})
                return
                
            server_id = room_info['server_id']
            room_name = encryption_manager.decrypt_data(room_info['name_encrypted'])
            
            conn.commit()

        # Update active_users with new nickname
        for sid, user_data in active_users.items():
            if user_data.get('user_id') == user_id and user_data.get('room_id') == room_id:
                user_data['username'] = new_nick
                break

        # Generate unique message ID
        message_id = str(uuid.uuid4())
        
        # Create system message
        system_message = f"{old_nick} is now known as {new_nick}"
        
        # Save to database
        save_message_to_db(
            room_id, 
            server_id, 
            user_id, 
            'SYSTEM', 
            system_message,
            'system',
            message_id
        )
        
        # Broadcast system message to all users in the room
        system_msg = {
            'id': message_id,
            'type': 'system',
            'message': system_message,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        emit('system_message', system_msg, room=f'room_{room_id}')
        
        # Broadcast updated user list to all users in the room
        if room_id in room_users:
            users_in_room = []
            for sid in room_users[room_id]:
                if sid in active_users:
                    users_in_room.append(active_users[sid]['username'])
            
            # Remove duplicates and sort
            unique_users = sorted(list(set(users_in_room)))
            emit('users_list', {'users': unique_users}, room=f'room_{room_id}')
        
        logger.info(f"Nickname changed: {old_nick} -> {new_nick} in room {room_id}")
        emit('nickname_changed', {'success': True, 'new_nick': new_nick})
        
    except Exception as e:
        logger.error(f"Error changing nickname: {e}")
        emit('nickname_error', {'error': f'Failed to change nickname: {str(e)}'})

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
    logger.info("TERMINET IRC SERVER - AES-GCM & DATABASE ONLY")
    logger.info("="*60)
    logger.info(f"Server URL: http://localhost:5000")
    logger.info(f"Database: {DATABASE} (AES-GCM ENCRYPTED + MESSAGE IDs)")
    logger.info(f"Storage: Database-only (no log files)")
    logger.info(f"Encryption: AES-256-GCM")
    logger.info(f"Encryption Key: {CUSTOM_ENCRYPTION_KEY[:30]}...")
    logger.info("IMPROVEMENTS:")
    logger.info("Ã¢Å“â€¦ AES-GCM encryption (more efficient than Fernet)")
    logger.info("Ã¢Å“â€¦ Database-only storage (no log folder system)")
    logger.info("Ã¢Å“â€¦ Smaller file size and reduced complexity")
    logger.info("Ã¢Å“â€¦ No duplicate messages on refresh")
    logger.info("Ã¢Å“â€¦ Join tracking still works perfectly")
    
    logger.info("Starting AES-GCM server on port 5000...")
    
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
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
