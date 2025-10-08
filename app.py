import os
import datetime
import logging
import mimetypes
import hashlib
import json
from urllib.parse import urlparse, unquote
from functools import wraps
import sqlite3
from contextlib import contextmanager

from flask import Flask, jsonify, request, send_from_directory, make_response, Response, session, redirect, url_for
from werkzeug.utils import secure_filename

# Azure imports
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

# NLP Translation imports - UPDATED: Using deep-translator instead of googletrans
from deep_translator import GoogleTranslator
import requests

# ---- Logging / Flask ----
logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.secret_key = 'manuscript-secret-key-2024'

# Session configuration
app.config.update(
    SESSION_COOKIE_NAME='manuscript_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400,
    SESSION_REFRESH_EACH_REQUEST=True
)

app.logger.setLevel(logging.DEBUG)

# ---- SQLite Database Configuration ----
DB_PATH = os.path.join(os.path.dirname(__file__), 'manuscripts.db')

def init_db():
    """Initialize SQLite database with tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create tables
        cursor.executescript('''
            -- Users table
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'Researcher',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            );

            -- Topics table
            CREATE TABLE IF NOT EXISTS topics (
                topic_id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic_name TEXT UNIQUE NOT NULL,
                description TEXT
            );

            -- Locations table
            CREATE TABLE IF NOT EXISTS locations (
                location_id INTEGER PRIMARY KEY AUTOINCREMENT,
                location_name TEXT UNIQUE NOT NULL,
                description TEXT
            );

            -- Manuscripts table
            CREATE TABLE IF NOT EXISTS manuscripts (
                manuscript_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT,
                topic_id INTEGER,
                location_id INTEGER,
                file_url TEXT NOT NULL,
                uploaded_by INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (topic_id) REFERENCES topics(topic_id),
                FOREIGN KEY (location_id) REFERENCES locations(location_id),
                FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
            );

            -- Translations table
            CREATE TABLE IF NOT EXISTS translations (
                translation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                manuscript_id INTEGER,
                translator_id INTEGER NOT NULL,
                translation_title TEXT NOT NULL,
                translated_text TEXT NOT NULL,
                language TEXT DEFAULT 'en',
                target_language TEXT DEFAULT 'en',
                method TEXT DEFAULT 'Manual',
                status TEXT DEFAULT 'Draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (manuscript_id) REFERENCES manuscripts(manuscript_id),
                FOREIGN KEY (translator_id) REFERENCES users(user_id)
            );
        ''')
        
        # Insert sample data
        topics = ['Religion', 'Philosophy', 'Science', 'Literature', 'History', 
                 'Mathematics', 'Medicine', 'Astronomy', 'Law', 'Arts']
        for topic in topics:
            cursor.execute("INSERT OR IGNORE INTO topics (topic_name) VALUES (?)", (topic,))
        
        locations = ['Europe', 'Asia', 'Africa', 'Middle East', 'Americas',
                    'Mediterranean', 'India', 'China', 'Persia', 'Byzantium']
        for location in locations:
            cursor.execute("INSERT OR IGNORE INTO locations (location_name) VALUES (?)", (location,))
        
        # Create default admin user (password: admin123)
        admin_password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
            ('admin', 'admin@manuscripts.org', admin_password_hash, 'System Administrator', 'Admin')
        )
        
        conn.commit()
        app.logger.info("✅ SQLite database initialized successfully")

@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Initialize database on startup
init_db()

# ---- Azure Configuration ----
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING", "DefaultEndpointsProtocol=https;AccountName=raaghavi01;AccountKey=FGDUXkYF0N9ScIhaYr9xCNZ658wyX1GrspaISBhFprJIPbwo+KUUxqSUWq6E/WdXDGyc9Fj6zjmJ+AStFyp01g==;EndpointSuffix=core.windows.net")
CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME", "manuscripts")

# Upload config
ALLOWED_EXT = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}
MAX_UPLOAD_SIZE = 30 * 1024 * 1024

# ---- Azure client ----
blob_service_client = None
container_client = None
if AZURE_CONNECTION_STRING:
    try:
        blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
        container_client = blob_service_client.get_container_client(CONTAINER_NAME)
        try:
            container_client.create_container()
        except ResourceExistsError:
            pass
        app.logger.info("Azure Blob client initialized.")
    except Exception as e:
        app.logger.exception("Azure Blob initialization failed: %s", e)
        blob_service_client = None
        container_client = None
else:
    app.logger.info("No AZURE_CONNECTION_STRING provided — using local file fallback.")

# ---- NLP Translation Service ----
class AdvancedTranslationService:
    def __init__(self):
        try:
            # Test the translator
            test_result = GoogleTranslator(source='en', target='es').translate('hello')
            self.supported_languages = GoogleTranslator().get_supported_languages(as_dict=True)
            app.logger.info("Deep Translator service initialized successfully")
        except Exception as e:
            app.logger.warning(f"Deep Translator initialization failed: {e}")
            self.supported_languages = {
                'en': 'english', 'es': 'spanish', 'fr': 'french', 'de': 'german',
                'it': 'italian', 'pt': 'portuguese', 'ru': 'russian', 
                'zh': 'chinese', 'ja': 'japanese', 'ar': 'arabic', 'hi': 'hindi',
                'la': 'latin', 'el': 'greek'
            }
    
    def map_language_code(self, code):
        mapping = {
            'zh-cn': 'zh',
            'sa': 'hi',
            'grc': 'el',
        }
        return mapping.get(code, code)
    
    def translate_manuscript(self, text, target_lang='en', source_lang='auto'):
        try:
            if not text or not text.strip():
                return {
                    'success': False,
                    'error': 'No text provided for translation',
                    'translated_text': '',
                    'method': 'Google Translate'
                }
            
            text = text.strip()
            mapped_target = self.map_language_code(target_lang)
            mapped_source = self.map_language_code(source_lang) if source_lang != 'auto' else 'auto'
            
            if len(text) > 4500:
                return self._translate_large_text(text, mapped_target, mapped_source)
            
            if mapped_source == 'auto':
                translated = GoogleTranslator(target=mapped_target).translate(text)
            else:
                translated = GoogleTranslator(source=mapped_source, target=mapped_target).translate(text)
            
            return {
                'success': True,
                'translated_text': translated,
                'source_language': source_lang,
                'source_language_name': self.supported_languages.get(source_lang, 'Unknown'),
                'target_language': target_lang,
                'target_language_name': self.supported_languages.get(target_lang, 'Unknown'),
                'confidence': 'high',
                'method': 'Google Translate',
                'characters_translated': len(text)
            }
            
        except Exception as e:
            logging.error(f"Translation error: {str(e)}")
            return {
                'success': False,
                'error': f'Translation service error: {str(e)}',
                'translated_text': text,
                'method': 'Google Translate',
                'fallback_used': True
            }
    
    def _translate_large_text(self, text, target_lang, source_lang):
        try:
            chunks = self._split_text_into_chunks(text)
            translated_chunks = []
            
            for i, chunk in enumerate(chunks):
                try:
                    if source_lang == 'auto':
                        result = GoogleTranslator(target=target_lang).translate(chunk)
                    else:
                        result = GoogleTranslator(source=source_lang, target=target_lang).translate(chunk)
                    translated_chunks.append(result)
                except Exception as e:
                    translated_chunks.append(chunk)
            
            return {
                'success': True,
                'translated_text': ' '.join(translated_chunks),
                'source_language': source_lang if source_lang != 'auto' else 'detected',
                'target_language': target_lang,
                'confidence': 'medium',
                'method': 'Google Translate (Chunked)',
                'note': f'Text was split into {len(chunks)} chunks for translation',
                'characters_translated': len(text)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Large text translation failed: {str(e)}',
                'translated_text': text,
                'method': 'Google Translate',
                'fallback_used': True
            }
    
    def _split_text_into_chunks(self, text, max_chunk_size=4000):
        sentences = text.split('. ')
        chunks = []
        current_chunk = ""
        
        for sentence in sentences:
            if len(current_chunk) + len(sentence) >= max_chunk_size and current_chunk:
                chunks.append(current_chunk.strip() + '.')
                current_chunk = sentence + '. '
            else:
                current_chunk += sentence + '. '
        
        if current_chunk.strip():
            chunks.append(current_chunk.strip())
        
        if not chunks:
            words = text.split()
            current_chunk = ""
            for word in words:
                if len(current_chunk) + len(word) + 1 < max_chunk_size:
                    current_chunk += word + " "
                else:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                    current_chunk = word + " "
            if current_chunk:
                chunks.append(current_chunk.strip())
        
        return chunks
    
    def detect_language_advanced(self, text):
        try:
            if not text or len(text.strip()) < 3:
                return {
                    'success': False,
                    'error': 'Text too short for language detection',
                    'language_code': 'unknown',
                    'language_name': 'Unknown'
                }
            
            clean_text = text.strip()
            if len(clean_text) < 3:
                return {
                    'success': False,
                    'error': 'Text too short for language detection',
                    'language_code': 'unknown',
                    'language_name': 'Unknown'
                }
            
            return {
                'success': True,
                'language_code': 'en',
                'language_name': 'English',
                'confidence': 0.5,
                'reliable': False,
                'note': 'Language detection is limited in this version'
            }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Language detection failed: {str(e)}',
                'language_code': 'unknown',
                'language_name': 'Unknown'
            }
    
    def get_language_name(self, code):
        return self.supported_languages.get(code, 'Unknown')

translation_service = AdvancedTranslationService()

# ---- Authentication Decorators ----
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'Admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def translator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['Admin', 'Translator']:
            return jsonify({"error": "Translator access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ---- Helpers ----
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def safe_filename(filename):
    return secure_filename(filename)

def extract_blob_name_from_url(url):
    if not url:
        return None
    try:
        url = unquote(url)
        parsed = urlparse(url)
        path = parsed.path.lstrip('/')
        if path.startswith(CONTAINER_NAME + '/'):
            return path[len(CONTAINER_NAME) + 1:]
        return path
    except Exception:
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_file_mimetype(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    mime_types = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg'
    }
    return mime_types.get(ext, 'application/octet-stream')

# ------------------ Authentication Routes ------------------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name', '')
        role = data.get('role', 'Researcher')

        if not all([username, email, password]):
            return jsonify({"error": "Missing required fields: username, email, and password are required"}), 400

        password_hash = hash_password(password)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, password_hash, full_name, role))
                conn.commit()
                
                return jsonify({"message": "User registered successfully"})
        except sqlite3.IntegrityError as e:
            if "username" in str(e).lower():
                return jsonify({"error": "Username already exists"}), 400
            elif "email" in str(e).lower():
                return jsonify({"error": "Email already exists"}), 400
            else:
                return jsonify({"error": "User already exists"}), 400
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            return jsonify({"error": "Registration failed: " + str(e)}), 500
    except Exception as e:
        app.logger.error(f"Registration endpoint error: {e}")
        return jsonify({"error": "Server error during registration"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        password_hash = hash_password(password)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT user_id, username, email, full_name, role, password_hash 
                    FROM users WHERE username = ?
                """, (username,))
                
                user = cursor.fetchone()
                
                if user and user['password_hash'] == password_hash:
                    cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?", (user['user_id'],))
                    conn.commit()
                    
                    session.permanent = True
                    session['user_id'] = user['user_id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['full_name'] = user['full_name']
                    
                    app.logger.info(f"User {username} logged in successfully")
                    
                    return jsonify({
                        "message": "Login successful",
                        "user": {
                            "user_id": user['user_id'],
                            "username": user['username'],
                            "full_name": user['full_name'],
                            "role": user['role']
                        }
                    })
                else:
                    return jsonify({"error": "Invalid credentials"}), 401
                    
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            return jsonify({"error": "Login failed: " + str(e)}), 500
    except Exception as e:
        app.logger.error(f"Login endpoint error: {e}")
        return jsonify({"error": "Server error during login"}), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route('/user/profile', methods=['GET'])
@login_required
def get_user_profile():
    return jsonify({
        "user_id": session.get('user_id'),
        "username": session.get('username'),
        "full_name": session.get('full_name'),
        "role": session.get('role')
    })

# ------------------ Serve Frontend ------------------
@app.route('/')
def serve_index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except Exception as e:
        return f"Error loading index.html: {str(e)}", 500

@app.route('/login-page')
def serve_login_page():
    try:
        with open('login.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except Exception as e:
        return f"Error loading login.html: {str(e)}", 500

@app.route('/<path:filename>')
def serve_static(filename):
    try:
        return send_from_directory('.', filename)
    except Exception as e:
        return f"File not found: {filename}", 404

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    return send_from_directory(uploads_dir, filename)

# ------------------ API: Get Manuscripts ------------------
@app.route('/manuscripts', methods=['GET'])
def get_manuscripts():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT m.manuscript_id, m.title, m.author, m.topic_id, m.location_id, m.file_url,
                       COALESCE(t.topic_name, '') AS topic_name,
                       COALESCE(l.location_name, '') AS location_name,
                       m.upload_date
                FROM manuscripts m
                LEFT JOIN topics t ON m.topic_id = t.topic_id
                LEFT JOIN locations l ON m.location_id = l.location_id
                ORDER BY m.manuscript_id DESC
            """)
            rows = cursor.fetchall()
            manuscripts = []
            for row in rows:
                manuscript = dict(row)
                for k, v in manuscript.items():
                    if isinstance(v, (datetime.date, datetime.datetime)):
                        manuscript[k] = v.isoformat()
                manuscripts.append(manuscript)
            return jsonify(manuscripts)
    except Exception as e:
        app.logger.exception("DB error in get_manuscripts")
        return jsonify({"error": str(e)}), 500

# ------------------ API: Upload Manuscript ------------------
@app.route('/upload', methods=['POST'])
@admin_required
def upload_manuscript():
    try:
        title = request.form.get('title')
        author = request.form.get('author')
        topic_id = request.form.get('topic_id')
        location_id = request.form.get('location_id') or None
        uploaded_by = session.get('user_id')
        file = request.files.get('file')

        app.logger.info(f"Upload request - Title: {title}, Author: {author}, Topic: {topic_id}, Location: {location_id}")

        if not (title and author and topic_id and file):
            return jsonify({"error": "Missing required fields: title, author, topic, and file are required"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": f"File type not allowed. Supported types: {', '.join(ALLOWED_EXT)}"}), 400

        # Generate unique filename
        original_filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{original_filename.rsplit('.', 1)[0]}_{timestamp}.{original_filename.rsplit('.', 1)[1]}"
        
        file_url = None

        # Try Azure first
        if blob_service_client:
            try:
                blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=filename)
                file.stream.seek(0)
                blob_client.upload_blob(file.stream, overwrite=True)
                file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{CONTAINER_NAME}/{filename}"
                app.logger.info("Uploaded to Azure: %s", file_url)
            except Exception as e:
                app.logger.warning("Azure upload failed, fallback to local: %s", e)
                file_url = None

        # Local fallback - REMOVED for Render compatibility
        if not file_url:
            app.logger.error("Azure upload failed and local storage not available on Render")
            return jsonify({"error": "File upload failed. Azure Blob Storage is required for cloud deployment."}), 500

        # Save metadata
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO manuscripts (title, author, topic_id, location_id, file_url, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (title, author, topic_id, location_id, file_url, uploaded_by))
                conn.commit()
                
                manuscript_id = cursor.lastrowid
                app.logger.info(f"Manuscript saved successfully with ID: {manuscript_id}")
                
                return jsonify({
                    "message": "✅ Manuscript uploaded successfully!", 
                    "file_url": file_url,
                    "manuscript_id": manuscript_id
                })
        except Exception as e:
            app.logger.exception("DB insert error upload_manuscript")
            return jsonify({"error": f"Database error: {str(e)}"}), 500

    except Exception as e:
        app.logger.exception("Upload manuscript error")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

# ------------------ File Preview & Download Routes ------------------
@app.route('/preview/<int:manuscript_id>')
@login_required
def preview_manuscript(manuscript_id):
    """Enhanced preview with multiple viewing options"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_url, title FROM manuscripts WHERE manuscript_id = ?", (manuscript_id,))
            manuscript = cursor.fetchone()
            
            if not manuscript:
                return jsonify({"error": "Manuscript not found"}), 404
            
            file_url = manuscript['file_url']
            title = manuscript['title']
            
            if not file_url:
                return jsonify({"error": "No file URL available"}), 404
            
            # Create a preview page with multiple options
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Preview: {title}</title>
                <style>
                    body {{ 
                        margin: 0; 
                        padding: 0; 
                        font-family: 'Segoe UI', system-ui, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 40px 20px;
                    }}
                    .preview-card {{
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(20px);
                        border-radius: 20px;
                        padding: 40px;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        text-align: center;
                        margin-bottom: 30px;
                        border-bottom: 2px solid #f0f0f0;
                        padding-bottom: 20px;
                    }}
                    .header h1 {{
                        color: #2c3e50;
                        margin-bottom: 10px;
                        font-size: 2.2em;
                    }}
                    .header p {{
                        color: #666;
                        font-size: 1.1em;
                    }}
                    .preview-options {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 20px;
                        margin-bottom: 30px;
                    }}
                    .option-card {{
                        background: white;
                        padding: 25px;
                        border-radius: 15px;
                        text-align: center;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                        border: 2px solid transparent;
                        transition: all 0.3s ease;
                        cursor: pointer;
                    }}
                    .option-card:hover {{
                        transform: translateY(-5px);
                        border-color: #3498db;
                        box-shadow: 0 15px 40px rgba(52, 152, 219, 0.2);
                    }}
                    .option-icon {{
                        font-size: 3em;
                        margin-bottom: 15px;
                        color: #3498db;
                    }}
                    .option-title {{
                        font-size: 1.3em;
                        font-weight: 600;
                        color: #2c3e50;
                        margin-bottom: 10px;
                    }}
                    .option-desc {{
                        color: #666;
                        line-height: 1.5;
                    }}
                    .viewer-container {{
                        background: white;
                        border-radius: 15px;
                        padding: 20px;
                        margin-top: 20px;
                        display: none;
                    }}
                    .viewer-frame {{
                        width: 100%;
                        height: 70vh;
                        border: none;
                        border-radius: 10px;
                    }}
                    .action-buttons {{
                        text-align: center;
                        margin-top: 30px;
                    }}
                    .btn {{
                        display: inline-flex;
                        align-items: center;
                        gap: 10px;
                        padding: 12px 25px;
                        background: linear-gradient(135deg, #3498db, #2c3e50);
                        color: white;
                        text-decoration: none;
                        border-radius: 50px;
                        font-weight: 600;
                        margin: 0 10px;
                        transition: all 0.3s ease;
                        border: none;
                        cursor: pointer;
                    }}
                    .btn:hover {{
                        transform: translateY(-3px);
                        box-shadow: 0 10px 25px rgba(52, 152, 219, 0.3);
                    }}
                    .btn-download {{
                        background: linear-gradient(135deg, #27ae60, #219a52);
                    }}
                    .btn-download:hover {{
                        box-shadow: 0 10px 25px rgba(39, 174, 96, 0.3);
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="preview-card">
                        <div class="header">
                            <h1>📖 {title}</h1>
                            <p>Choose how you want to view this manuscript</p>
                        </div>
                        
                        <div class="preview-options">
                            <div class="option-card" onclick="openDirectView()">
                                <div class="option-icon">🔗</div>
                                <div class="option-title">Direct View</div>
                                <div class="option-desc">Open the file directly in your browser</div>
                            </div>
                            
                            <div class="option-card" onclick="openGoogleViewer()">
                                <div class="option-icon">📄</div>
                                <div class="option-title">Google Docs Viewer</div>
                                <div class="option-desc">Use Google's PDF viewer (recommended for PDFs)</div>
                            </div>
                            
                            <div class="option-card" onclick="openNewTab()">
                                <div class="option-icon">🔄</div>
                                <div class="option-title">New Tab</div>
                                <div class="option-desc">Open in a new browser tab</div>
                            </div>
                        </div>
                        
                        <div id="viewer-container" class="viewer-container">
                            <iframe id="viewer-frame" class="viewer-frame" src=""></iframe>
                        </div>
                        
                        <div class="action-buttons">
                            <a href="/download/{manuscript_id}" class="btn btn-download">
                                <i class="fas fa-download"></i> Download File
                            </a>
                            <button class="btn" onclick="window.close()">
                                <i class="fas fa-times"></i> Close Preview
                            </button>
                        </div>
                    </div>
                </div>
                
                <script>
                    const fileUrl = "{file_url}";
                    
                    function openDirectView() {{
                        // Try to open directly with inline disposition
                        window.open(fileUrl, '_blank');
                    }}
                    
                    function openGoogleViewer() {{
                        // Use Google Docs viewer for better PDF rendering
                        const googleViewerUrl = `https://docs.google.com/gview?url=${{fileUrl}}&embedded=true`;
                        document.getElementById('viewer-frame').src = googleViewerUrl;
                        document.getElementById('viewer-container').style.display = 'block';
                    }}
                    
                    function openNewTab() {{
                        window.open(fileUrl, '_blank');
                    }}
                    
                    // Auto-open Google Viewer for PDF files
                    if (fileUrl.toLowerCase().endsWith('.pdf')) {{
                        setTimeout(() => openGoogleViewer(), 500);
                    }}
                </script>
            </body>
            </html>
            """
            
            return html_content
                
    except Exception as e:
        app.logger.error(f"Preview manuscript error: {e}")
        return jsonify({"error": f"Failed to preview manuscript: {str(e)}"}), 500

@app.route('/download/<int:manuscript_id>')
@login_required
def download_manuscript(manuscript_id):
    """Download manuscript file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_url, title FROM manuscripts WHERE manuscript_id = ?", (manuscript_id,))
            manuscript = cursor.fetchone()
            
            if not manuscript:
                return jsonify({"error": "Manuscript not found"}), 404
            
            file_url = manuscript['file_url']
            title = manuscript['title']
            
            # If it's an Azure URL, redirect to it
            if file_url and file_url.startswith('http'):
                # For Azure URLs, we can redirect directly
                response = redirect(file_url)
                # Try to suggest download filename
                safe_title = secure_filename(title)
                response.headers['Content-Disposition'] = f'attachment; filename="{safe_title}.pdf"'
                return response
            
            # If it's a local path (this won't work on Render for uploaded files)
            elif file_url and file_url.startswith('/uploads/'):
                filename = file_url.split('/')[-1]
                uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
                file_path = os.path.join(uploads_dir, filename)
                
                if os.path.exists(file_path):
                    safe_title = secure_filename(title)
                    return send_from_directory(
                        uploads_dir, 
                        filename, 
                        as_attachment=True,
                        download_name=f"{safe_title}.{filename.split('.')[-1]}"
                    )
                else:
                    return jsonify({"error": "File not found on server. On Render cloud, files must be stored in Azure Blob Storage."}), 404
            else:
                return jsonify({"error": "Invalid file URL or file not accessible"}), 404
                
    except Exception as e:
        app.logger.error(f"Download manuscript error: {e}")
        return jsonify({"error": f"Failed to download manuscript: {str(e)}"}), 500

# ------------------ Translation Download Routes ------------------
@app.route('/translations/<int:translation_id>')
@login_required
def get_translation(translation_id):
    """Get specific translation details"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT tr.*, m.title as manuscript_title, m.author as manuscript_author,
                       u.username as translator_name, u.full_name as translator_full_name
                FROM translations tr
                LEFT JOIN manuscripts m ON tr.manuscript_id = m.manuscript_id
                LEFT JOIN users u ON tr.translator_id = u.user_id
                WHERE tr.translation_id = ?
            """, (translation_id,))
            
            translation = cursor.fetchone()
            
            if not translation:
                return jsonify({"error": "Translation not found"}), 404
            
            translation_dict = dict(translation)
            # Convert datetime objects to strings
            for key, value in translation_dict.items():
                if isinstance(value, (datetime.datetime, datetime.date)):
                    translation_dict[key] = value.isoformat()
            
            return jsonify(translation_dict)
            
    except Exception as e:
        app.logger.error(f"Get translation error: {e}")
        return jsonify({"error": "Failed to load translation"}), 500

@app.route('/translations/<int:translation_id>/download')
@login_required
def download_translation(translation_id):
    """Download translation as text file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT translation_title, translated_text, target_language
                FROM translations WHERE translation_id = ?
            """, (translation_id,))
            
            translation = cursor.fetchone()
            
            if not translation:
                return jsonify({"error": "Translation not found"}), 404
            
            # Create text file
            text_content = translation['translated_text']
            filename = f"{translation['translation_title']}_{translation['target_language']}.txt"
            safe_filename = secure_filename(filename)
            
            response = make_response(text_content)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
            
            return response
            
    except Exception as e:
        app.logger.error(f"Download translation error: {e}")
        return jsonify({"error": "Failed to download translation"}), 500

# ------------------ Topics & Locations ------------------
@app.route('/topics', methods=['GET'])
def get_topics():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM topics ORDER BY topic_name")
            rows = cursor.fetchall()
            return jsonify([dict(row) for row in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/locations', methods=['GET'])
def get_locations():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM locations ORDER BY location_name")
            rows = cursor.fetchall()
            return jsonify([dict(row) for row in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ Save/Get Translations ------------------
@app.route('/translate', methods=['POST'])
@translator_required
def save_translation():
    try:
        data = request.get_json(force=True)
        app.logger.info(f"Translation data received: {data}")
        
        manuscript_id = data.get('manuscript_id')
        translator_id = session.get('user_id')
        translation_title = data.get('translation_title')
        translated_text = data.get('translated_text')
        language = data.get('language', 'en')
        target_language = data.get('target_language', 'en')
        method = data.get('method', 'Manual')

        app.logger.info(f"Translation save - Manuscript: {manuscript_id}, Title: {translation_title}, Text length: {len(translated_text) if translated_text else 0}")

        if not translation_title or not translation_title.strip():
            return jsonify({"error": "Translation title is required"}), 400
        if not translated_text or not translated_text.strip():
            return jsonify({"error": "Translation text is required"}), 400

        # Handle NULL manuscript_id
        if manuscript_id == "" or manuscript_id == "null" or manuscript_id is None:
            manuscript_id = None
        else:
            try:
                manuscript_id = int(manuscript_id)
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid manuscript ID"}), 400

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # If manuscript_id is provided, validate it exists
                if manuscript_id:
                    cursor.execute("SELECT manuscript_id FROM manuscripts WHERE manuscript_id = ?", (manuscript_id,))
                    manuscript = cursor.fetchone()
                    
                    if not manuscript:
                        return jsonify({"error": "Manuscript not found"}), 404

                # Save translation
                if manuscript_id:
                    cursor.execute("""
                        INSERT INTO translations (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method))
                else:
                    cursor.execute("""
                        INSERT INTO translations (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method)
                        VALUES (NULL, ?, ?, ?, ?, ?, ?)
                    """, (translator_id, translation_title, translated_text, language, target_language, method))
                
                conn.commit()
                translation_id = cursor.lastrowid
                
                app.logger.info(f"Translation saved successfully with ID: {translation_id}")
                
                return jsonify({
                    "message": "✅ Translation saved successfully!",
                    "translation_id": translation_id
                })
                
        except Exception as e:
            app.logger.error(f"Translation save error: {e}")
            return jsonify({"error": f"Failed to save translation: {str(e)}"}), 500

    except Exception as e:
        app.logger.exception("Save translation endpoint error")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/translations', methods=['GET'])
def get_translations():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT tr.translation_id, tr.translation_title, tr.manuscript_id,
                       COALESCE(m.title,'') AS manuscript_title,
                       COALESCE(m.author,'') AS manuscript_author,
                       tr.translator_id,
                       COALESCE(u.username,'') AS translator_name,
                       COALESCE(u.full_name,'') AS translator_full_name,
                       tr.language, tr.target_language, tr.translated_text, 
                       tr.method, tr.status, tr.created_at, tr.updated_at
                FROM translations tr
                LEFT JOIN manuscripts m ON tr.manuscript_id = m.manuscript_id
                LEFT JOIN users u ON tr.translator_id = u.user_id
                ORDER BY tr.created_at DESC
            """)
            rows = cursor.fetchall()
            translations = []
            for row in rows:
                translation = dict(row)
                for k, v in translation.items():
                    if isinstance(v, (datetime.date, datetime.datetime)):
                        translation[k] = v.isoformat()
                translations.append(translation)
            return jsonify(translations)
    except Exception as e:
        app.logger.error(f"Get translations error: {e}")
        return jsonify({"error": "Failed to load translations"}), 500

# ------------------ NLP Translation Endpoints ------------------
@app.route('/api/translate/advanced', methods=['POST'])
@translator_required
def advanced_translate():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "No JSON data received"
            }), 400
            
        text = data.get('text', '').strip()
        target_language = data.get('target_language', 'en')
        source_language = data.get('source_language', 'auto')
        
        app.logger.info(f"Translation request - Source: {source_language}, Target: {target_language}, Text length: {len(text)}")
        
        if not text:
            return jsonify({
                "success": False,
                "error": "No text provided for translation"
            }), 400
        
        if len(text) > 50000:
            return jsonify({
                "success": False,
                "error": "Text too long. Maximum 50,000 characters allowed."
            }), 400
        
        result = translation_service.translate_manuscript(text, target_language, source_language)
        
        app.logger.info(f"Translation result - Success: {result['success']}, Method: {result.get('method', 'Unknown')}")
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logging.error(f"Advanced translation endpoint error: {e}")
        return jsonify({
            "success": False,
            "error": f"Translation service error: {str(e)}",
            "translated_text": data.get('text', '') if 'data' in locals() else '',
            "fallback_used": True
        }), 500

@app.route('/api/languages/detailed', methods=['GET'])
def get_detailed_languages():
    try:
        languages_list = []
        for code, name in translation_service.supported_languages.items():
            languages_list.append({
                'code': code,
                'name': name.title(),
                'supported': True
            })
        
        languages_list.sort(key=lambda x: x['name'])
        
        return jsonify({
            'success': True,
            'languages': languages_list,
            'total_languages': len(languages_list)
        })
    except Exception as e:
        app.logger.error(f"Error getting languages: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to load languages: {str(e)}'
        }), 500

# ------------------ Debug Routes ------------------
@app.route('/debug/files', methods=['GET'])
@admin_required
def debug_files():
    """Debug endpoint to check file URLs and accessibility"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT manuscript_id, title, file_url FROM manuscripts")
            manuscripts = cursor.fetchall()
            
            file_info = []
            for ms in manuscripts:
                file_url = ms['file_url']
                accessible = False
                error = ""
                file_type = ""
                
                if file_url:
                    if file_url.startswith('http'):
                        # Azure URL
                        file_type = "Azure Blob"
                        try:
                            response = requests.head(file_url, timeout=10)
                            accessible = response.status_code == 200
                            if not accessible:
                                error = f"HTTP {response.status_code}"
                        except Exception as e:
                            error = str(e)
                    elif file_url.startswith('/uploads/'):
                        # Local file
                        file_type = "Local File"
                        filename = file_url.split('/')[-1]
                        uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
                        file_path = os.path.join(uploads_dir, filename)
                        accessible = os.path.exists(file_path)
                        if not accessible:
                            error = "File not found locally (not persistent on Render)"
                    else:
                        file_type = "Unknown"
                        error = "Invalid URL format"
                
                file_info.append({
                    'id': ms['manuscript_id'],
                    'title': ms['title'],
                    'url': file_url,
                    'type': file_type,
                    'accessible': accessible,
                    'error': error
                })
            
            return jsonify({"files": file_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ Check Auth Status ------------------
@app.route('/check-auth', methods=['GET'])
def check_auth():
    app.logger.info(f"Checking auth, session: {dict(session)}")
    if 'user_id' in session:
        app.logger.info(f"User {session.get('username')} is authenticated")
        return jsonify({
            "authenticated": True,
            "user": {
                "user_id": session.get('user_id'),
                "username": session.get('username'),
                "full_name": session.get('full_name'),
                "role": session.get('role')
            }
        })
    else:
        app.logger.info("No user in session, not authenticated")
        return jsonify({"authenticated": False})

# ------------------ Health Check ------------------
@app.route('/health', methods=['GET'])
def health_check():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
        
        test_result = translation_service.translate_manuscript("Hello", "es", "en")
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "translation_service": "available" if test_result['success'] else "degraded",
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

# ------------------ Main ------------------
if __name__ == '__main__':
    uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
