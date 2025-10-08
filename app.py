import os
import datetime
import logging
import mimetypes
import hashlib
import json
from urllib.parse import urlparse, unquote
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, make_response, Response, session, redirect, url_for
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error

# Azure imports
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

# NLP Translation imports
from googletrans import Translator, LANGUAGES

# ---- Logging / Flask ----
logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.secret_key = 'manuscript-secret-key-2024'  # Important for sessions

# FIXED: Enhanced session configuration
app.config.update(
    SESSION_COOKIE_NAME='manuscript_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
    SESSION_REFRESH_EACH_REQUEST=True
)

app.logger.setLevel(logging.DEBUG)

# ---- Config ----
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Raaghavi@2005")
DB_NAME = os.getenv("DB_NAME", "manuscript_db")

# Azure Configuration
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING", "DefaultEndpointsProtocol=https;AccountName=raaghavi01;AccountKey=FGDUXkYF0N9ScIhaYr9xCNZ658wyX1GrspaISBhFprJIPbwo+KUUxqSUWq6E/WdXDGyc9Fj6zjmJ+AStFyp01g==;EndpointSuffix=core.windows.net")
CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME", "manuscripts")

# Upload config
ALLOWED_EXT = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}
MAX_UPLOAD_SIZE = 30 * 1024 * 1024

# ---- DB helper ----
def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

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
            self.translator = Translator()
            self.supported_languages = LANGUAGES  # 100+ languages
            # Extended language mapping for better compatibility
            self.language_mapping = {
                'zh-cn': 'zh-CN',
                'zh-tw': 'zh-TW',
                'sa': 'sa',  # Sanskrit
                'grc': 'el',  # Ancient Greek maps to modern Greek
                'la': 'la'   # Latin
            }
            # Test the translator
            test_result = self.translator.translate('hello', dest='es')
            app.logger.info("Google Translate service initialized successfully")
        except Exception as e:
            app.logger.warning(f"Google Translate initialization failed: {e}")
            self.translator = None
            self.supported_languages = {
                'en': 'English',
                'es': 'Spanish', 
                'fr': 'French',
                'de': 'German',
                'it': 'Italian',
                'pt': 'Portuguese',
                'ru': 'Russian',
                'zh-cn': 'Chinese',
                'ja': 'Japanese',
                'ar': 'Arabic',
                'hi': 'Hindi',
                'la': 'Latin',
                'sa': 'Sanskrit',
                'grc': 'Ancient Greek'
            }
    
    def map_language_code(self, code):
        """Map custom language codes to Google Translate codes"""
        return self.language_mapping.get(code, code)
    
    def translate_manuscript(self, text, target_lang='en', source_lang='auto'):
        """Enhanced translation with better error handling and fallback"""
        try:
            # Input validation
            if not text or not text.strip():
                return {
                    'success': False,
                    'error': 'No text provided for translation',
                    'translated_text': '',
                    'method': 'Google Translate'
                }
            
            # Clean and prepare text
            text = text.strip()
            
            # Check if translator is available
            if self.translator is None:
                return {
                    'success': False,
                    'error': 'Translation service temporarily unavailable',
                    'translated_text': text,
                    'method': 'Fallback',
                    'fallback_used': True
                }
            
            # Map language codes
            mapped_target = self.map_language_code(target_lang)
            mapped_source = self.map_language_code(source_lang) if source_lang != 'auto' else 'auto'
            
            # Check if target language is supported
            if mapped_target not in self.supported_languages and mapped_target not in ['sa', 'grc', 'la']:
                app.logger.warning(f"Target language {target_lang} (mapped: {mapped_target}) may not be fully supported")
            
            # Handle large texts by splitting (Google Translate has 15k char limit)
            if len(text) > 15000:
                return self._translate_large_text(text, mapped_target, mapped_source)
            
            # Perform translation with timeout handling
            translated = self.translator.translate(text, dest=mapped_target, src=mapped_source)
            
            return {
                'success': True,
                'translated_text': translated.text,
                'source_language': source_lang,
                'source_language_name': self.supported_languages.get(source_lang, 'Unknown'),
                'target_language': target_lang,
                'target_language_name': self.supported_languages.get(target_lang, 'Unknown'),
                'confidence': 'high',
                'method': 'Google Translate',
                'characters_translated': len(text),
                'mapped_source': mapped_source,
                'mapped_target': mapped_target
            }
            
        except Exception as e:
            logging.error(f"Translation error: {str(e)}")
            # Fallback: Return original text with error message
            return {
                'success': False,
                'error': f'Translation service error: {str(e)}',
                'translated_text': text,  # Return original text as fallback
                'method': 'Google Translate',
                'fallback_used': True
            }
    
    def _translate_large_text(self, text, target_lang, source_lang):
        """Split large text into chunks and translate separately"""
        try:
            chunks = self._split_text_into_chunks(text)
            translated_chunks = []
            
            for i, chunk in enumerate(chunks):
                try:
                    result = self.translator.translate(chunk, dest=target_lang, src=source_lang)
                    translated_chunks.append(result.text)
                    logging.info(f"Translated chunk {i+1}/{len(chunks)}")
                except Exception as e:
                    logging.error(f"Chunk translation error: {str(e)}")
                    translated_chunks.append(chunk)  # Keep original on error
            
            return {
                'success': True,
                'translated_text': ' '.join(translated_chunks),
                'source_language': source_lang if source_lang != 'auto' else 'detected',
                'target_language': target_lang,
                'confidence': 'medium',  # Lower confidence for chunked translation
                'method': 'Google Translate (Chunked)',
                'note': f'Text was split into {len(chunks)} chunks for translation',
                'characters_translated': len(text)
            }
        except Exception as e:
            logging.error(f"Large text translation error: {str(e)}")
            return {
                'success': False,
                'error': f'Large text translation failed: {str(e)}',
                'translated_text': text,
                'method': 'Google Translate',
                'fallback_used': True
            }
    
    def _split_text_into_chunks(self, text, max_chunk_size=5000):
        """Split text into sensible chunks (reduced size for better reliability)"""
        # Split by sentences first
        sentences = text.split('. ')
        chunks = []
        current_chunk = ""
        
        for sentence in sentences:
            # If adding this sentence would exceed chunk size, save current chunk and start new one
            if len(current_chunk) + len(sentence) >= max_chunk_size and current_chunk:
                chunks.append(current_chunk.strip() + '.')
                current_chunk = sentence + '. '
            else:
                current_chunk += sentence + '. '
        
        # Add the last chunk if it's not empty
        if current_chunk.strip():
            chunks.append(current_chunk.strip())
        
        # If no chunks were created (text is one long sentence), split by words
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
        """Enhanced language detection with better error handling"""
        try:
            if not text or len(text.strip()) < 3:
                return {
                    'success': False,
                    'error': 'Text too short for language detection',
                    'language_code': 'unknown',
                    'language_name': 'Unknown'
                }
            
            # Clean the text for detection
            clean_text = text.strip()
            if len(clean_text) < 3:
                return {
                    'success': False,
                    'error': 'Text too short for language detection',
                    'language_code': 'unknown',
                    'language_name': 'Unknown'
                }
            
            # Check if translator is available
            if self.translator is None:
                return {
                    'success': False,
                    'error': 'Language detection service unavailable',
                    'language_code': 'unknown',
                    'language_name': 'Unknown'
                }
            
            detected = self.translator.detect(clean_text)
            
            # Handle None confidence values safely
            confidence = getattr(detected, 'confidence', 0.5)
            if confidence is None:
                confidence = 0.5
                
            # Map detected language back to our codes if needed
            detected_code = detected.lang
            for our_code, gt_code in self.language_mapping.items():
                if gt_code == detected_code:
                    detected_code = our_code
                    break
                
            return {
                'success': True,
                'language_code': detected_code,
                'language_name': self.supported_languages.get(detected_code, 'Unknown'),
                'confidence': confidence,
                'reliable': confidence > 0.5
            }
        except Exception as e:
            logging.error(f"Language detection error: {str(e)}")
            return {
                'success': False,
                'error': f'Language detection failed: {str(e)}',
                'language_code': 'unknown',
                'language_name': 'Unknown'
            }
    
    def get_language_name(self, code):
        """Get human-readable language name"""
        return self.supported_languages.get(code, 'Unknown')

# Initialize the advanced service
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

        # Validate role
        valid_roles = ['Admin', 'Translator', 'Researcher']
        if role not in valid_roles:
            return jsonify({"error": "Invalid role selected"}), 400

        password_hash = hash_password(password)

        conn = cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, password_hash, full_name, role))
            conn.commit()
            
            return jsonify({"message": "User registered successfully"})
        except mysql.connector.IntegrityError as e:
            if "username" in str(e).lower():
                return jsonify({"error": "Username already exists"}), 400
            elif "email" in str(e).lower():
                return jsonify({"error": "Email already exists"}), 400
            else:
                return jsonify({"error": "User already exists"}), 400
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            return jsonify({"error": "Registration failed: " + str(e)}), 500
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
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

        conn = cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT user_id, username, email, full_name, role, password_hash 
                FROM users WHERE username = %s
            """, (username,))
            
            user = cursor.fetchone()
            
            if user and user['password_hash'] == password_hash:
                cursor.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user['user_id'],))
                conn.commit()
                
                # FIXED: Set session as permanent and add user info
                session.permanent = True
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['full_name'] = user['full_name']
                
                app.logger.info(f"User {username} logged in successfully, session: {dict(session)}")
                
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
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
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
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
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
        rows = cursor.fetchall() or []
        for r in rows:
            for k, v in list(r.items()):
                if isinstance(v, (datetime.date, datetime.datetime)):
                    r[k] = v.isoformat()
        return jsonify(rows)
    except Error as e:
        app.logger.exception("DB error in get_manuscripts")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ API: Upload Manuscript ------------------
@app.route('/upload', methods=['POST'])
@admin_required
def upload_manuscript():
    try:
        title = request.form.get('title')
        author = request.form.get('author')
        topic_id = request.form.get('topic_id')
        location_id = request.form.get('location_id') or None  # Handle empty location
        uploaded_by = session.get('user_id')
        file = request.files.get('file')

        app.logger.info(f"Upload request - Title: {title}, Author: {author}, Topic: {topic_id}, Location: {location_id}")

        if not (title and author and topic_id and file):
            return jsonify({"error": "Missing required fields: title, author, topic, and file are required"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": f"File type not allowed. Supported types: {', '.join(ALLOWED_EXT)}"}), 400

        # Generate unique filename to avoid conflicts
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

        # Local fallback
        if not file_url:
            uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
            os.makedirs(uploads_dir, exist_ok=True)
            local_path = os.path.join(uploads_dir, filename)
            file.stream.seek(0)
            file.save(local_path)
            file_url = f"/uploads/{filename}"
            app.logger.info("Saved locally at %s", local_path)

        # Save metadata
        conn = cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO manuscripts (title, author, topic_id, location_id, file_url, uploaded_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (title, author, topic_id, location_id, file_url, uploaded_by))
            conn.commit()
            
            # Get the inserted manuscript ID
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
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    except Exception as e:
        app.logger.exception("Upload manuscript error")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

# ------------------ Topics & Locations ------------------
@app.route('/topics', methods=['GET'])
def get_topics():
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM topics ORDER BY topic_name")
        return jsonify(cursor.fetchall() or [])
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/locations', methods=['GET'])
def get_locations():
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM locations ORDER BY location_name")
        return jsonify(cursor.fetchall() or [])
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ FIXED: Save/Get Translations ------------------
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

        # Validate required fields
        if not translation_title or not translation_title.strip():
            return jsonify({"error": "Translation title is required"}), 400
        if not translated_text or not translated_text.strip():
            return jsonify({"error": "Translation text is required"}), 400

        # Handle NULL manuscript_id for AI translations
        if manuscript_id == "" or manuscript_id == "null" or manuscript_id is None:
            manuscript_id = None
        else:
            try:
                manuscript_id = int(manuscript_id)
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid manuscript ID"}), 400

        # Validate manuscript exists if provided
        conn = cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # If manuscript_id is provided, validate it exists
            if manuscript_id:
                cursor.execute("SELECT manuscript_id FROM manuscripts WHERE manuscript_id = %s", (manuscript_id,))
                manuscript = cursor.fetchone()
                
                if not manuscript:
                    return jsonify({"error": "Manuscript not found"}), 404

            # FIXED: Save translation with proper method handling
            # Ensure method is one of the allowed ENUM values
            valid_methods = ['Manual', 'NLP']
            if method not in valid_methods:
                method = 'Manual'  # Default to Manual if invalid
            
            # FIXED: Use proper SQL with NULL handling for manuscript_id
            if manuscript_id:
                cursor.execute("""
                    INSERT INTO translations (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method))
            else:
                cursor.execute("""
                    INSERT INTO translations (manuscript_id, translator_id, translation_title, translated_text, language, target_language, method)
                    VALUES (NULL, %s, %s, %s, %s, %s, %s)
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
            conn.rollback()
            return jsonify({"error": f"Failed to save translation: {str(e)}"}), 500
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    except Exception as e:
        app.logger.exception("Save translation endpoint error")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/translations', methods=['GET'])
def get_translations():
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
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
        rows = cursor.fetchall() or []
        for r in rows:
            for k, v in list(r.items()):
                if isinstance(v, (datetime.date, datetime.datetime)):
                    r[k] = v.isoformat()
        return jsonify(rows)
    except Exception as e:
        app.logger.error(f"Get translations error: {e}")
        return jsonify({"error": "Failed to load translations"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/translations/<int:translation_id>', methods=['GET'])
def get_translation(translation_id):
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT tr.*, m.title as manuscript_title, m.author as manuscript_author,
                   u.username as translator_name, u.full_name as translator_full_name
            FROM translations tr
            LEFT JOIN manuscripts m ON tr.manuscript_id = m.manuscript_id
            LEFT JOIN users u ON tr.translator_id = u.user_id
            WHERE tr.translation_id = %s
        """, (translation_id,))
        translation = cursor.fetchone()
        
        if not translation:
            return jsonify({"error": "Translation not found"}), 404
            
        for k, v in list(translation.items()):
            if isinstance(v, (datetime.date, datetime.datetime)):
                translation[k] = v.isoformat()
                
        return jsonify(translation)
    except Exception as e:
        app.logger.error(f"Get translation error: {e}")
        return jsonify({"error": "Failed to load translation"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/translations/<int:translation_id>/download', methods=['GET'])
def download_translation(translation_id):
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT tr.translation_title, tr.translated_text, m.title as manuscript_title
            FROM translations tr
            LEFT JOIN manuscripts m ON tr.manuscript_id = m.manuscript_id
            WHERE tr.translation_id = %s
        """, (translation_id,))
        translation = cursor.fetchone()
        
        if not translation:
            return jsonify({"error": "Translation not found"}), 404
            
        # Create downloadable text file
        content = f"Translation: {translation['translation_title']}\n"
        content += f"Original Manuscript: {translation['manuscript_title']}\n"
        content += f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += "="*50 + "\n\n"
        content += translation['translated_text']
        
        response = Response(content, mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename(translation["translation_title"])}.txt"'
        return response
        
    except Exception as e:
        app.logger.error(f"Download translation error: {e}")
        return jsonify({"error": "Failed to download translation"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ NLP Translation Endpoints ------------------
@app.route('/api/translate/advanced', methods=['POST'])
@translator_required
def advanced_translate():
    """Enhanced translation endpoint with better error handling"""
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
        
        # Perform translation
        result = translation_service.translate_manuscript(
            text, target_language, source_language
        )
        
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
            "translated_text": data.get('text', '') if 'data' in locals() else '',  # Return original text as fallback
            "fallback_used": True
        }), 500

@app.route('/api/languages/detailed', methods=['GET'])
def get_detailed_languages():
    """Get detailed language information"""
    try:
        # Extended language list with better support
        extended_languages = {
            'en': 'English',
            'es': 'Spanish', 
            'fr': 'French',
            'de': 'German',
            'it': 'Italian',
            'pt': 'Portuguese',
            'ru': 'Russian',
            'zh-cn': 'Chinese (Simplified)',
            'ja': 'Japanese',
            'ko': 'Korean',
            'ar': 'Arabic',
            'hi': 'Hindi',
            'bn': 'Bengali',
            'pa': 'Punjabi',
            'ta': 'Tamil',
            'te': 'Telugu',
            'mr': 'Marathi',
            'gu': 'Gujarati',
            'kn': 'Kannada',
            'ml': 'Malayalam',
            'or': 'Odia',
            'sa': 'Sanskrit',
            'la': 'Latin',
            'grc': 'Ancient Greek',
            'el': 'Greek',
            'he': 'Hebrew',
            'tr': 'Turkish',
            'nl': 'Dutch',
            'pl': 'Polish',
            'uk': 'Ukrainian',
            'vi': 'Vietnamese',
            'th': 'Thai'
        }
        
        languages = []
        for code, name in extended_languages.items():
            languages.append({
                'code': code,
                'name': name,
                'supported': True
            })
        
        # Sort by name
        languages.sort(key=lambda x: x['name'])
        
        return jsonify({
            'success': True,
            'languages': languages,
            'total_languages': len(languages)
        })
    except Exception as e:
        app.logger.error(f"Error getting languages: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to load languages: {str(e)}'
        }), 500

@app.route('/api/translate/detect', methods=['POST'])
def detect_language():
    """Detect language of given text"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        text = data.get('text', '')
        
        if not text:
            return jsonify({"error": "No text provided"}), 400
        
        detected = translation_service.detect_language_advanced(text)
        
        return jsonify(detected)
        
    except Exception as e:
        app.logger.error(f"Language detection error: {e}")
        return jsonify({
            "success": False,
            "error": f"Language detection failed: {str(e)}"
        }), 500

# ------------------ FIXED: PDF Preview Endpoint ------------------
@app.route('/preview/<int:manuscript_id>', methods=['GET'])
def preview_manuscript(manuscript_id):
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT file_url, title FROM manuscripts WHERE manuscript_id = %s", (manuscript_id,))
        manuscript = cursor.fetchone()
        
        if not manuscript or not manuscript['file_url']:
            return jsonify({"error": "Manuscript not found"}), 404
        
        file_url = manuscript['file_url']
        
        # Handle Azure URLs
        if file_url.startswith('http'):
            blob_name = extract_blob_name_from_url(file_url)
            if blob_name and blob_service_client:
                try:
                    blob_client = blob_service_client.get_blob_client(CONTAINER_NAME, blob_name)
                    blob_data = blob_client.download_blob().readall()
                    
                    mimetype = get_file_mimetype(blob_name)
                    
                    # FIXED: Set proper headers for inline viewing
                    response = Response(blob_data, mimetype=mimetype)
                    
                    # For PDFs and images, use inline; for others, use attachment
                    if mimetype in ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg']:
                        response.headers['Content-Disposition'] = f'inline; filename="{secure_filename(manuscript["title"])}"'
                    else:
                        # For non-viewable files, fallback to download
                        response.headers['Content-Disposition'] = f'attachment; filename="{secure_filename(manuscript["title"])}"'
                    
                    response.headers['X-Content-Type-Options'] = 'nosniff'
                    return response
                except Exception as e:
                    app.logger.error(f"Azure blob error: {e}")
                    return jsonify({"error": "Failed to load file from Azure"}), 500
        
        # Handle local files
        elif file_url.startswith('/uploads/'):
            filename = file_url.split('/')[-1]
            uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
            file_path = os.path.join(uploads_dir, filename)
            
            if os.path.exists(file_path):
                mimetype = get_file_mimetype(filename)
                
                # FIXED: For local files, use send_from_directory with conditional attachment
                if mimetype in ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg', 'text/plain']:
                    # For viewable files, send as inline
                    response = send_from_directory(uploads_dir, filename, mimetype=mimetype)
                    response.headers['Content-Disposition'] = f'inline; filename="{secure_filename(manuscript["title"])}"'
                    return response
                else:
                    # For non-viewable files, send as attachment
                    return send_from_directory(uploads_dir, filename, as_attachment=True, 
                                             download_name=secure_filename(manuscript["title"]))
            else:
                return jsonify({"error": "File not found locally"}), 404
        
        return jsonify({"error": "Invalid file URL"}), 400
        
    except Exception as e:
        app.logger.exception("Error in preview_manuscript")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ FIXED: Download Manuscript ------------------
@app.route('/download/<int:manuscript_id>', methods=['GET'])
def download_manuscript(manuscript_id):
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT file_url, title FROM manuscripts WHERE manuscript_id = %s", (manuscript_id,))
        manuscript = cursor.fetchone()
        
        if not manuscript or not manuscript['file_url']:
            return jsonify({"error": "Manuscript not found"}), 404
        
        file_url = manuscript['file_url']
        title = manuscript['title']
        
        # Handle Azure URLs
        if file_url.startswith('http'):
            blob_name = extract_blob_name_from_url(file_url)
            if blob_name and blob_service_client:
                try:
                    blob_client = blob_service_client.get_blob_client(CONTAINER_NAME, blob_name)
                    blob_data = blob_client.download_blob().readall()
                    
                    file_ext = os.path.splitext(blob_name)[1] or '.pdf'
                    filename = f"{secure_filename(title)}{file_ext}"
                    mimetype = get_file_mimetype(blob_name)
                    
                    response = Response(blob_data, mimetype=mimetype)
                    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
                    return response
                except Exception as e:
                    app.logger.error(f"Azure blob download error: {e}")
                    return jsonify({"error": "Failed to download from Azure"}), 500
        
        # Handle local files
        elif file_url.startswith('/uploads/'):
            filename = file_url.split('/')[-1]
            uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
            file_path = os.path.join(uploads_dir, filename)
            
            if os.path.exists(file_path):
                safe_title = secure_filename(title)
                file_ext = os.path.splitext(filename)[1] or '.pdf'
                download_name = f"{safe_title}{file_ext}"
                
                return send_from_directory(
                    uploads_dir, 
                    filename, 
                    as_attachment=True, 
                    download_name=download_name
                )
        
        return jsonify({"error": "File not found for download"}), 404
        
    except Exception as e:
        app.logger.exception("Error in download_manuscript")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ FIXED: Check Auth Status ------------------
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

# ------------------ Statistics ------------------
@app.route('/stats', methods=['GET'])
def get_statistics():
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Total manuscripts
        cursor.execute("SELECT COUNT(*) as total FROM manuscripts")
        total_manuscripts = cursor.fetchone()['total']
        
        # Total translations
        cursor.execute("SELECT COUNT(*) as total FROM translations")
        total_translations = cursor.fetchone()['total']
        
        # Unique authors
        cursor.execute("SELECT COUNT(DISTINCT author) as total FROM manuscripts WHERE author IS NOT NULL AND author != ''")
        unique_authors = cursor.fetchone()['total']
        
        # Recent uploads (this month)
        cursor.execute("SELECT COUNT(*) as total FROM manuscripts WHERE MONTH(upload_date) = MONTH(CURRENT_DATE()) AND YEAR(upload_date) = YEAR(CURRENT_DATE())")
        recent_uploads = cursor.fetchone()['total']
        
        return jsonify({
            "total_manuscripts": total_manuscripts,
            "total_translations": total_translations,
            "unique_authors": unique_authors,
            "recent_uploads": recent_uploads
        })
        
    except Exception as e:
        app.logger.error(f"Statistics error: {e}")
        return jsonify({"error": "Failed to load statistics"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ------------------ Health Check ------------------
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        conn = get_db_connection()
        conn.close()
        
        # Test translation service
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