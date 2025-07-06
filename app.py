# app.py
from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
import time
import json
import sqlite3
from datetime import datetime
import yara

# Custom utility imports
from utils.analyzer import analyze_pdf
from models.user_model import User

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', static_url_path='/')

# Configuration
app.config['UPLOAD_FOLDER'] = '../uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_for_development')
app.config['DATABASE'] = 'database.db'
app.config['YARA_RULES_PATH'] = 'yara_rules'

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Database setup
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("Database initialized successfully")

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Compile YARA rules
def compile_yara_rules():
    try:
        rules_path = app.config['YARA_RULES_PATH']
        rules_files = {}
        
        # Look for all .yar files in the rules directory
        for filename in os.listdir(rules_path):
            if filename.endswith('.yar'):
                rule_name = os.path.splitext(filename)[0]
                rule_path = os.path.join(rules_path, filename)
                rules_files[rule_name] = rule_path
        
        # Compile rules
        compiled_rules = yara.compile(filepaths=rules_files)
        return compiled_rules
    except Exception as e:
        app.logger.error(f"Error compiling YARA rules: {str(e)}")
        return None

# Log scan activity
def log_scan(user_id, filename, result, method):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'user_id': user_id,
        'filename': filename,
        'result': result,
        'method': method
    }
    
    log_path = os.path.join('logs', 'scan_log.json')
    
    # Read existing logs or create new log file
    try:
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
            
        logs.append(log_entry)
        
        with open(log_path, 'w') as f:
            json.dump(logs, f, indent=2)
            
    except Exception as e:
        app.logger.error(f"Error logging scan: {str(e)}")

# Routes
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    # Check if user is logged in
    user_id = session.get('user_id', None)
    
    # Check if file is present in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    
    # Check if file is selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    # Check if file type is allowed
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Only PDF files are accepted.'}), 400
    
    # Get analysis method
    method = request.form.get('method', 'yara')
    
    try:
        # Save file with secure filename
        filename = secure_filename(file.filename)
        # Add timestamp to filename to avoid conflicts
        unique_filename = f"{int(time.time())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Perform analysis based on method
        if method == 'yara':
            # Get compiled YARA rules
            rules = compile_yara_rules()
            if not rules:
                # app.py (continuing from where it left off)
            if not rules:
                return jsonify({'error': 'Failed to compile YARA rules'}), 500
                
            # Run YARA scan
            matches = rules.match(file_path)
            
            # Process results
            if matches:
                result = {
                    'status': 'suspicious',
                    'matches': [match.rule for match in matches],
                    'details': 'File matched YARA signatures indicating potential malicious content'
                }
            else:
                result = {
                    'status': 'clean',
                    'matches': [],
                    'details': 'No malicious signatures detected'
                }
                
        elif method == 'ai':
            # Use custom PDF analyzer
            result = analyze_pdf(file_path)
        else:
            return jsonify({'error': 'Invalid analysis method'}), 400
            
        # Log the scan
        log_scan(user_id or 'anonymous', filename, result['status'], method)
        
        return jsonify({
            'filename': filename,
            'status': result['status'],
            'details': result.get('details', ''),
            'matches': result.get('matches', []),
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'method': method
        })
        
    except Exception as e:
        app.logger.error(f"Error analyzing file: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up - remove uploaded file after analysis
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            app.logger.error(f"Error removing temporary file: {str(e)}")

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
        
    try:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', 
                           (data['username'],)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], data['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                }
            })
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
            
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        conn = get_db_connection()
        
        # Check if username already exists
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', 
                                   (data['username'],)).fetchone()
        if existing_user:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 409
            
        # Check if email already exists
        existing_email = conn.execute('SELECT * FROM users WHERE email = ?', 
                                    (data['email'],)).fetchone()
        if existing_email:
            conn.close()
            return jsonify({'error': 'Email already in use'}), 409
            
        # Create new user
        hashed_password = generate_password_hash(data['password'])
        conn.execute('INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)',
                   (data['username'], hashed_password, data['email'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        
        # Get the newly created user
        user = conn.execute('SELECT * FROM users WHERE username = ?', 
                          (data['username'],)).fetchone()
        conn.close()
        
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        })
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({'success': True})

@app.route('/api/user/scans', methods=['GET'])
def get_user_scans():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 401
        
    try:
        log_path = os.path.join('logs', 'scan_log.json')
        if not os.path.exists(log_path):
            return jsonify({'scans': []})
            
        with open(log_path, 'r') as f:
            logs = json.load(f)
            
        # Filter logs for current user
        user_logs = [log for log in logs if log['user_id'] == user_id]
        
        return jsonify({'scans': user_logs})
        
    except Exception as e:
        app.logger.error(f"Error getting user scans: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scan history'}), 500

@app.route('/api/profile', methods=['GET'])
def get_profile():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 401
        
    try:
        conn = get_db_connection()
        user = conn.execute('SELECT id, username, email, created_at FROM users WHERE id = ?', 
                          (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'created_at': user['created_at']
        })
        
    except Exception as e:
        app.logger.error(f"Error getting profile: {str(e)}")
        return jsonify({'error': 'Failed to retrieve profile'}), 500

@app.route('/api/upload_test', methods=['POST'])
def test_upload():
    # Simplified upload function for testing
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Only PDF files are accepted.'}), 400
    
    return jsonify({'success': True, 'message': 'File validation successful'})

# Initialize database if not exists
@app.before_first_request
def setup():
    if not os.path.exists(app.config['DATABASE']):
        init_db()

# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
