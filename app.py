from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import sqlite3
import hashlib
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'skillswap_secret_key_2024'
CORS(app)

# JWT Configuration
JWT_SECRET = 'skillswap_jwt_secret'
JWT_ALGORITHM = 'HS256'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        credits INTEGER DEFAULT 20,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Skills table
    c.execute('''CREATE TABLE IF NOT EXISTS skills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        credits_required INTEGER NOT NULL,
        teacher_id INTEGER NOT NULL,
        meeting_link TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (teacher_id) REFERENCES users (id)
    )''')
    
    # Enrollments table
    c.execute('''CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        skill_id INTEGER NOT NULL,
        learner_id INTEGER NOT NULL,
        status TEXT DEFAULT 'enrolled',
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (skill_id) REFERENCES skills (id),
        FOREIGN KEY (learner_id) REFERENCES users (id)
    )''')
    
    # Check if meeting_link column exists, if not add it
    try:
        c.execute('SELECT meeting_link FROM skills LIMIT 1')
    except sqlite3.OperationalError:
        # Column doesn't exist, add it
        c.execute('ALTER TABLE skills ADD COLUMN meeting_link TEXT')
        print("Added meeting_link column to skills table")
    
    # Check if class_timing column exists, if not add it
    try:
        c.execute('SELECT class_timing FROM skills LIMIT 1')
    except sqlite3.OperationalError:
        # Column doesn't exist, add it
        c.execute('ALTER TABLE skills ADD COLUMN class_timing TEXT')
        print("Added class_timing column to skills table")
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user_id, username, role):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = {
                'id': data['user_id'],
                'username': data['username'],
                'role': data['role']
            }
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/skills')
def skills_page():
    return render_template('skills.html')

@app.route('/add-skill')
def add_skill_page():
    return render_template('add_skill.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    # Check if user already exists
    c.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
              (data['username'], data['email']))
    if c.fetchone():
        conn.close()
        return jsonify({'message': 'User already exists'}), 400
    
    # Create new user
    hashed_password = hash_password(data['password'])
    c.execute('INSERT INTO users (username, email, password, credits) VALUES (?, ?, ?, ?)',
              (data['username'], data['email'], hashed_password, 20))
    
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Generate token
    token = generate_token(user_id, data['username'], 'user')
    
    return jsonify({
        'message': 'User registered successfully',
        'token': token,
        'user': {
            'id': user_id,
            'username': data['username'],
            'role': 'user',
            'credits': 20
        }
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
    
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    hashed_password = hash_password(data['password'])
    c.execute('SELECT id, username, role, credits FROM users WHERE username = ? AND password = ?',
              (data['username'], hashed_password))
    
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = generate_token(user[0], user[1], user[2])
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'credits': user[3]
        }
    })

@app.route('/api/skills', methods=['GET'])
def get_skills():
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    c.execute('''SELECT s.id, s.title, s.description, s.category, s.difficulty, 
                        s.credits_required, u.username as teacher_name, COALESCE(s.meeting_link, ""), COALESCE(s.class_timing, "")
                 FROM skills s 
                 JOIN users u ON s.teacher_id = u.id''')
    
    skills = []
    for row in c.fetchall():
        skills.append({
            'id': row[0],
            'title': row[1],
            'description': row[2],
            'category': row[3],
            'difficulty': row[4],
            'credits_required': row[5],
            'teacher_name': row[6],
            'meeting_link': row[7],
            'class_timing': row[8]
        })
    
    conn.close()
    return jsonify(skills)

@app.route('/api/skills', methods=['POST'])
@token_required
def add_skill(current_user):
    data = request.get_json()
    
    required_fields = ['title', 'description', 'category', 'difficulty', 'credits_required']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO skills (title, description, category, difficulty, credits_required, teacher_id, meeting_link, class_timing)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (data['title'], data['description'], data['category'], 
               data['difficulty'], int(data['credits_required']), current_user['id'], 
               data.get('meeting_link', ''), data.get('class_timing', '')))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Skill added successfully'}), 201

@app.route('/api/skills/<int:skill_id>', methods=['PUT'])
@token_required
def update_skill(current_user, skill_id):
    data = request.get_json()
    
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    # Check if the skill belongs to the current user
    c.execute('SELECT teacher_id FROM skills WHERE id = ?', (skill_id,))
    skill = c.fetchone()
    
    if not skill:
        conn.close()
        return jsonify({'message': 'Skill not found'}), 404
    
    if skill[0] != current_user['id']:
        conn.close()
        return jsonify({'message': 'Unauthorized to update this skill'}), 403
    
    # Update the skill
    update_fields = []
    values = []
    
    if 'title' in data:
        update_fields.append('title = ?')
        values.append(data['title'])
    if 'description' in data:
        update_fields.append('description = ?')
        values.append(data['description'])
    if 'category' in data:
        update_fields.append('category = ?')
        values.append(data['category'])
    if 'difficulty' in data:
        update_fields.append('difficulty = ?')
        values.append(data['difficulty'])
    if 'credits_required' in data:
        update_fields.append('credits_required = ?')
        values.append(int(data['credits_required']))
    if 'meeting_link' in data:
        update_fields.append('meeting_link = ?')
        values.append(data['meeting_link'])
    if 'class_timing' in data:
        update_fields.append('class_timing = ?')
        values.append(data['class_timing'])
    
    if not update_fields:
        conn.close()
        return jsonify({'message': 'No fields to update'}), 400
    
    values.append(skill_id)
    query = f"UPDATE skills SET {', '.join(update_fields)} WHERE id = ?"
    c.execute(query, values)
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Skill updated successfully'}), 200

@app.route('/api/enroll', methods=['POST'])
@token_required
def enroll_skill(current_user):
    data = request.get_json()
    skill_id = data.get('skill_id')
    
    if not skill_id:
        return jsonify({'message': 'Skill ID required'}), 400
    
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    # Check if skill exists and get required credits
    c.execute('SELECT credits_required, teacher_id FROM skills WHERE id = ?', (skill_id,))
    skill = c.fetchone()
    
    if not skill:
        conn.close()
        return jsonify({'message': 'Skill not found'}), 404
    
    if skill[1] == current_user['id']:
        conn.close()
        return jsonify({'message': 'Cannot enroll in your own skill'}), 400
    
    # Check user credits
    c.execute('SELECT credits FROM users WHERE id = ?', (current_user['id'],))
    user_credits = c.fetchone()[0]
    
    if user_credits < skill[0]:
        conn.close()
        return jsonify({'message': 'Insufficient credits'}), 400
    
    # Check if already enrolled
    c.execute('SELECT id FROM enrollments WHERE skill_id = ? AND learner_id = ?',
              (skill_id, current_user['id']))
    if c.fetchone():
        conn.close()
        return jsonify({'message': 'Already enrolled in this skill'}), 400
    
    # Enroll and deduct credits
    c.execute('INSERT INTO enrollments (skill_id, learner_id) VALUES (?, ?)',
              (skill_id, current_user['id']))
    c.execute('UPDATE users SET credits = credits - ? WHERE id = ?',
              (skill[0], current_user['id']))
    c.execute('UPDATE users SET credits = credits + ? WHERE id = ?',
              (skill[0], skill[1]))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Enrolled successfully'}), 201

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    c.execute('SELECT username, credits FROM users ORDER BY credits DESC LIMIT 10')
    leaderboard = []
    
    for i, row in enumerate(c.fetchall(), 1):
        leaderboard.append({
            'rank': i,
            'username': row[0],
            'credits': row[1]
        })
    
    conn.close()
    return jsonify(leaderboard)

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    try:
        # Get user info
        c.execute('SELECT username, email, credits FROM users WHERE id = ?', (current_user['id'],))
        user_info = c.fetchone()
        
        if not user_info:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
        
        # Get skills taught
        c.execute('SELECT title, category, credits_required, COALESCE(meeting_link, ""), COALESCE(class_timing, "") FROM skills WHERE teacher_id = ?',
                  (current_user['id'],))
        skills_taught = [{'title': row[0], 'category': row[1], 'credits': row[2], 'meeting_link': row[3], 'class_timing': row[4]} 
                         for row in c.fetchall()]
        
        # Get enrolled skills
        c.execute('''SELECT s.title, s.category, s.credits_required, COALESCE(s.meeting_link, ""), COALESCE(s.class_timing, "")
                     FROM enrollments e 
                     JOIN skills s ON e.skill_id = s.id 
                     WHERE e.learner_id = ? AND e.status = 'enrolled' ''',
                  (current_user['id'],))
        enrolled_skills = [{'title': row[0], 'category': row[1], 'credits': row[2], 'meeting_link': row[3], 'class_timing': row[4]} 
                           for row in c.fetchall()]
        
        conn.close()
        
        return jsonify({
            'username': user_info[0],
            'email': user_info[1],
            'credits': user_info[2],
            'skills_taught': skills_taught,
            'enrolled_skills': enrolled_skills
        })
        
    except Exception as e:
        conn.close()
        print(f"Profile error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/user/delete', methods=['DELETE'])
@token_required
def delete_account(current_user):
    conn = sqlite3.connect('skillswap.db')
    c = conn.cursor()
    
    try:
        # Check if user has active enrollments or skills being taught
        c.execute('SELECT COUNT(*) FROM enrollments WHERE learner_id = ? AND status = "enrolled"', (current_user['id'],))
        active_enrollments = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM skills WHERE teacher_id = ?', (current_user['id'],))
        skills_taught = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM enrollments e JOIN skills s ON e.skill_id = s.id WHERE s.teacher_id = ? AND e.status = "enrolled"', (current_user['id'],))
        students_enrolled = c.fetchone()[0]
        
        # If user has students enrolled in their skills, prevent deletion
        if students_enrolled > 0:
            conn.close()
            return jsonify({
                'message': f'Cannot delete account. You have {students_enrolled} students enrolled in your skills. Please wait for them to complete or contact support.'
            }), 400
        
        # Delete user data in correct order (due to foreign key constraints)
        # 1. Delete enrollments where user is a learner
        c.execute('DELETE FROM enrollments WHERE learner_id = ?', (current_user['id'],))
        
        # 2. Delete skills taught by the user
        c.execute('DELETE FROM skills WHERE teacher_id = ?', (current_user['id'],))
        
        # 3. Delete the user account
        c.execute('DELETE FROM users WHERE id = ?', (current_user['id'],))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Account deleted successfully'}), 200
        
    except Exception as e:
        conn.close()
        print(f"Delete account error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)