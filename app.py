# app.py
import ssl
import os
import subprocess
import sys
import secrets
import json
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from functools import wraps
import sqlite3
import random
import string
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'butembo_mapper_secret_key_2026')
app.config['SESSION_TYPE'] = 'filesystem'

DATABASE = 'butembo.db'

# ---------- SECURITE : En-têtes HTTP ----------
@app.after_request
def add_security_headers(response):
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ---------- BASE DE DONNEES ----------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'contributeur',
            display_name TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'display_name' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            categorie TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            adresse TEXT,
            telephone TEXT,
            website TEXT,
            description TEXT,
            user_id INTEGER,
            status TEXT DEFAULT 'approuve',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            validated_at TIMESTAMP,
            validated_by INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (validated_by) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            categorie TEXT DEFAULT 'route',
            type_acces TEXT NOT NULL,
            geometrie TEXT NOT NULL,
            user_id INTEGER,
            status TEXT DEFAULT 'en_attente',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            validated_at TIMESTAMP,
            validated_by INTEGER,
            nombre_voies INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (validated_by) REFERENCES users (id)
        )
    ''')
    # Ajout colonne categorie si elle n'existe pas (migration)
    cursor.execute("PRAGMA table_info(routes)")
    route_cols = [col[1] for col in cursor.fetchall()]
    if 'categorie' not in route_cols:
        cursor.execute("ALTER TABLE routes ADD COLUMN categorie TEXT DEFAULT 'route'")
    if 'nombre_voies' not in route_cols:
        cursor.execute("ALTER TABLE routes ADD COLUMN nombre_voies INTEGER DEFAULT 1")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            speed REAL DEFAULT 0,
            altitude REAL DEFAULT 0,
            accuracy REAL DEFAULT 0,
            mode TEXT DEFAULT 'person',
            is_sharing INTEGER DEFAULT 0,
            last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS share_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            point_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (point_id) REFERENCES points (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Base de données initialisée correctement")

# ---------- DECORATEURS ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Non authentifié'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Non authentifié'}), 401
        if session.get('role') not in ['admin', 'admin_second']:
            return jsonify({'error': 'Accès non autorisé'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/request-reset')
def request_reset_page():
    return render_template('request_reset.html')

@app.route('/reset-password/<token>')
def reset_password_page(token):
    return render_template('reset_password.html', token=token)

@app.route('/admin')
def admin_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') not in ['admin', 'admin_second']:
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/dashboard-contributeur')
def dashboard_contributeur():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') != 'contributeur':
        return redirect(url_for('index'))
    return render_template('dashboard_contributeur.html')

@app.route('/profile')
def profile_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('profile.html')

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

# ---------- AUTHENTIFICATION ----------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    chosen_role = data.get('role')
    
    if not all([username, email, password, chosen_role]):
        return jsonify({'error': 'Tous les champs sont requis, y compris le profil'}), 400
        
    if chosen_role not in ['admin', 'contributeur']:
        return jsonify({'error': 'Profil utilisateur invalide'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    final_role = chosen_role
    if chosen_role == 'admin':
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] > 0:
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin_second'")
            if cursor.fetchone()[0] > 0:
                conn.close()
                return jsonify({'error': 'Les postes d\'administrateur principal et secondaire sont déjà occupés.'}), 400
            final_role = 'admin_second'
    
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Nom d\'utilisateur ou email déjà utilisé'}), 400
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    cursor.execute(
        'INSERT INTO users (username, email, password, role, display_name) VALUES (?, ?, ?, ?, ?)',
        (username, email, hashed_password, final_role, username)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    role_labels = {
        'admin': 'Administrateur Principal',
        'admin_second': 'Administrateur Secondaire',
        'contributeur': 'Contributeur'
    }
    
    return jsonify({
        'message': f'Inscription réussie en tant que : {role_labels.get(final_role)}',
        'user': {'id': user_id, 'username': username, 'email': email, 'role': final_role}
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, password, role, display_name FROM users WHERE username = ? OR email = ?', (username, username))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        
        return jsonify({
            'message': 'Connexion réussie',
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'role': user['role'], 'display_name': user['display_name']}
        }), 200
    else:
        return jsonify({'error': 'Identifiants invalides'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Déconnexion réussie'}), 200

@app.route('/api/me', methods=['GET'])
def get_me():
    if 'user_id' not in session:
        return jsonify({'error': 'Non authentifié'}), 401
    return jsonify({'id': session['user_id'], 'username': session['username'], 'role': session['role']}), 200

# ---------- RÉCUPÉRATION MOT DE PASSE ----------
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email requis'}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Si cet email existe, un lien de réinitialisation vous a été envoyé.'}), 200
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)
    cursor.execute('DELETE FROM password_resets WHERE email = ?', (email,))
    cursor.execute('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
                   (email, token, expires_at))
    conn.commit()
    conn.close()
    print(f"🔗 Lien de réinitialisation : http://localhost:5000/reset-password/{token}")
    return jsonify({'message': 'Un lien de réinitialisation a été envoyé à votre email.'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    if not token or not new_password:
        return jsonify({'error': 'Token et mot de passe requis'}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM password_resets WHERE token = ? AND expires_at > ?', (token, datetime.now()))
    reset = cursor.fetchone()
    if not reset:
        conn.close()
        return jsonify({'error': 'Token invalide ou expiré'}), 400
    email = reset['email']
    hashed = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed, email))
    cursor.execute('DELETE FROM password_resets WHERE token = ?', (token,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Mot de passe réinitialisé avec succès'}), 200

# ---------- PROFIL ----------
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, display_name, role FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    return jsonify(dict(user)), 200

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.json
    display_name = data.get('display_name', '').strip()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    
    updates = []
    params = []
    
    if display_name:
        updates.append('display_name = ?')
        params.append(display_name)
    
    if current_password and new_password:
        if not check_password_hash(user['password'], current_password):
            conn.close()
            return jsonify({'error': 'Mot de passe actuel incorrect'}), 400
        hashed = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        updates.append('password = ?')
        params.append(hashed)
    
    if not updates:
        conn.close()
        return jsonify({'error': 'Aucune modification demandée'}), 400
    
    params.append(session['user_id'])
    sql = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(sql, params)
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Profil mis à jour avec succès'}), 200

# ---------- POINTS ----------
@app.route('/api/points', methods=['GET'])
def get_points():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT p.*, u.username as contributeur FROM points p LEFT JOIN users u ON p.user_id = u.id WHERE p.status = 'approuve' ORDER BY p.created_at DESC''')
    points = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(points), 200

@app.route('/api/points', methods=['POST'])
@login_required
def add_point():
    data = request.json
    nom, categorie, latitude, longitude = data.get('nom'), data.get('categorie'), data.get('latitude'), data.get('longitude')
    if not all([nom, categorie, latitude, longitude]):
        return jsonify({'error': 'Nom, catégorie et coordonnées requis'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO points (nom, categorie, latitude, longitude, adresse, telephone, website, description, status, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'en_attente', ?, CURRENT_TIMESTAMP)''', (nom, categorie, latitude, longitude, data.get('adresse', ''), data.get('telephone', ''), data.get('website', ''), data.get('description', ''), session['user_id']))
    point_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': point_id, 'message': 'Lieu ajouté'}), 201

@app.route('/api/points/<int:point_id>', methods=['GET'])
def get_point_details(point_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT p.*, u.username as contributeur, vu.username as valide_par 
                     FROM points p 
                     LEFT JOIN users u ON p.user_id = u.id 
                     LEFT JOIN users vu ON p.validated_by = vu.id 
                     WHERE p.id = ?''', (point_id,))
    point = cursor.fetchone()
    conn.close()
    if not point:
        return jsonify({'error': 'Point non trouvé'}), 404
    return jsonify(dict(point)), 200

@app.route('/api/points/<int:point_id>', methods=['PUT'])
@login_required
def edit_point(point_id):
    data = request.json
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM points WHERE id = ?', (point_id,))
    existing = cursor.fetchone()
    
    if not existing:
        conn.close()
        return jsonify({'error': 'Lieu introuvable'}), 404
    if existing['user_id'] != session['user_id'] and session.get('role') not in ['admin', 'admin_second']:
        conn.close()
        return jsonify({'error': 'Action non autorisée'}), 403
        
    cursor.execute('''UPDATE points SET nom=?, categorie=?, latitude=?, longitude=?, adresse=?, telephone=?, website=?, description=? WHERE id=?''', (data.get('nom'), data.get('categorie'), data.get('latitude'), data.get('longitude'), data.get('adresse', ''), data.get('telephone', ''), data.get('website', ''), data.get('description', ''), point_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Lieu mis à jour'}), 200

@app.route('/api/points/<int:point_id>', methods=['DELETE'])
@login_required
def delete_point(point_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM points WHERE id = ?', (point_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Lieu introuvable'}), 404
    if existing['user_id'] != session['user_id'] and session.get('role') not in ['admin', 'admin_second']:
        conn.close()
        return jsonify({'error': 'Action non autorisée'}), 403
    cursor.execute('DELETE FROM points WHERE id = ?', (point_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Lieu supprimé'}), 200

# ---------- ROUTES ----------
@app.route('/api/routes', methods=['GET'])
def get_routes():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT *, categorie, nombre_voies FROM routes WHERE status = "approuve" ORDER BY created_at DESC')
    routes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(routes), 200

@app.route('/api/routes', methods=['POST'])
@login_required
def add_route():
    data = request.json
    nom = data.get('nom')
    type_acces = data.get('type_acces')
    geometrie = data.get('geometrie')
    categorie = data.get('categorie', 'route')
    nombre_voies = data.get('nombre_voies', 1)
    if not nom or not type_acces or not geometrie or len(geometrie) < 2:
        return jsonify({'error': 'Nom, type d\'accès et au moins deux points requis'}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO routes (nom, type_acces, geometrie, user_id, status, categorie, nombre_voies, created_at)
        VALUES (?, ?, ?, ?, 'en_attente', ?, ?, CURRENT_TIMESTAMP)
    ''', (nom, type_acces, json.dumps(geometrie), session['user_id'], categorie, nombre_voies))
    route_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': route_id, 'message': 'Route ajoutée'}), 201

@app.route('/api/routes/<int:route_id>', methods=['PUT'])
@login_required
def edit_route(route_id):
    data = request.json
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM routes WHERE id = ?', (route_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Route introuvable'}), 404
    if existing['user_id'] != session['user_id'] and session.get('role') not in ['admin', 'admin_second']:
        conn.close()
        return jsonify({'error': 'Action non autorisée'}), 403
    cursor.execute('''
        UPDATE routes SET nom=?, type_acces=?, geometrie=?, categorie=?, nombre_voies=?
        WHERE id=?
    ''', (data.get('nom'), data.get('type_acces'), json.dumps(data.get('geometrie')), data.get('categorie', 'route'), data.get('nombre_voies', 1), route_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Route mise à jour'}), 200

@app.route('/api/routes/<int:route_id>', methods=['DELETE'])
@login_required
def delete_route(route_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM routes WHERE id = ?', (route_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Route introuvable'}), 404
    if existing['user_id'] != session['user_id'] and session.get('role') not in ['admin', 'admin_second']:
        conn.close()
        return jsonify({'error': 'Action non autorisée'}), 403
    cursor.execute('DELETE FROM routes WHERE id = ?', (route_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Route supprimée'}), 200

@app.route('/api/admin/routes-all', methods=['GET'])
@admin_required
def get_all_routes_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, u.username as contributeur, vu.username as valide_par
        FROM routes r
        LEFT JOIN users u ON r.user_id = u.id
        LEFT JOIN users vu ON r.validated_by = vu.id
        ORDER BY r.created_at DESC
    ''')
    routes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(routes), 200

@app.route('/api/admin/routes/<int:route_id>/status', methods=['PUT'])
@admin_required
def update_route_status(route_id):
    new_status = request.json.get('status')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM routes WHERE id = ?', (route_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Route non trouvée'}), 404
    if existing['status'] != new_status:
        cursor.execute('UPDATE routes SET status = ?, validated_at = CURRENT_TIMESTAMP, validated_by = ? WHERE id = ?',
                       (new_status, session['user_id'], route_id))
        conn.commit()
    conn.close()
    return jsonify({'message': 'Statut mis à jour'}), 200

# ---------- SIGNALEMENT ----------
@app.route('/api/signal-point', methods=['POST'])
@login_required
def signal_point():
    data = request.json
    point_id = data.get('point_id')
    comment = data.get('comment', '')
    if not point_id:
        return jsonify({'error': 'ID du point requis'}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM points WHERE id = ?', (point_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Point non trouvé'}), 404
    cursor.execute('INSERT INTO signals (point_id, user_id, comment) VALUES (?, ?, ?)',
                   (point_id, session['user_id'], comment))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Signalement envoyé'}), 200

# ---------- ADMIN ----------
@app.route('/api/admin/points/<int:point_id>/status', methods=['PUT'])
@admin_required
def update_point_status(point_id):
    new_status = request.json.get('status')
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT status FROM points WHERE id = ?', (point_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Point non trouvé'}), 404
    
    if existing['status'] != new_status:
        cursor.execute('UPDATE points SET status = ?, validated_at = CURRENT_TIMESTAMP, validated_by = ? WHERE id = ?', 
                       (new_status, session['user_id'], point_id))
        conn.commit()
    
    conn.close()
    return jsonify({'message': 'Statut mis à jour'}), 200

@app.route('/api/admin/points-all', methods=['GET'])
@admin_required
def get_all_points_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT p.*, u.username as contributeur, 
                     vu.username as valide_par 
                     FROM points p 
                     LEFT JOIN users u ON p.user_id = u.id 
                     LEFT JOIN users vu ON p.validated_by = vu.id 
                     ORDER BY p.created_at DESC''')
    points = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(points), 200

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, display_name, created_at FROM users ORDER BY created_at DESC')
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    new_role = request.json.get('role')
    if new_role not in ['admin', 'admin_second', 'contributeur']:
        return jsonify({'error': 'Rôle invalide'}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Rôle mis à jour'}), 200

@app.route('/api/admin/exists', methods=['GET'])
def check_admin_exists():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_exists = cursor.fetchone()[0] > 0
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin_second'")
    admin_second_exists = cursor.fetchone()[0] > 0
    conn.close()
    return jsonify({'admin_exists': admin_exists, 'admin_second_exists': admin_second_exists}), 200

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Impossible de supprimer votre propre compte'}), 400
    conn = get_db()
    cursor = conn.cursor()

    # Mettre à jour les points pour enlever la référence à l'utilisateur
    cursor.execute('UPDATE points SET user_id = NULL WHERE user_id = ?', (user_id,))
    cursor.execute('UPDATE routes SET user_id = NULL WHERE user_id = ?', (user_id,))
    # Mettre à jour les champs validated_by
    cursor.execute('UPDATE points SET validated_by = NULL WHERE validated_by = ?', (user_id,))
    cursor.execute('UPDATE routes SET validated_by = NULL WHERE validated_by = ?', (user_id,))

    # Supprimer les données de localisation et codes de partage (données personnelles)
    cursor.execute('DELETE FROM user_locations WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM share_codes WHERE user_id = ?', (user_id,))

    # Supprimer l'utilisateur
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Utilisateur supprimé, ses contributions ont été conservées'}), 200

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM points')
    total_points = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM points WHERE status = 'en_attente'")
    pending_points = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM routes WHERE status = 'en_attente'")
    pending_routes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM points WHERE status = 'approuve'")
    approved_points = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM routes WHERE status = 'approuve'")
    approved_routes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM points WHERE status = 'rejete'")
    rejected_points = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM routes WHERE status = 'rejete'")
    rejected_routes = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        'total_users': total_users,
        'total_points': total_points,
        'pending_points': pending_points,
        'pending_routes': pending_routes,
        'approved_points': approved_points,
        'approved_routes': approved_routes,
        'rejected_points': rejected_points,
        'rejected_routes': rejected_routes
    }), 200

@app.route('/api/admin/user/<int:user_id>', methods=['GET'])
@admin_required
def get_user_details(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, email, role, display_name, created_at FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    user_dict = dict(user)
    
    cursor.execute('''
        SELECT id, nom, categorie, status, created_at, validated_at 
        FROM points WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,))
    contributions = [dict(row) for row in cursor.fetchall()]
    user_dict['contributions'] = contributions
    user_dict['total_contributions'] = len(contributions)
    
    cursor.execute('''
        SELECT latitude, longitude, mode, is_sharing, last_update 
        FROM user_locations WHERE user_id = ?
    ''', (user_id,))
    location = cursor.fetchone()
    user_dict['location'] = dict(location) if location else None
    
    conn.close()
    return jsonify(user_dict), 200

# ---------- LOCALISATION ----------
@app.route('/api/update-location', methods=['POST'])
@login_required
def update_location():
    data = request.json
    lat, lng = data.get('latitude'), data.get('longitude')
    if lat is None or lng is None:
        return jsonify({'error': 'Coordonnées requises'}), 400
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT OR REPLACE INTO user_locations (user_id, latitude, longitude, speed, altitude, accuracy, mode, is_sharing, last_update) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''', (session['user_id'], lat, lng, data.get('speed', 0), data.get('altitude', 0), data.get('accuracy', 0), data.get('mode', 'person'), data.get('is_sharing', 1)))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Position mise à jour'}), 200

@app.route('/api/active-users', methods=['GET'])
@login_required
def get_active_users():
    conn = get_db()
    cursor = conn.cursor()
    threshold = datetime.now() - timedelta(minutes=5)
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if user_role in ['admin', 'admin_second']:
        cursor.execute('''
            SELECT u.id as user_id, u.username, ul.latitude, ul.longitude, ul.mode, ul.last_update, ul.is_sharing
            FROM user_locations ul 
            JOIN users u ON u.id = ul.user_id 
            WHERE ul.last_update > ? 
            AND ul.user_id != ?
            AND ul.is_sharing = 1
        ''', (threshold, user_id))
        users = [dict(row) for row in cursor.fetchall()]
    else:
        users = []
    
    conn.close()
    return jsonify(users), 200

@app.route('/api/generate-share-code', methods=['POST'])
@login_required
def generate_share_code():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    expires_at = datetime.now() + timedelta(hours=1)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM share_codes WHERE expires_at < ?', (datetime.now(),))
    cursor.execute('DELETE FROM share_codes WHERE user_id = ?', (session['user_id'],))
    
    cursor.execute('INSERT INTO share_codes (user_id, code, expires_at) VALUES (?, ?, ?)', 
                   (session['user_id'], code, expires_at))
    conn.commit()
    conn.close()
    return jsonify({'code': code, 'expires_at': expires_at.isoformat()}), 200

@app.route('/api/share-code-location/<code>', methods=['GET'])
@login_required
def get_share_code_location(code):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT sc.user_id, u.username, ul.latitude, ul.longitude, ul.mode, ul.last_update, ul.is_sharing
        FROM share_codes sc 
        JOIN users u ON u.id = sc.user_id 
        LEFT JOIN user_locations ul ON ul.user_id = sc.user_id 
        WHERE sc.code = ? AND sc.expires_at > ?
    ''', (code, datetime.now()))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Code invalide ou expiré'}), 404
    
    if not result['is_sharing']:
        return jsonify({'error': 'L\'utilisateur a désactivé le partage de sa position'}), 403
        
    return jsonify({
        'user_id': result['user_id'], 
        'username': result['username'], 
        'latitude': result['latitude'], 
        'longitude': result['longitude'], 
        'mode': result['mode'], 
        'last_update': result['last_update'],
        'is_sharing': result['is_sharing']
    }), 200

@app.route('/api/stop-sharing', methods=['POST'])
@login_required
def stop_sharing():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE user_locations SET is_sharing = 0 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Partage désactivé'}), 200

# ---------- STATISTIQUES ----------
@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM points')
    total_points = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    conn.close()
    return jsonify({'total_points': total_points, 'total_users': total_users}), 200

# ---------- DASHBOARD CONTRIBUTEUR ----------
@app.route('/api/dashboard/contributeur/stats', methods=['GET'])
@login_required
def get_dashboard_contributeur_stats():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'contributeur':
            conn.close()
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Stats points
        cursor.execute('SELECT COUNT(*) FROM points WHERE user_id = ?', (user_id,))
        total_points = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM points WHERE user_id = ? AND status = 'en_attente'", (user_id,))
        pending_points = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM points WHERE user_id = ? AND status = 'approuve'", (user_id,))
        approved_points = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM points WHERE user_id = ? AND status = 'rejete'", (user_id,))
        rejected_points = cursor.fetchone()[0]
        
        # Stats routes
        cursor.execute('SELECT COUNT(*) FROM routes WHERE user_id = ?', (user_id,))
        total_routes = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM routes WHERE user_id = ? AND status = 'en_attente'", (user_id,))
        pending_routes = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM routes WHERE user_id = ? AND status = 'approuve'", (user_id,))
        approved_routes = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM routes WHERE user_id = ? AND status = 'rejete'", (user_id,))
        rejected_routes = cursor.fetchone()[0]
        
        # Mises à jour récentes
        cursor.execute("""
            SELECT COUNT(*) FROM points 
            WHERE user_id = ? AND validated_at IS NOT NULL 
            AND datetime(validated_at) > datetime('now', '-1 day')
        """, (user_id,))
        recent_points = cursor.fetchone()[0]
        cursor.execute("""
            SELECT COUNT(*) FROM routes 
            WHERE user_id = ? AND validated_at IS NOT NULL 
            AND datetime(validated_at) > datetime('now', '-1 day')
        """, (user_id,))
        recent_routes = cursor.fetchone()[0]
        recent_updates = recent_points + recent_routes
        
        conn.close()
        return jsonify({
            'total_contributions': total_points + total_routes,
            'pending_contributions': pending_points + pending_routes,
            'approved_contributions': approved_points + approved_routes,
            'rejected_contributions': rejected_points + rejected_routes,
            'recent_updates': recent_updates,
            'points': {
                'total': total_points,
                'pending': pending_points,
                'approved': approved_points,
                'rejected': rejected_points
            },
            'routes': {
                'total': total_routes,
                'pending': pending_routes,
                'approved': approved_routes,
                'rejected': rejected_routes
            }
        }), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/contributeur/points', methods=['GET'])
@login_required
def get_dashboard_contributeur_points():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT p.*, u.username as valide_par 
            FROM points p 
            LEFT JOIN users u ON p.validated_by = u.id 
            WHERE p.user_id = ? 
            ORDER BY p.created_at DESC
        ''', (user_id,))
        points = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(points), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

# NOUVEL ENDPOINT : contributions mixtes (points + routes)
@app.route('/api/dashboard/contributeur/contributions', methods=['GET'])
@login_required
def get_contributeur_contributions():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'contributeur':
            conn.close()
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Points
        cursor.execute('''
            SELECT p.*, 'point' as type, u.username as valide_par
            FROM points p
            LEFT JOIN users u ON p.validated_by = u.id
            WHERE p.user_id = ?
            ORDER BY p.created_at DESC
        ''', (user_id,))
        points = [dict(row) for row in cursor.fetchall()]
        
        # Routes
        cursor.execute('''
            SELECT r.*, 'route' as type, u.username as valide_par
            FROM routes r
            LEFT JOIN users u ON r.validated_by = u.id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        ''', (user_id,))
        routes = [dict(row) for row in cursor.fetchall()]
        
        contributions = points + routes
        contributions.sort(key=lambda x: x['created_at'], reverse=True)
        conn.close()
        return jsonify(contributions), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/contributeur/check-updates', methods=['GET'])
@login_required
def check_contributeur_updates():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Mises à jour des points
        cursor.execute('''
            SELECT id, nom, status, validated_at, 'point' as type
            FROM points 
            WHERE user_id = ? 
            AND validated_at IS NOT NULL 
            AND datetime(validated_at) > datetime('now', '-1 day')
            ORDER BY validated_at DESC
            LIMIT 5
        ''', (user_id,))
        points_updates = [dict(row) for row in cursor.fetchall()]
        
        # Mises à jour des routes
        cursor.execute('''
            SELECT id, nom, status, validated_at, 'route' as type
            FROM routes 
            WHERE user_id = ? 
            AND validated_at IS NOT NULL 
            AND datetime(validated_at) > datetime('now', '-1 day')
            ORDER BY validated_at DESC
            LIMIT 5
        ''', (user_id,))
        routes_updates = [dict(row) for row in cursor.fetchall()]
        
        all_updates = points_updates + routes_updates
        all_updates.sort(key=lambda x: x['validated_at'], reverse=True)
        conn.close()
        return jsonify({'updates': all_updates, 'count': len(all_updates)}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

# ---------- GENERATION DE CERTIFICAT AUTO-SIGNE ----------
def generate_self_signed_cert():
    cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_file = os.path.join(cert_dir, 'cert.pem')
    key_file = os.path.join(cert_dir, 'key.pem')
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("✅ Certificats SSL déjà existants")
        return cert_file, key_file
    
    print("🔐 Génération de certificats auto-signés...")
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CD"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nord-Kivu"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Butembo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ButemboMapper"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            dt.datetime.utcnow()
        ).not_valid_after(
            dt.datetime.utcnow() + dt.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("✅ Certificats générés avec cryptography")
        return cert_file, key_file
        
    except ImportError:
        print("ℹ️  cryptography non installé, tentative avec OpenSSL...")
    except Exception as e:
        print(f"⚠️  Erreur avec cryptography : {e}, tentative avec OpenSSL...")
    
    try:
        subprocess.run(['openssl', 'version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ OpenSSL n'est pas installé ou n'est pas dans le PATH.")
        print("   Pour installer OpenSSL :")
        print("     - Windows : https://slproweb.com/products/Win32OpenSSL.html")
        print("     - Linux : sudo apt-get install openssl")
        print("     - macOS : brew install openssl")
        print("   Ou installez cryptography : pip install cryptography")
        return None, None
    
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-nodes', '-out', cert_file, '-keyout', key_file,
        '-days', '365',
        '-subj', '/C=CD/ST=Nord-Kivu/L=Butembo/O=ButemboMapper/CN=localhost'
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("✅ Certificats générés avec OpenSSL")
        return cert_file, key_file
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur OpenSSL : {e.stderr.decode()}")
        return None, None

def create_ssl_context(cert_file, key_file):
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_file, key_file)
        return context
    except Exception as e:
        print(f"❌ Erreur lors du chargement du certificat : {e}")
        return None

# ---------- POINT D'ENTRÉE ----------
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    use_https = os.environ.get('USE_HTTPS', 'true').lower() != 'false'
    
    if use_https:
        print("\n🔒 Activation du mode HTTPS...")
        cert_file, key_file = generate_self_signed_cert()
        
        if cert_file and key_file:
            context = create_ssl_context(cert_file, key_file)
            if context:
                print(f"\n🚀 Serveur HTTPS démarré sur https://localhost:{port}")
                print("⚠️  Certificat auto-signé : acceptez-le dans votre navigateur.")
                app.run(host='0.0.0.0', port=port, ssl_context=context)
            else:
                print("❌ Impossible de démarrer en HTTPS, lancement en HTTP...")
                app.run(host='0.0.0.0', port=port)
        else:
            print("❌ Impossible de générer les certificats, lancement en HTTP...")
            app.run(host='0.0.0.0', port=port)
    else:
        print(f"\n🚀 Serveur HTTP démarré sur http://localhost:{port}")
        app.run(host='0.0.0.0', port=port)