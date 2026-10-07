# Archivo: backend/app.py

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
import random
import string
import requests
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_clave_secreta_campus_v1') 
CORS(app, supports_credentials=True)

# ==========================================
# SEGURIDAD: RATE LIMITING (Anti Fuerza Bruta)
# ==========================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

# ==========================================
# CONFIGURACIÓN Y POOL DE BASE DE DATOS
# ==========================================
dbconfig = {
    "host": os.environ.get("DB_HOST", "gateway01.us-east-1.prod.aws.tidbcloud.com"),
    "user": os.environ.get("DB_USER", "t6BEupECtGTsvUW.root"),
    "password": os.environ.get("DB_PASSWORD", "GlrkiYV1MsMMGoIf"),
    "database": os.environ.get("DB_NAME", "campus_security_v1"),
    "port": int(os.environ.get("DB_PORT", 4000)),
    "ssl_disabled": False
}

db_pool = pooling.MySQLConnectionPool(pool_name="campus_pool", pool_size=10, pool_reset_session=True, **dbconfig)

def get_db_connection():
    return db_pool.get_connection()

EMAIL_SISTEMA = "campus.security.test@gmail.com"

# ==========================================
# RUTAS DE SEGURIDAD E IDENTIDAD (IAM)
# ==========================================
@app.route('/api/auth/captcha', methods=['GET'])
def generar_captcha():
    return jsonify({"captcha_code": ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    correo, password = data.get('correo'), data.get('password')
    captcha_user, captcha_real = data.get('captcha_input'), data.get('captcha_real')
    ip = request.remote_addr

    if not captcha_user or captcha_user.upper() != captcha_real.upper():
        registrar_intento(correo, ip, False)
        return jsonify({"error": "Código CAPTCHA incorrecto"}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT id_usuario, matricula, nombre, correo, password, rol, bloqueado, id_carrera, 
                 perfil_completo, curp, telefono, direccion, semestre_actual 
                 FROM usuarios WHERE correo = %s"""
        cursor.execute(sql, (correo,))
        usuario = cursor.fetchone()
        
        if usuario:
            db_password = usuario.pop('password')
            is_valid = check_password_hash(db_password, password) if (db_password.startswith('scrypt:') or db_password.startswith('pbkdf2:')) else (db_password == password)

            if is_valid:
                if usuario['bloqueado']:
                    registrar_intento(correo, ip, False)
                    return jsonify({"error": "Cuenta bloqueada. Contacte a soporte."}), 403
                
                registrar_intento(correo, ip, True)
                return jsonify({"mensaje": "Bienvenido", "usuario": usuario}), 200
            
        registrar_intento(correo, ip, False)
        return jsonify({"error": "Credenciales inválidas"}), 401
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

def registrar_intento(correo, ip, exitoso):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO seguridad_accesos (correo_intentado, ip_origen, exitoso) VALUES (%s, %s, %s)", (correo, ip, exitoso))
        conn.commit()
    except Exception: pass
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/auth/recuperar-solicitar', methods=['POST'])
@limiter.limit("3 per 15 minutes")
def solicitar_recuperacion():
    data = request.json
    correo = data.get('correo')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, nombre FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        
        if not usuario:
            return jsonify({"error": "El correo electrónico no está registrado en el sistema."}), 404
            
        token = ''.join(random.choice(string.digits) for _ in range(6))
        expiracion = datetime.now() + timedelta(minutes=15)
        
        cursor.execute("UPDATE usuarios SET token_recuperacion = %s, token_expiracion = %s WHERE id_usuario = %s", 
                       (token, expiracion, usuario['id_usuario']))
        conn.commit()
        
        llave_actual = os.environ.get("BREVO_API_KEY", "").strip()
        if not llave_actual:
            return jsonify({"error": "Error interno del servidor. Llave de correo no encontrada."}), 500
            
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "api-key": llave_actual,
            "content-type": "application/json"
        }
        payload = {
            "sender": {"name": "Campus Security", "email": EMAIL_SISTEMA},
            "to": [{"email": correo, "name": usuario['nombre']}],
            "subject": "Recuperación de Contraseña - Campus Security",
            "htmlContent": f"<p>Hola <b>{usuario['nombre']}</b>,</p><p>Has solicitado restablecer tu contraseña o el administrador forzó un reseteo.</p><p>Tu código de recuperación es: <h2 style='color:#3b82f6;'>{token}</h2></p><p>Este código expira en 15 minutos.</p>"
        }
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code not in [200, 201]:
            return jsonify({"error": f"Error al enviar el correo: {response.text}"}), 500
        
        return jsonify({"mensaje": "Código de recuperación enviado a tu correo exitosamente."}), 200
    except Exception as e:
        return jsonify({"error": f"Error al procesar la solicitud: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/auth/recuperar-cambiar', methods=['POST'])
def cambiar_password():
    data = request.json
    correo = data.get('correo')
    token = data.get('token')
    nueva_password = data.get('nueva_password')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, token_recuperacion, token_expiracion FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        
        if not usuario:
            return jsonify({"error": "Usuario no encontrado."}), 404
        if usuario['token_recuperacion'] != token:
            return jsonify({"error": "Código de recuperación incorrecto."}), 400
        if usuario['token_expiracion'] and datetime.now() > usuario['token_expiracion']:
            return jsonify({"error": "El código ha expirado. Solicita uno nuevo."}), 400
            
        hashed_password = generate_password_hash(nueva_password)
        cursor.execute("""
            UPDATE usuarios 
            SET password = %s, token_recuperacion = NULL, token_expiracion = NULL 
            WHERE id_usuario = %s
        """, (hashed_password, usuario['id_usuario']))
        conn.commit()
        
        return jsonify({"mensaje": "Contraseña actualizada exitosamente. Ya puedes iniciar sesión."}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DEL ADMINISTRADOR
# ==========================================
@app.route('/api/admin/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT (SELECT COUNT(*) FROM usuarios) as usuarios, (SELECT COUNT(*) FROM materias) as materias, (SELECT COUNT(*) FROM seguridad_accesos WHERE exitoso = 0) as alertas")
        return jsonify(cursor.fetchone())
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/auditoria', methods=['GET'])
def get_auditoria():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM seguridad_accesos ORDER BY fecha_intento DESC LIMIT 100")
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/usuarios', methods=['GET', 'POST'])
def gestionar_usuarios():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            data = request.json
            rol = data['rol']
            id_carrera = data.get('id_carrera') if data.get('id_carrera') else None
            
            # Reglas de negocio estrictas
            semestre_actual = 0
            if rol == 'alumno':
                if not id_carrera: return jsonify({"error": "Un alumno requiere forzosamente una carrera asignada."}), 400
                semestre_actual = 1
            elif rol == 'coordinadora':
                if not id_carrera: return jsonify({"error": "Un coordinador requiere forzosamente una carrera asignada."}), 400
                cursor.execute("SELECT id_usuario FROM usuarios WHERE rol = 'coordinadora' AND id_carrera = %s", (id_carrera,))
                if cursor.fetchone(): return jsonify({"error": "Ya existe un coordinador asignado a esta carrera."}), 400
            
            hashed_password = generate_password_hash(data['password'])
            cursor.execute("""
                INSERT INTO usuarios (matricula, nombre, correo, password, rol, id_carrera, semestre_actual) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (data['matricula'], data['nombre'], data['correo'], hashed_password, rol, id_carrera, semestre_actual))
            conn.commit()
            return jsonify({"mensaje": f"Usuario {rol.capitalize()} creado exitosamente"}), 201
            
        elif request.method == 'GET':
            cursor.execute("""
                SELECT u.id_usuario, u.matricula, u.nombre, u.correo, u.rol, u.bloqueado, u.semestre_actual, c.clave as carrera 
                FROM usuarios u LEFT JOIN carreras c ON u.id_carrera = c.id_carrera ORDER BY u.id_usuario DESC
            """)
            return jsonify(cursor.fetchall()), 200
    except mysql.connector.IntegrityError: return jsonify({"error": "Matrícula o correo duplicado"}), 400
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/usuarios/<int:id_usuario>/bloquear', methods=['PUT'])
def toggle_bloqueo(id_usuario):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET bloqueado = NOT bloqueado WHERE id_usuario = %s", (id_usuario,))
        conn.commit()
        return jsonify({"mensaje": "Estado de usuario actualizado"}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/carreras', methods=['GET', 'POST'])
def gestionar_carreras():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            data = request.json
            cursor.execute("""
                INSERT INTO carreras (clave, nombre, duracion_semestres, creditos_totales) 
                VALUES (%s, %s, %s, %s)
            """, (data['clave'].upper(), data['nombre'], data['duracion_semestres'], data['creditos_totales']))
            conn.commit()
            return jsonify({"mensaje": "Carrera creada y enlazada al sistema exitosamente"}), 201
            
        elif request.method == 'GET':
            cursor.execute("SELECT id_carrera, clave, nombre, duracion_semestres, creditos_totales FROM carreras ORDER BY nombre ASC")
            return jsonify(cursor.fetchall()), 200
    except mysql.connector.IntegrityError: 
        return jsonify({"error": "Error: La clave de esta carrera ya existe en el sistema."}), 400
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/materias', methods=['GET', 'POST'])
def gestionar_materias():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            data = request.json
            cursor.execute("INSERT INTO materias (id_carrera, clave, nombre, semestre, creditos, tipo) VALUES (%s, %s, %s, %s, %s, %s)",
                           (data['id_carrera'], data['clave'], data['nombre'], data['semestre'], data['creditos'], data['tipo']))
            conn.commit()
            return jsonify({"mensaje": "Materia agregada exitosamente"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT m.clave, m.nombre, m.semestre, m.creditos, m.tipo, c.clave as carrera FROM materias m JOIN carreras c ON m.id_carrera = c.id_carrera ORDER BY m.semestre ASC")
            return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)