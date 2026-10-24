# Archivo: backend/app.py

import os
from flask import Flask, request, jsonify, session, g
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
from functools import wraps
from datetime import timezone
import secrets

app = Flask(__name__)
# No production secret or database credential may have a source-code fallback.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if os.environ.get("SESSION_V2_ENFORCE") == "1" and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY is required when session enforcement is enabled")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_SAMESITE="None", PERMANENT_SESSION_LIFETIME=timedelta(minutes=2))
CORS(app, origins=[origin.strip() for origin in os.environ.get("FRONTEND_ORIGINS", "").split(",") if origin.strip()], supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

dbconfig = {
    "host": os.environ.get("DB_HOST"),
    "user": os.environ.get("DB_USER"),
    "password": os.environ.get("DB_PASSWORD"),
    "database": os.environ.get("DB_NAME", "campus_security_v1"),
    "port": int(os.environ.get("DB_PORT", 4000)),
    "ssl_disabled": False
}

db_pool = pooling.MySQLConnectionPool(pool_name="campus_pool", pool_size=10, pool_reset_session=True, **dbconfig)

def get_db_connection(): return db_pool.get_connection()

EMAIL_SISTEMA = "campus.security.test@gmail.com"

# ==========================================
# HELPERS DE AUDITORÍA AVANZADA
# ==========================================
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

def registrar_operacion(usuario, rol, accion, detalles, ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO auditoria_operaciones (usuario, rol, accion, detalles, ip_origen) VALUES (%s, %s, %s, %s, %s)", 
                       (usuario, rol, accion, detalles, ip))
        conn.commit()
    except Exception: pass
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

def verificar_ip_bloqueada(ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM ips_bloqueadas WHERE ip = %s", (ip,))
        return cursor.fetchone() is not None
    except Exception: return False
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# Authentication is enforced at the API, not by browser sessionStorage.
# Flask's signed cookie is server-verified, but not a server-stored/revocable session.
# SESSION_V2_ENFORCE defaults off until the frontend and cookie deployment are validated.
def require_identity(fn):
    @wraps(fn)
    def guarded(*args, **kwargs):
        if os.environ.get("SESSION_V2_ENFORCE") != "1":
            return fn(*args, **kwargs)
        uid = session.get("uid")
        last = session.get("last_activity")
        now = datetime.now(timezone.utc).timestamp()
        if not uid or not last or now - float(last) >= 120:
            session.clear()
            return jsonify({"error": "Sesión expirada o inexistente"}), 401
        conn = cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id_usuario, rol, bloqueado FROM usuarios WHERE id_usuario = %s", (uid,))
            identity = cursor.fetchone()
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
        if not identity or identity["bloqueado"]:
            session.clear()
            return jsonify({"error": "Cuenta no autorizada"}), 403
        role = str(identity["rol"]).lower()
        path = request.path
        required = ("admin" if path.startswith("/api/admin/") else
                    "alumno" if path.startswith("/api/alumno/") else
                    "profesor" if path.startswith("/api/profesor/") else
                    "coordinadora" if path.startswith("/api/coordinador/") else None)
        if required and role not in ({required, "coordinador"} if required == "coordinadora" else {required, "administrador"} if required == "admin" else {required}):
            return jsonify({"error": "Permisos insuficientes"}), 403
        # Object-level access: a student/teacher cannot supply another user's id.
        for key in ("id_usuario", "id_alumno", "id_profesor"):
            if ((required == "alumno" and key in ("id_usuario", "id_alumno")) or (required == "profesor" and key == "id_profesor")) and key in (request.view_args or {}) and int(request.view_args[key]) != int(uid):
                return jsonify({"error": "Recurso no autorizado"}), 403
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            csrf = request.headers.get("X-CSRF-Token", "")
            if not csrf or not secrets.compare_digest(csrf, session.get("csrf", "")):
                return jsonify({"error": "CSRF inválido"}), 403
        session["last_activity"] = now
        g.identity = identity
        return fn(*args, **kwargs)
    return guarded

@app.before_request
def protect_role_apis():
    if request.path.startswith(("/api/admin/", "/api/alumno/", "/api/profesor/", "/api/coordinador/")):
        return require_identity(lambda: None)()

@app.route("/api/auth/session", methods=["GET"])
@require_identity
def session_status():
    if not session.get("uid"):
        return jsonify({"error": "Sin sesión"}), 401
    if datetime.now(timezone.utc).timestamp() - float(session.get("last_activity", 0)) >= 120:
        session.clear()
        return jsonify({"error": "Sesión expirada"}), 401
    session["last_activity"] = datetime.now(timezone.utc).timestamp()
    return jsonify({"id_usuario": session["uid"], "csrf": session.get("csrf")})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    if os.environ.get("SESSION_V2_ENFORCE") == "1" and session.get("uid"):
        csrf = request.headers.get("X-CSRF-Token", "")
        if not session.get("csrf") or not secrets.compare_digest(csrf, session["csrf"]):
            return jsonify({"error": "CSRF inválido"}), 403
    session.clear()
    return jsonify({"mensaje": "Sesión cerrada"})

# ==========================================
# RUTAS DE SEGURIDAD E IDENTIDAD (IAM)
# ==========================================
@app.route('/api/auth/captcha', methods=['GET'])
def generar_captcha():
    code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    session["captcha_expected"] = code
    session["captcha_issued_at"] = datetime.now(timezone.utc).timestamp()
    return jsonify({"captcha_code": code})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    ip = request.remote_addr
    if verificar_ip_bloqueada(ip):
        return jsonify({"error": "Tu dirección IP está en la Lista Negra del servidor. Acceso denegado permanentemente."}), 403

    data = request.json
    correo, password = data.get('correo'), data.get('password')
    captcha_user, captcha_real = data.get('captcha_input'), data.get('captcha_real')

    if os.environ.get("SESSION_V2_ENFORCE") == "1":
        expected = session.pop("captcha_expected", None)
        issued_at = session.pop("captcha_issued_at", 0)
        captcha_ok = bool(expected and captcha_user and
                          datetime.now(timezone.utc).timestamp() - float(issued_at) <= 120 and
                          secrets.compare_digest(captcha_user.upper(), expected))
    else:
        captcha_ok = bool(captcha_user and captcha_real and captcha_user.upper() == captcha_real.upper())
    if not captcha_ok:
        registrar_intento(correo, ip, False)
        return jsonify({"error": "Código CAPTCHA incorrecto"}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        
        if usuario:
            db_password = usuario.pop('password')
            is_valid = (check_password_hash(db_password, password) if (db_password.startswith('scrypt:') or db_password.startswith('pbkdf2:')) else (os.environ.get('SESSION_V2_ENFORCE') != '1' and secrets.compare_digest(db_password, password or '')))

            if is_valid:
                if usuario['bloqueado']:
                    registrar_intento(correo, ip, False)
                    return jsonify({"error": "Cuenta bloqueada. Contacte a soporte."}), 403
                
                registrar_intento(correo, ip, True)
                session.clear()
                session.permanent = True
                session["uid"] = usuario["id_usuario"]
                session["last_activity"] = datetime.now(timezone.utc).timestamp()
                session["csrf"] = secrets.token_urlsafe(32)
                # Never expose password-recovery credentials or expiry in login responses.
                usuario.pop('token_recuperacion', None)
                usuario.pop('token_expiracion', None)
                return jsonify({"mensaje": "Bienvenido", "usuario": usuario}), 200
            
        registrar_intento(correo, ip, False)
        return jsonify({"error": "Credenciales inválidas"}), 401
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/auth/recuperar-solicitar', methods=['POST'])
@limiter.limit("3 per 15 minutes")
def solicitar_recuperacion():
    data = request.json
    correo = data.get('correo')
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, nombre FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        if not usuario: return jsonify({"error": "Correo no registrado."}), 404
            
        token = ''.join(secrets.choice(string.digits) for _ in range(6))
        expiracion = datetime.now() + timedelta(minutes=15)
        cursor.execute("UPDATE usuarios SET token_recuperacion = %s, token_expiracion = %s WHERE id_usuario = %s", (token, expiracion, usuario['id_usuario']))
        conn.commit()
        
        llave_actual = os.environ.get("BREVO_API_KEY", "").strip()
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {"accept": "application/json", "api-key": llave_actual, "content-type": "application/json"}
        payload = {
            "sender": {"name": "Campus Security", "email": EMAIL_SISTEMA},
            "to": [{"email": correo, "name": usuario['nombre']}],
            "subject": "Recuperación de Contraseña",
            "htmlContent": f"<p>Hola <b>{usuario['nombre']}</b>,</p><p>Tu código de recuperación es: <h2>{token}</h2></p><p>Expira en 15 minutos.</p>"
        }
        requests.post(url, json=payload, headers=headers)
        return jsonify({"mensaje": "Código enviado."}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/auth/recuperar-cambiar', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def cambiar_password():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, token_recuperacion, token_expiracion FROM usuarios WHERE correo = %s", (data.get('correo'),))
        usuario = cursor.fetchone()
        
        if not usuario or not usuario['token_expiracion'] or usuario['token_expiracion'] < datetime.now() or not secrets.compare_digest(str(usuario['token_recuperacion'] or ''), str(data.get('token') or '')): return jsonify({"error": "Código inválido o expirado."}), 400
            
        nueva = data.get('nueva_password')
        if not isinstance(nueva, str) or len(nueva) < 12 or len(nueva) > 128:
            return jsonify({"error": "La contraseña debe tener entre 12 y 128 caracteres."}), 400
        hashed_password = generate_password_hash(nueva)
        cursor.execute("UPDATE usuarios SET password = %s, token_recuperacion = NULL, token_expiracion = NULL WHERE id_usuario = %s", (hashed_password, usuario['id_usuario']))
        conn.commit()
        registrar_operacion(data.get('correo'), "sistema", "RESETEO_PASSWORD", "El usuario restableció su credencial.", request.remote_addr)
        return jsonify({"mensaje": "Contraseña actualizada."}), 200
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

@app.route('/api/admin/ban_ip', methods=['POST'])
def ban_ip():
    ip_a_bloquear = request.json.get('ip')
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ips_bloqueadas (ip, motivo) VALUES (%s, 'Bloqueo manual desde panel Admin')", (ip_a_bloquear,))
        conn.commit()
        registrar_operacion("Administrador", "admin", "BAN_IP", f"Se agregó la IP {ip_a_bloquear} a la lista negra", request.remote_addr)
        return jsonify({"mensaje": f"IP {ip_a_bloquear} baneada exitosamente."}), 200
    except mysql.connector.IntegrityError:
        return jsonify({"error": "Esta IP ya estaba bloqueada."}), 400
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/auditoria/accesos', methods=['GET'])
def get_auditoria_accesos():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT s.*, IF(i.ip IS NOT NULL, 1, 0) as esta_baneada 
                 FROM seguridad_accesos s LEFT JOIN ips_bloqueadas i ON s.ip_origen = i.ip 
                 ORDER BY s.fecha_intento DESC LIMIT 200"""
        cursor.execute(sql)
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/admin/auditoria/operaciones', methods=['GET'])
def get_auditoria_operaciones():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM auditoria_operaciones ORDER BY fecha DESC LIMIT 300")
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
            rol, id_carrera = data['rol'], data.get('id_carrera')
            semestre_actual = 1 if rol == 'alumno' else 0
            hashed_password = generate_password_hash(data['password'])
            cursor.execute("INSERT INTO usuarios (matricula, nombre, correo, password, rol, id_carrera, semestre_actual) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                           (data['matricula'], data['nombre'], data['correo'], hashed_password, rol, id_carrera, semestre_actual))
            conn.commit()
            registrar_operacion("Administrador", "admin", f"ALTA_{rol.upper()}", f"Creó usuario {data['matricula']}", request.remote_addr)
            return jsonify({"mensaje": "Usuario creado"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT u.id_usuario, u.matricula, u.nombre, u.correo, u.rol, u.bloqueado, u.semestre_actual, c.clave as carrera FROM usuarios u LEFT JOIN carreras c ON u.id_carrera = c.id_carrera ORDER BY u.id_usuario DESC")
            return jsonify(cursor.fetchall()), 200
    except mysql.connector.IntegrityError: return jsonify({"error": "Dato duplicado"}), 400
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
        return jsonify({"mensaje": "Actualizado"}), 200
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
            cursor.execute("INSERT INTO carreras (clave, nombre, duracion_semestres, creditos_totales) VALUES (%s, %s, %s, %s)", (data['clave'].upper(), data['nombre'], data['duracion_semestres'], data['creditos_totales']))
            conn.commit()
            return jsonify({"mensaje": "Carrera creada"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT id_carrera, clave, nombre, duracion_semestres, creditos_totales FROM carreras ORDER BY nombre ASC")
            return jsonify(cursor.fetchall()), 200
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
            cursor.execute("INSERT INTO materias (id_carrera, clave, nombre, semestre, creditos, tipo) VALUES (%s, %s, %s, %s, %s, %s)", (data['id_carrera'], data['clave'], data['nombre'], data['semestre'], data['creditos'], data['tipo']))
            conn.commit()
            return jsonify({"mensaje": "Materia agregada"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT m.clave, m.nombre, m.semestre, m.creditos, m.tipo, c.clave as carrera FROM materias m JOIN carreras c ON m.id_carrera = c.id_carrera ORDER BY m.semestre ASC")
            return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DE ALUMNO
# ==========================================
@app.route('/api/alumno/perfil/<int:id_usuario>', methods=['PUT'])
def actualizar_perfil(id_usuario):
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        if data.get('password_nueva'):
            hashed_password = generate_password_hash(data['password_nueva'])
            sql = "UPDATE usuarios SET curp = %s, telefono = %s, direccion = %s, password = %s, perfil_completo = 1 WHERE id_usuario = %s"
            cursor.execute(sql, (data['curp'], data['telefono'], data['direccion'], hashed_password, id_usuario))
        else:
            sql = "UPDATE usuarios SET curp = %s, telefono = %s, direccion = %s, perfil_completo = 1 WHERE id_usuario = %s"
            cursor.execute(sql, (data['curp'], data['telefono'], data['direccion'], id_usuario))
        conn.commit()
        return jsonify({"mensaje": "Expediente actualizado"}), 200
    except Exception as e: return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/alumno/progreso/<int:id_alumno>', methods=['GET'])
def progreso_alumno(id_alumno):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT c.* FROM usuarios u JOIN carreras c ON u.id_carrera = c.id_carrera WHERE u.id_usuario = %s", (id_alumno,))
        carrera = cursor.fetchone()
        if not carrera: return jsonify({"error": "Sin carrera"}), 400
        cursor.execute("SELECT m.clave, m.nombre, m.semestre, m.creditos, m.tipo, k.estatus, k.calificacion, g.horario, p.nombre as profesor FROM kardex k JOIN materias m ON k.id_materia = m.id_materia LEFT JOIN grupos g ON k.id_grupo = g.id_grupo LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario WHERE k.id_alumno = %s ORDER BY m.semestre ASC", (id_alumno,))
        historial = cursor.fetchall()
        creditos_aprobados = sum(m['creditos'] for m in historial if m['estatus'] == 'Aprobada')
        porcentaje = (creditos_aprobados / carrera['creditos_totales']) * 100 if carrera['creditos_totales'] > 0 else 0
        return jsonify({"carrera": carrera['nombre'], "creditos_totales": carrera['creditos_totales'], "creditos_aprobados": creditos_aprobados, "porcentaje_avance": round(porcentaje, 1), "servicio_liberado": any(m['tipo'] == 'Servicio_Social' and m['estatus'] == 'Aprobada' for m in historial), "residencia_liberada": any(m['tipo'] == 'Residencia' and m['estatus'] == 'Aprobada' for m in historial), "historial": historial}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DE COORDINADOR
# ==========================================
@app.route('/api/coordinador/inscribir', methods=['POST'])
def coord_inscribir():
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("""SELECT 1 FROM usuarios coordinador
                JOIN usuarios alumno ON alumno.id_usuario = %s
                JOIN grupos grupo ON grupo.id_grupo = %s
                JOIN materias materia ON materia.id_materia = grupo.id_materia
                WHERE coordinador.id_usuario = %s AND coordinador.rol = 'coordinadora'
                AND alumno.rol = 'alumno' AND alumno.id_carrera = coordinador.id_carrera
                AND materia.id_carrera = coordinador.id_carrera AND materia.id_materia = %s""",
                (data['id_alumno'], data['id_grupo'], session['uid'], data['id_materia']))
            if not cursor.fetchone():
                return jsonify({"error": "Inscripción fuera de la carrera autorizada"}), 403
        cursor.execute("INSERT INTO kardex (id_alumno, id_materia, id_grupo, estatus) VALUES (%s, %s, %s, 'Cursando')", (data['id_alumno'], data['id_materia'], data['id_grupo']))
        conn.commit()
        return jsonify({"mensaje": "Inscrito"}), 201
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/profesores', methods=['GET'])
def list_profesores():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, nombre FROM usuarios WHERE rol = 'profesor' AND bloqueado = 0")
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/grupos/<int:id_carrera>', methods=['GET', 'POST'])
def gestionar_grupos(id_carrera):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = %s AND id_carrera = %s AND rol = 'coordinadora'", (session['uid'], id_carrera))
            if not cursor.fetchone():
                return jsonify({"error": "Carrera no autorizada"}), 403
        if request.method == 'POST':
            data = request.json
            if os.environ.get("SESSION_V2_ENFORCE") == "1":
                cursor.execute("SELECT 1 FROM materias WHERE id_materia = %s AND id_carrera = %s", (data['id_materia'], id_carrera))
                if not cursor.fetchone():
                    return jsonify({"error": "Materia fuera de su carrera"}), 403
            cursor.execute("INSERT INTO grupos (id_materia, id_profesor, nombre_grupo, horario, aula) VALUES (%s, %s, %s, %s, %s)", (data['id_materia'], data['id_profesor'], data['nombre_grupo'], data['horario'], data['aula']))
            conn.commit()
            return jsonify({"mensaje": "Grupo creado"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.nombre as materia, m.semestre, p.nombre as profesor FROM grupos g JOIN materias m ON g.id_materia = m.id_materia LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario WHERE m.id_carrera = %s ORDER BY m.semestre ASC", (id_carrera,))
            return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/materias_carrera/<int:id_carrera>', methods=['GET'])
def materias_carrera(id_carrera):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = %s AND rol = 'coordinadora' AND id_carrera = %s", (session['uid'], id_carrera))
            if not cursor.fetchone():
                return jsonify({"error": "Carrera no autorizada"}), 403
        cursor.execute("SELECT id_materia, nombre, semestre, clave FROM materias WHERE id_carrera = %s ORDER BY semestre ASC", (id_carrera,))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/alumnos/<int:id_carrera>', methods=['GET'])
def list_alumnos(id_carrera):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = %s AND rol = 'coordinadora' AND id_carrera = %s", (session['uid'], id_carrera))
            if not cursor.fetchone():
                return jsonify({"error": "Carrera no autorizada"}), 403
        cursor.execute("SELECT id_usuario, matricula, nombre, perfil_completo FROM usuarios WHERE rol = 'alumno' AND bloqueado = 0 AND id_carrera = %s ORDER BY nombre ASC", (id_carrera,))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/grupos_disponibles/<int:id_alumno>', methods=['GET'])
def grupos_disponibles(id_alumno):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM usuarios coordinador JOIN usuarios alumno ON alumno.id_carrera = coordinador.id_carrera WHERE coordinador.id_usuario = %s AND coordinador.rol = 'coordinadora' AND alumno.id_usuario = %s", (session['uid'], id_alumno))
            if not cursor.fetchone():
                return jsonify({"error": "Alumno fuera de su carrera"}), 403
        sql = """SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.id_materia, m.nombre as materia, m.semestre, p.nombre as profesor 
                 FROM grupos g JOIN materias m ON g.id_materia = m.id_materia LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario JOIN usuarios u ON m.id_carrera = u.id_carrera
                 WHERE u.id_usuario = %s AND m.id_materia NOT IN (SELECT id_materia FROM kardex WHERE id_alumno = %s AND estatus IN ('Aprobada', 'Cursando')) ORDER BY m.semestre ASC"""
        cursor.execute(sql, (id_alumno, id_alumno))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DEL PROFESOR
# ==========================================
@app.route('/api/profesor/grupos/<int:id_profesor>', methods=['GET'])
def profesor_get_grupos(id_profesor):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        sql = "SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.id_materia, m.clave as clave_materia, m.nombre as nombre_materia, m.semestre, c.nombre as carrera FROM grupos g JOIN materias m ON g.id_materia = m.id_materia JOIN carreras c ON m.id_carrera = c.id_carrera WHERE g.id_profesor = %s ORDER BY m.semestre ASC"
        cursor.execute(sql, (id_profesor,))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/profesor/grupo/<int:id_grupo>/alumnos', methods=['GET'])
def profesor_get_alumnos_grupo(id_grupo):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM grupos WHERE id_grupo = %s AND id_profesor = %s", (id_grupo, session['uid']))
            if not cursor.fetchone():
                return jsonify({"error": "Grupo no autorizado"}), 403
        sql = "SELECT k.id_kardex, u.id_usuario as id_alumno, u.matricula, u.nombre, u.correo, k.estatus, k.calificacion FROM kardex k JOIN usuarios u ON k.id_alumno = u.id_usuario WHERE k.id_grupo = %s ORDER BY u.nombre ASC"
        cursor.execute(sql, (id_grupo,))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/profesor/calificar', methods=['POST'])
def profesor_calificar_alumno():
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        if os.environ.get("SESSION_V2_ENFORCE") == "1":
            cursor.execute("SELECT 1 FROM kardex k JOIN grupos g ON k.id_grupo = g.id_grupo WHERE k.id_kardex = %s AND g.id_profesor = %s", (data['id_kardex'], session['uid']))
            if not cursor.fetchone():
                return jsonify({"error": "No autorizado para calificar este grupo"}), 403
        cursor.execute("UPDATE kardex SET calificacion = %s, estatus = %s WHERE id_kardex = %s", (data['calificacion'], data['estatus'], data['id_kardex']))
        conn.commit()
        return jsonify({"mensaje": "Calificación asentada"}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# NUEVA RUTA DE SOPORTE TÉCNICO (BREVO)
# ==========================================
@app.route('/api/soporte/enviar', methods=['POST'])
@limiter.limit("3 per hour")
def enviar_soporte():
    data = request.json
    nombre, correo = data.get('nombre'), data.get('correo')
    asunto, mensaje = data.get('asunto'), data.get('mensaje')

    if not all([nombre, correo, asunto, mensaje]):
        return jsonify({"error": "Todos los campos son obligatorios"}), 400

    try:
        llave_actual = os.environ.get("BREVO_API_KEY", "").strip()
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {"accept": "application/json", "api-key": llave_actual, "content-type": "application/json"}
        
        payload = {
            "sender": {"name": "Campus Soporte IT", "email": EMAIL_SISTEMA},
            "to": [{"email": EMAIL_SISTEMA, "name": "Administrador"}],
            "replyTo": {"email": correo, "name": nombre},
            "subject": f"Ticket de Soporte: {asunto}",
            "htmlContent": f"""
            <div style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #2563eb;">Nuevo Ticket de Asistencia</h2>
                <p><strong>Usuario:</strong> {nombre}</p>
                <p><strong>Contacto:</strong> {correo}</p>
                <hr>
                <p><strong>Mensaje:</strong></p>
                <p style="background-color: #f8fafc; padding: 15px; border-left: 4px solid #2563eb;">{mensaje}</p>
                <hr>
                <small>Responde directamente a este correo para contactar al usuario.</small>
            </div>
            """
        }
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code not in [200, 201]:
            return jsonify({"error": "Error interno del proveedor de correo."}), 500
            
        return jsonify({"mensaje": "Tu mensaje ha sido enviado al equipo de TI. Te contactaremos pronto."}), 200
    except Exception as e:
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)