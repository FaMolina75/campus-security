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

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

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
        
        if not usuario: return jsonify({"error": "Correo no registrado."}), 404
            
        token = ''.join(random.choice(string.digits) for _ in range(6))
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
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/auth/recuperar-cambiar', methods=['POST'])
def cambiar_password():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, token_recuperacion, token_expiracion FROM usuarios WHERE correo = %s", (data.get('correo'),))
        usuario = cursor.fetchone()
        
        if not usuario or usuario['token_recuperacion'] != data.get('token'):
            return jsonify({"error": "Código incorrecto."}), 400
            
        hashed_password = generate_password_hash(data.get('nueva_password'))
        cursor.execute("UPDATE usuarios SET password = %s, token_recuperacion = NULL, token_expiracion = NULL WHERE id_usuario = %s", (hashed_password, usuario['id_usuario']))
        conn.commit()
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
            semestre_actual = 1 if rol == 'alumno' else 0
            
            hashed_password = generate_password_hash(data['password'])
            cursor.execute("""
                INSERT INTO usuarios (matricula, nombre, correo, password, rol, id_carrera, semestre_actual) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (data['matricula'], data['nombre'], data['correo'], hashed_password, rol, id_carrera, semestre_actual))
            conn.commit()
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
# RUTAS DEL ALUMNO
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500
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

        cursor.execute("""
            SELECT m.clave, m.nombre, m.semestre, m.creditos, m.tipo, k.estatus, k.calificacion, g.horario, p.nombre as profesor 
            FROM kardex k JOIN materias m ON k.id_materia = m.id_materia LEFT JOIN grupos g ON k.id_grupo = g.id_grupo LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario
            WHERE k.id_alumno = %s ORDER BY m.semestre ASC
        """, (id_alumno,))
        historial = cursor.fetchall()
        creditos_aprobados = sum(m['creditos'] for m in historial if m['estatus'] == 'Aprobada')
        porcentaje = (creditos_aprobados / carrera['creditos_totales']) * 100 if carrera['creditos_totales'] > 0 else 0
        
        return jsonify({"carrera": carrera['nombre'], "creditos_totales": carrera['creditos_totales'], "creditos_aprobados": creditos_aprobados, "porcentaje_avance": round(porcentaje, 1), "servicio_liberado": any(m['tipo'] == 'Servicio_Social' and m['estatus'] == 'Aprobada' for m in historial), "residencia_liberada": any(m['tipo'] == 'Residencia' and m['estatus'] == 'Aprobada' for m in historial), "historial": historial}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DEL COORDINADOR
# ==========================================
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
        if request.method == 'POST':
            data = request.json
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
        sql = """SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.id_materia, m.nombre as materia, m.semestre, p.nombre as profesor 
                 FROM grupos g JOIN materias m ON g.id_materia = m.id_materia LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario JOIN usuarios u ON m.id_carrera = u.id_carrera
                 WHERE u.id_usuario = %s AND m.id_materia NOT IN (SELECT id_materia FROM kardex WHERE id_alumno = %s AND estatus IN ('Aprobada', 'Cursando')) ORDER BY m.semestre ASC"""
        cursor.execute(sql, (id_alumno, id_alumno))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/inscribir', methods=['POST'])
def coord_inscribir():
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO kardex (id_alumno, id_materia, id_grupo, estatus) VALUES (%s, %s, %s, 'Cursando')", (data['id_alumno'], data['id_materia'], data['id_grupo']))
        conn.commit()
        return jsonify({"mensaje": "Inscrito"}), 201
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
        cursor.execute("UPDATE kardex SET calificacion = %s, estatus = %s WHERE id_kardex = %s", (data['calificacion'], data['estatus'], data['id_kardex']))
        conn.commit()
        return jsonify({"mensaje": "Calificación asentada"}), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)