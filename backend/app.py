# Archivo: backend/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import random
import string
import smtplib
import threading
from email.mime.text import MIMEText
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'super_clave_secreta_campus_v1' 
CORS(app, supports_credentials=True)

# ==========================================
# CONFIGURACIÓN DE BASE DE DATOS (NUBE - TiDB)
# ==========================================
DB_HOST = 'gateway01.us-east-1.prod.aws.tidbcloud.com'
DB_USER = 't6BEupECtGTsvUW.root'
DB_PASSWORD = 'GlrkiYV1MsMMGoIf'
DB_NAME = 'campus_security_v1'
DB_PORT = 4000

# ==========================================
# CONFIGURACIÓN DE CORREO (SMTP GMAIL)
# ==========================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SISTEMA = "campus.security.test@gmail.com"
EMAIL_PASSWORD = "FA200175m@."

def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT,
        ssl_disabled=False
    )

# Función para enviar correo en segundo plano (Evita Timeouts en Render)
def enviar_correo_async(destinatario, nombre, token):
    try:
        asunto = "Recuperación de Contraseña - Campus Security"
        cuerpo = f"Hola {nombre},\n\nHas solicitado restablecer tu contraseña. Tu código de recuperación es: {token}\nEste código expira en 15 minutos.\n\nSi no solicitaste esto, ignora este mensaje."
        
        msg = MIMEText(cuerpo)
        msg['Subject'] = asunto
        msg['From'] = EMAIL_SISTEMA
        msg['To'] = destinatario
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SISTEMA, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SISTEMA, destinatario, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Error al enviar correo en background: {str(e)}")

# ==========================================
# RUTAS DE SEGURIDAD E IDENTIDAD (IAM)
# ==========================================
@app.route('/api/auth/captcha', methods=['GET'])
def generar_captcha():
    return jsonify({"captcha_code": ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))})

@app.route('/api/auth/login', methods=['POST'])
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
        sql = """SELECT id_usuario, matricula, nombre, correo, rol, bloqueado, id_carrera, 
                 perfil_completo, curp, telefono, direccion 
                 FROM usuarios WHERE correo = %s AND password = %s"""
        cursor.execute(sql, (correo, password))
        usuario = cursor.fetchone()
        
        if usuario:
            if usuario['bloqueado']:
                registrar_intento(correo, ip, False)
                return jsonify({"error": "Cuenta bloqueada. Contacte a soporte."}), 403
            registrar_intento(correo, ip, True)
            return jsonify({"mensaje": "Bienvenido", "usuario": usuario}), 200
        else:
            registrar_intento(correo, ip, False)
            return jsonify({"error": "Credenciales inválidas"}), 401
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA
# ==========================================
@app.route('/api/auth/recuperar-solicitar', methods=['POST'])
def solicitar_recuperacion():
    data = request.json
    correo = data.get('correo')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, nombre FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        
        if not usuario:
            return jsonify({"error": "El correo electrónico no está registrado en el sistema."}), 404
            
        # Generar token de 6 dígitos
        token = ''.join(random.choice(string.digits) for _ in range(6))
        expiracion = datetime.now() + timedelta(minutes=15)
        
        # Guardar en base de datos
        cursor.execute("UPDATE usuarios SET token_recuperacion = %s, token_expiracion = %s WHERE id_usuario = %s", 
                       (token, expiracion, usuario['id_usuario']))
        conn.commit()
        
        # Lanzar el envío de correo en un hilo separado (No bloquea a Render)
        hilo = threading.Thread(target=enviar_correo_async, args=(correo, usuario['nombre'], token))
        hilo.start()
        
        return jsonify({"mensaje": "Código de recuperación enviado a tu correo exitosamente."}), 200
    except Exception as e:
        return jsonify({"error": f"Error al procesar la solicitud: {str(e)}"}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

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
            
        # Actualizar contraseña y limpiar token
        cursor.execute("""
            UPDATE usuarios 
            SET password = %s, token_recuperacion = NULL, token_expiracion = NULL 
            WHERE id_usuario = %s
        """, (nueva_password, usuario['id_usuario']))
        conn.commit()
        
        return jsonify({"mensaje": "Contraseña actualizada exitosamente. Ya puedes iniciar sesión."}), 200
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

@app.route('/api/admin/usuarios', methods=['GET', 'POST'])
def gestionar_usuarios():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            data = request.json
            id_carrera = data.get('id_carrera') if data.get('id_carrera') else None
            
            if data['rol'] == 'coordinadora' and id_carrera:
                cursor.execute("SELECT id_usuario FROM usuarios WHERE rol = 'coordinadora' AND id_carrera = %s", (id_carrera,))
                if cursor.fetchone():
                    return jsonify({"error": "Ya existe un coordinador asignado a esta carrera."}), 400
            
            cursor.execute("INSERT INTO usuarios (matricula, nombre, correo, password, rol, id_carrera) VALUES (%s, %s, %s, %s, %s, %s)", 
                           (data['matricula'], data['nombre'], data['correo'], data['password'], data['rol'], id_carrera))
            conn.commit()
            return jsonify({"mensaje": "Usuario creado exitosamente"}), 201
        elif request.method == 'GET':
            cursor.execute("SELECT u.id_usuario, u.matricula, u.nombre, u.correo, u.rol, u.bloqueado, c.clave as carrera FROM usuarios u LEFT JOIN carreras c ON u.id_carrera = c.id_carrera ORDER BY u.id_usuario DESC")
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

@app.route('/api/admin/carreras', methods=['GET'])
def get_carreras():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_carrera, clave, nombre, duracion_semestres, creditos_totales FROM carreras")
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

# ==========================================
# RUTAS DEL ALUMNO
# ==========================================
@app.route('/api/alumno/perfil/<int:id_usuario>', methods=['PUT'])
def actualizar_perfil(id_usuario):
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        nueva_password = data['password_nueva']
        
        sql = """UPDATE usuarios 
                 SET curp = %s, telefono = %s, direccion = %s, password = %s, perfil_completo = 1 
                 WHERE id_usuario = %s"""
        cursor.execute(sql, (data['curp'], data['telefono'], data['direccion'], nueva_password, id_usuario))
        conn.commit()
        return jsonify({"mensaje": "Expediente guardado y contraseña actualizada exitosamente"}), 200
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
        if not carrera: return jsonify({"error": "Sin carrera asignada."}), 400

        cursor.execute("""
            SELECT m.clave, m.nombre, m.semestre, m.creditos, m.tipo, k.estatus, k.calificacion, g.horario, p.nombre as profesor 
            FROM kardex k 
            JOIN materias m ON k.id_materia = m.id_materia 
            LEFT JOIN grupos g ON k.id_grupo = g.id_grupo
            LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario
            WHERE k.id_alumno = %s ORDER BY m.semestre ASC
        """, (id_alumno,))
        historial = cursor.fetchall()

        creditos_aprobados = sum(m['creditos'] for m in historial if m['estatus'] == 'Aprobada')
        porcentaje = (creditos_aprobados / carrera['creditos_totales']) * 100 if carrera['creditos_totales'] > 0 else 0
        
        return jsonify({
            "carrera": carrera['nombre'], "creditos_totales": carrera['creditos_totales'],
            "creditos_aprobados": creditos_aprobados, "porcentaje_avance": round(porcentaje, 1),
            "servicio_liberado": any(m['tipo'] == 'Servicio_Social' and m['estatus'] == 'Aprobada' for m in historial),
            "residencia_liberada": any(m['tipo'] == 'Residencia' and m['estatus'] == 'Aprobada' for m in historial),
            "historial": historial
        }), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# ==========================================
# RUTAS DE LA COORDINADORA
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
            cursor.execute("""
                INSERT INTO grupos (id_materia, id_profesor, nombre_grupo, horario, aula) 
                VALUES (%s, %s, %s, %s, %s)
            """, (data['id_materia'], data['id_profesor'], data['nombre_grupo'], data['horario'], data['aula']))
            conn.commit()
            return jsonify({"mensaje": "Grupo creado exitosamente"}), 201
        elif request.method == 'GET':
            cursor.execute("""
                SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.nombre as materia, m.semestre, p.nombre as profesor 
                FROM grupos g
                JOIN materias m ON g.id_materia = m.id_materia
                LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario
                WHERE m.id_carrera = %s
                ORDER BY m.semestre ASC
            """, (id_carrera,))
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
        cursor.execute("""
            SELECT u.id_usuario, u.matricula, u.nombre, u.perfil_completo 
            FROM usuarios u 
            WHERE u.rol = 'alumno' AND u.bloqueado = 0 AND u.id_carrera = %s
            ORDER BY u.nombre ASC
        """, (id_carrera,))
        return jsonify(cursor.fetchall()), 200
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/coordinador/grupos_disponibles/<int:id_alumno>', methods=['GET'])
def grupos_disponibles(id_alumno):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        sql = """
            SELECT g.id_grupo, g.nombre_grupo, g.horario, g.aula, m.id_materia, m.nombre as materia, m.semestre, p.nombre as profesor 
            FROM grupos g 
            JOIN materias m ON g.id_materia = m.id_materia 
            LEFT JOIN usuarios p ON g.id_profesor = p.id_usuario
            JOIN usuarios u ON m.id_carrera = u.id_carrera
            WHERE u.id_usuario = %s 
              AND m.id_materia NOT IN (
                  SELECT id_materia FROM kardex WHERE id_alumno = %s AND estatus IN ('Aprobada', 'Cursando')
              )
            ORDER BY m.semestre ASC
        """
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
        cursor.execute("INSERT INTO kardex (id_alumno, id_materia, id_grupo, estatus) VALUES (%s, %s, %s, 'Cursando')", 
                       (data['id_alumno'], data['id_materia'], data['id_grupo']))
        conn.commit()
        return jsonify({"mensaje": "Materia inscrita exitosamente al alumno en el grupo seleccionado"}), 201
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

if __name__ == '__main__':
    print("🛡️ Backend de Campus Security v1.0 Iniciado y conectado a AWS TiDB Cloud")
    app.run(debug=True, port=5000)