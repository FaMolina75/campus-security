"""
SECURITYCAMPUS V2
========================================================

Backend institucional Flask + TiDB Cloud.

MÓDULOS:
- Autenticación y sesiones persistentes
- CAPTCHA de un solo uso
- Protección CSRF
- Recuperación de contraseñas
- Brevo
- Administración
- Coordinación académica
- Portal docente
- Portal estudiantil
- Auditoría
- Control de inactividad

REQUISITOS DE SEGURIDAD:
- HTTPS obligatorio en producción
- SECRET_KEY configurada
- Cookies seguras
- Consultas parametrizadas
- Permisos verificados en el servidor
- Contraseñas almacenadas mediante hash
- Sesiones revocables

NOTA:
Este archivo define el contrato de SecurityCampus V2.

Requiere el esquema TiDB V2 correspondiente.
No crea ni modifica tablas automáticamente.
========================================================
"""

import os
import re
import hmac
import html
import json
import time
import secrets
import hashlib
import logging
import ipaddress

from datetime import datetime, timedelta, timezone
from functools import wraps
from contextlib import contextmanager

import requests
import mysql.connector

from flask import (
    Flask,
    request,
    jsonify,
    session,
    g,
    make_response
)

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.middleware.proxy_fix import ProxyFix


# ========================================================
# 1. CONFIGURACIÓN
# ========================================================

ENVIRONMENT = os.getenv(
    "APP_ENV",
    "development"
).lower()

PRODUCTION = ENVIRONMENT == "production"

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "").strip()
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "").strip()
RECAPTCHA_ALLOWED_HOSTNAMES = {h.strip().lower() for h in os.getenv("RECAPTCHA_ALLOWED_HOSTNAMES", "").split(",") if h.strip()}

if PRODUCTION and len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY debe contener al menos 32 caracteres "
        "en producción."
    )

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,

    SESSION_COOKIE_NAME="scv2_csrf",

    SESSION_COOKIE_HTTPONLY=True,

    SESSION_COOKIE_SECURE=PRODUCTION,

    SESSION_COOKIE_SAMESITE="Lax",

    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),

    MAX_CONTENT_LENGTH=1024 * 1024
)

# Activar ProxyFix solo si Render u otro proxy
# confiable termina TLS y controla estos encabezados.
if PRODUCTION:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1
    )

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("SecurityCampusV2")


# ========================================================
# 2. CORS
# ========================================================

FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        ""
    ).split(",")
    if origin.strip()
]

if FRONTEND_ORIGINS:
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": FRONTEND_ORIGINS
            }
        },
        supports_credentials=True,
        allow_headers=[
            "Content-Type",
            "X-CSRF-Token"
        ],
        methods=[
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ]
    )

# Recomendación de despliegue:
# usar un mismo origen público para frontend y API.
#
# Si frontend y API están en sitios diferentes,
# será necesario adaptar SameSite y probar
# las restricciones de cookies del navegador.


# ========================================================
# 3. LIMITADOR
# ========================================================

LIMITER_STORAGE = os.getenv(
    "RATELIMIT_STORAGE_URI",
    "memory://"
)

if PRODUCTION and LIMITER_STORAGE == "memory://":
    raise RuntimeError(
        "Configura RATELIMIT_STORAGE_URI con Redis "
        "antes de ejecutar en producción."
    )

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[
        "300 per hour"
    ],
    storage_uri=LIMITER_STORAGE
)


# ========================================================
# 4. TIDB CLOUD
# ========================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),

    "database": os.getenv(
        "DB_NAME",
        "campus_security_v2"
    ),

    "port": int(
        os.getenv("DB_PORT", "4000")
    ),

    "connection_timeout": 10,
    "ssl_disabled": False
}

if os.getenv("DB_SSL_CA"):
    DB_CONFIG["ssl_ca"] = os.getenv("DB_SSL_CA")


def conectar_db():
    required = [
        "host",
        "user",
        "password",
        "database"
    ]

    faltantes = [
        campo
        for campo in required
        if not DB_CONFIG.get(campo)
    ]

    if faltantes:
        raise RuntimeError(
            "Configuración TiDB incompleta: "
            + ", ".join(faltantes)
        )

    return mysql.connector.connect(**DB_CONFIG)


@contextmanager
def db_cursor(dictionary=True):
    conexion = None
    cursor = None

    try:
        conexion = conectar_db()

        cursor = conexion.cursor(
            dictionary=dictionary
        )

        yield conexion, cursor

    except Exception:
        if conexion is not None:
            conexion.rollback()

        raise

    finally:
        if cursor is not None:
            cursor.close()

        if conexion is not None:
            conexion.close()


def consultar_uno(sql, parametros=()):
    with db_cursor() as (_, cursor):
        cursor.execute(sql, parametros)
        return cursor.fetchone()


def consultar_todos(sql, parametros=()):
    with db_cursor() as (_, cursor):
        cursor.execute(sql, parametros)
        return cursor.fetchall()


def ejecutar(sql, parametros=()):
    with db_cursor() as (conexion, cursor):
        cursor.execute(sql, parametros)

        afectados = cursor.rowcount
        ultimo_id = cursor.lastrowid

        conexion.commit()

        return afectados, ultimo_id


# ========================================================
# 5. UTILIDADES
# ========================================================

ROLES = {
    "admin",
    "coordinadora",
    "profesor",
    "alumno"
}

SESSION_COOKIE = "scv2_session"

SESSION_IDLE_SECONDS = 120

SESSION_ABSOLUTE_HOURS = 8

CALIFICACION_APROBATORIA = int(
    os.getenv(
        "CALIFICACION_APROBATORIA",
        "70"
    )
)

EMAIL_SISTEMA = os.getenv(
    "EMAIL_SISTEMA",
    ""
)

EMAIL_SOPORTE = os.getenv(
    "EMAIL_SOPORTE",
    EMAIL_SISTEMA
)


def utc_now():
    return datetime.now(timezone.utc)


def db_now():
    # Las fechas de la base deben manejarse en UTC.
    return utc_now().replace(tzinfo=None)


def json_body():
    data = request.get_json(silent=True)

    return data if isinstance(data, dict) else {}


def error_json(mensaje, codigo=400):
    return jsonify({
        "error": mensaje
    }), codigo


def validar_email(valor):
    return (
            isinstance(valor, str)
            and len(valor) <= 254
            and re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        valor
    ) is not None
    )


def normalizar_email(valor):
    return str(valor or "").strip().lower()


def password_valida(valor):
    return (
            isinstance(valor, str)
            and 12 <= len(valor) <= 128
    )


def entero_positivo(valor):
    try:
        numero = int(valor)

        if isinstance(valor, bool) or numero <= 0:
            return None

        return numero

    except (TypeError, ValueError):
        return None


def sha256(valor):
    return hashlib.sha256(
        valor.encode("utf-8")
    ).hexdigest()


def ip_cliente():
    return request.remote_addr or "0.0.0.0"


def usuario_publico(usuario):
    campos = [
        "id_usuario",
        "matricula",
        "nombre",
        "correo",
        "rol",
        "id_carrera",
        "semestre_actual",
        "perfil_completo",
        "correo_verificado",
        "bloqueado"
    ]

    return {
        campo: usuario.get(campo)
        for campo in campos
    }


def json_safe(valor):
    return json.dumps(
        valor,
        ensure_ascii=False,
        default=str
    )


# ========================================================
# 6. ENCABEZADOS DE SEGURIDAD
# ========================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Cache-Control"] = "no-store"

    if PRODUCTION:
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000"

    return response


# ========================================================
# 7. CSRF
# ========================================================

def obtener_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


@app.get("/api/auth/csrf")
@limiter.limit("60 per minute")
def csrf_endpoint():
    return jsonify({
        "csrf_token": obtener_csrf()
    })


@app.before_request
def verificar_csrf():
    if not request.path.startswith("/api/"):
        return None

    if request.method in {
        "GET",
        "HEAD",
        "OPTIONS"
    }:
        return None

    enviado = request.headers.get(
        "X-CSRF-Token",
        ""
    )

    esperado = session.get(
        "csrf_token",
        ""
    )

    if (
            not enviado
            or not esperado
            or not hmac.compare_digest(
        enviado,
        esperado
    )
    ):
        return error_json(
            "Token CSRF inválido",
            403
        )

    # Defensa adicional frente a solicitudes de otros orígenes.
    origen = request.headers.get("Origin")

    if origen:
        permitidos = set(FRONTEND_ORIGINS)

        permitidos.add(
            request.host_url.rstrip("/")
        )

        if origen.rstrip("/") not in permitidos:
            return error_json(
                "Origen no autorizado",
                403
            )

    return None


# ========================================================
# 8. SESIONES PERSISTENTES
# ========================================================

def crear_sesion(usuario):
    token = secrets.token_urlsafe(48)

    ahora = db_now()

    expiracion = ahora + timedelta(
        hours=SESSION_ABSOLUTE_HOURS
    )

    ejecutar(
        """
        INSERT INTO sesiones_usuario (
            id_usuario,
            token_hash,
            ip_origen,
            user_agent,
            fecha_creacion,
            ultima_actividad,
            fecha_expiracion,
            revocada
        )
        VALUES (
                   %s, %s, %s, %s,
                   %s, %s, %s, 0
               )
        """,
        (
            usuario["id_usuario"],
            sha256(token),
            ip_cliente(),
            request.headers.get(
                "User-Agent",
                ""
            )[:255],
            ahora,
            ahora,
            expiracion
        )
    )

    return token


def revocar_token(token):
    if not token:
        return

    ejecutar(
        """
        UPDATE sesiones_usuario
        SET revocada = 1,
            fecha_revocacion = UTC_TIMESTAMP()
        WHERE token_hash = %s
        """,
        (sha256(token),)
    )


def cargar_usuario_sesion():
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not token:
        return None

    registro = consultar_uno(
        """
        SELECT
            s.id_sesion,
            s.ultima_actividad,
            s.fecha_expiracion,
            u.*
        FROM sesiones_usuario s
                 JOIN usuarios u
                      ON u.id_usuario = s.id_usuario
        WHERE s.token_hash = %s
          AND s.revocada = 0
            LIMIT 1
        """,
        (sha256(token),)
    )

    if not registro:
        return None

    ahora = db_now()

    ultima = registro["ultima_actividad"]
    expiracion = registro["fecha_expiracion"]

    inactiva = (
                       ahora - ultima
               ).total_seconds() > SESSION_IDLE_SECONDS

    expirada = ahora >= expiracion

    if (
            inactiva
            or expirada
            or registro.get("bloqueado")
            or not registro.get("correo_verificado")
    ):
        revocar_token(token)
        return None

    ejecutar(
        """
        UPDATE sesiones_usuario
        SET ultima_actividad = %s
        WHERE id_sesion = %s
          AND revocada = 0
        """,
        (
            ahora,
            registro["id_sesion"]
        )
    )

    return registro


def requiere_rol(*roles):
    def decorador(funcion):
        @wraps(funcion)
        def protegido(*args, **kwargs):
            usuario = cargar_usuario_sesion()

            if not usuario:
                return error_json(
                    "Sesión no válida o expirada",
                    401
                )

            if roles and usuario["rol"] not in roles:
                return error_json(
                    "No tienes permisos para esta operación",
                    403
                )

            g.usuario = usuario

            return funcion(*args, **kwargs)

        return protegido

    return decorador


def cookie_sesion(response, token):
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=PRODUCTION,
        samesite="Lax",
        path="/",
        max_age=SESSION_ABSOLUTE_HOURS * 3600
    )

    return response


# ========================================================
# 9. AUDITORÍA
# ========================================================

def auditar(
        accion,
        detalles="",
        usuario=None
):
    try:
        if usuario is None:
            usuario = getattr(
                g,
                "usuario",
                None
            )

        ejecutar(
            """
            INSERT INTO auditoria_operaciones (
                id_usuario,
                usuario,
                rol,
                accion,
                detalles,
                ip_origen
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                usuario.get("id_usuario") if usuario else None,
                usuario.get("correo") if usuario else "sistema",
                usuario.get("rol") if usuario else "sistema",
                accion,
                str(detalles)[:3000],
                ip_cliente()
            )
        )

    except Exception:
        logger.exception(
            "No se pudo registrar auditoría"
        )


def registrar_acceso(correo, exitoso, motivo):
    try:
        ejecutar(
            """
            INSERT INTO seguridad_accesos (
                correo_intentado,
                ip_origen,
                exitoso,
                motivo,
                user_agent
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                correo,
                ip_cliente(),
                int(exitoso),
                motivo,
                request.headers.get(
                    "User-Agent",
                    ""
                )[:255]
            )
        )

    except Exception:
        logger.exception(
            "Error registrando acceso"
        )


# ========================================================
# 10. BREVO
# ========================================================

def enviar_correo(
        destinatario,
        nombre,
        asunto,
        contenido,
        reply_to=None
):
    api_key = os.getenv(
        "BREVO_API_KEY",
        ""
    )

    if not api_key or not EMAIL_SISTEMA:
        logger.error(
            "Configuración de Brevo incompleta"
        )
        return False

    payload = {
        "sender": {
            "name": "SecurityCampus",
            "email": EMAIL_SISTEMA
        },
        "to": [
            {
                "email": destinatario,
                "name": nombre
            }
        ],
        "subject": asunto,
        "htmlContent": contenido
    }

    if reply_to:
        payload["replyTo"] = reply_to

    try:
        respuesta = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            json=payload,
            timeout=15
        )

        return respuesta.status_code in {
            200,
            201,
            202
        }

    except requests.RequestException:
        logger.exception(
            "Error enviando correo con Brevo"
        )
        return False


# ========================================================
# 11. HEALTH
# ========================================================

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "SecurityCampus",
        "version": "2.0"
    })


# ========================================================
# 12. CAPTCHA
# ========================================================

@app.get("/api/auth/captcha")
@limiter.limit("20 per minute")
def generar_captcha():
    codigo = "".join(
        secrets.choice(
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        )
        for _ in range(5)
    )

    identificador = secrets.token_urlsafe(24)

    # Hash vinculado al identificador.
    respuesta_hash = hmac.new(
        SECRET_KEY.encode(),
        (
                identificador + ":" + codigo
        ).encode(),
        hashlib.sha256
    ).hexdigest()

    ejecutar(
        """
        INSERT INTO desafios_captcha (
            identificador_hash,
            respuesta_hash,
            intentos,
            fecha_creacion,
            fecha_expiracion,
            utilizado
        )
        VALUES (
                   %s, %s, 0,
                   UTC_TIMESTAMP(),
                   DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE),
                   0
               )
        """,
        (
            sha256(identificador),
            respuesta_hash
        )
    )

    return jsonify({
        "captcha_id": identificador,
        "captcha_code": codigo
    })


def validar_captcha(identificador, respuesta):
    if not isinstance(identificador, str):
        return False

    if not isinstance(respuesta, str):
        return False

    respuesta = respuesta.strip().upper()

    if not re.fullmatch(
            r"[A-Z2-9]{5}",
            respuesta
    ):
        return False

    # Consumo atómico: solo una solicitud puede utilizarlo.
    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """
            SELECT
                respuesta_hash,
                intentos,
                fecha_expiracion,
                utilizado
            FROM desafios_captcha
            WHERE identificador_hash = %s
                FOR UPDATE
            """,
            (sha256(identificador),)
        )

        desafio = cursor.fetchone()

        if not desafio:
            return False

        if (
                desafio["utilizado"]
                or desafio["intentos"] >= 3
                or db_now() >= desafio["fecha_expiracion"]
        ):
            return False

        esperado = hmac.new(
            SECRET_KEY.encode(),
            (
                    identificador + ":" + respuesta
            ).encode(),
            hashlib.sha256
        ).hexdigest()

        correcto = hmac.compare_digest(
            esperado,
            desafio["respuesta_hash"]
        )

        cursor.execute(
            """
            UPDATE desafios_captcha
            SET intentos = intentos + 1,
                utilizado = %s
            WHERE identificador_hash = %s
            """,
            (
                int(correcto),
                sha256(identificador)
            )
        )

        conexion.commit()

        return correcto



@app.get("/api/auth/recaptcha-config")
def recaptcha_config():
    if not RECAPTCHA_SITE_KEY or not RECAPTCHA_SECRET_KEY:
        return error_json("Google reCAPTCHA no está configurado", 503)
    return jsonify({"site_key": RECAPTCHA_SITE_KEY})


def verificar_recaptcha(token):
    if not RECAPTCHA_SECRET_KEY or not RECAPTCHA_ALLOWED_HOSTNAMES:
        return False
    if not isinstance(token, str) or not 1 <= len(token) <= 4096:
        return False
    try:
        respuesta = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": token, "remoteip": ip_cliente()},
            timeout=8
        )
        respuesta.raise_for_status()
        datos = respuesta.json()
        if not isinstance(datos, dict) or datos.get("success") is not True:
            return False
        hostname = datos.get("hostname")
        if not isinstance(hostname, str) or hostname.lower() not in RECAPTCHA_ALLOWED_HOSTNAMES:
            return False
        # Un desafío antiguo o con fecha inválida no debe autorizar un formulario.
        challenge_ts = datos.get("challenge_ts")
        if not isinstance(challenge_ts, str):
            return False
        try:
            fecha = datetime.fromisoformat(challenge_ts.replace("Z", "+00:00"))
            if fecha.tzinfo is None:
                return False
            edad = (datetime.now(timezone.utc) - fecha).total_seconds()
            return -30 <= edad <= 120
        except ValueError:
            return False
    except (requests.RequestException, ValueError):
        logger.warning("No se pudo validar reCAPTCHA")
        return False


@app.get("/api/auth/carreras")
@limiter.limit("30 per minute")
def carreras_publicas():
    # Solo se publican los campos necesarios para el registro.
    carreras = consultar_todos("SELECT id_carrera, nombre FROM carreras ORDER BY nombre")
    return jsonify({"carreras": carreras})


@app.post("/api/auth/registro-alumno")
@limiter.limit("3 per 15 minutes")
def registro_alumno():
    data = json_body()
    nombre = str(data.get("nombre") or "").strip()
    correo = normalizar_email(data.get("correo"))
    password = data.get("password")
    id_carrera = entero_positivo(data.get("id_carrera"))
    if not 3 <= len(nombre) <= 120 or not validar_email(correo):
        return error_json("Nombre o correo inválido")
    if not password_valida(password) or not id_carrera:
        return error_json("Contraseña o carrera inválida")
    if not verificar_recaptcha(data.get("recaptcha_token")):
        return error_json("Verificación de seguridad inválida", 403)
    carrera = consultar_uno("SELECT id_carrera FROM carreras WHERE id_carrera = %s LIMIT 1", (id_carrera,))
    if not carrera:
        return error_json("Carrera no disponible", 400)
    matricula = "SC" + utc_now().strftime("%y%m%d") + secrets.token_hex(4).upper()
    password_hash = generate_password_hash(password, method="scrypt")
    try:
        _, id_usuario = ejecutar(
            """INSERT INTO usuarios
               (matricula, nombre, correo, password, rol, id_carrera,
                semestre_actual, bloqueado, correo_verificado)
               VALUES (%s, %s, %s, %s, 'alumno', %s, 1, 0, 0)""",
            (matricula, nombre, correo, password_hash, id_carrera)
        )
    except mysql.connector.IntegrityError:
        return error_json("No se pudo registrar: correo o matrícula duplicada", 409)
    auditar("REGISTRO_ALUMNO", f"Alumno {id_usuario}")
    return jsonify({
        "mensaje": "Cuenta creada. Solicita el código para verificar tu correo.",
        "matricula": matricula,
        "id_usuario": id_usuario
    }), 201


# ========================================================
# 13. LOGIN
# ========================================================

@app.post("/api/auth/login")
@limiter.limit("10 per minute")
def login():
    data = json_body()

    correo = normalizar_email(
        data.get("correo")
    )

    password = data.get("password")

    recaptcha_token = data.get("recaptcha_token")

    if (
            not validar_email(correo)
            or not isinstance(password, str)
    ):
        return error_json(
            "Credenciales inválidas",
            400
        )

    ip_bloqueada = consultar_uno(
        """
        SELECT id_bloqueo
        FROM ips_bloqueadas
        WHERE ip = %s
          AND activo = 1
          AND (
            fecha_expiracion IS NULL
                OR fecha_expiracion > UTC_TIMESTAMP()
            )
            LIMIT 1
        """,
        (ip_cliente(),)
    )

    if ip_bloqueada:
        return error_json(
            "Acceso bloqueado",
            403
        )

    if not verificar_recaptcha(recaptcha_token):
        registrar_acceso(correo, False, "RECAPTCHA_INVALIDO")
        return error_json("Verificación Google reCAPTCHA inválida", 403)

    usuario = consultar_uno(
        """
        SELECT *
        FROM usuarios
        WHERE correo = %s
            LIMIT 1
        """,
        (correo,)
    )

    password_hash = (
        usuario.get("password")
        if usuario
        else None
    )

    password_correcta = False

    if (
            isinstance(password_hash, str)
            and password_hash.startswith(
        ("scrypt:", "pbkdf2:")
    )
    ):
        password_correcta = check_password_hash(
            password_hash,
            password
        )

    if not usuario or not password_correcta:
        registrar_acceso(
            correo,
            False,
            "CREDENCIALES_INVALIDAS"
        )

        return error_json(
            "Credenciales inválidas",
            401
        )

    if usuario.get("bloqueado"):
        registrar_acceso(
            correo,
            False,
            "CUENTA_BLOQUEADA"
        )

        return error_json(
            "Cuenta bloqueada",
            403
        )

    if not usuario.get("correo_verificado"):
        registrar_acceso(
            correo,
            False,
            "CORREO_NO_VERIFICADO"
        )

        return error_json(
            "Debes verificar tu correo institucional",
            403
        )

    if usuario.get("rol") not in ROLES:
        return error_json(
            "Rol no autorizado",
            403
        )

    # Revoca la sesión anterior del navegador,
    # si existía.
    token_anterior = request.cookies.get(
        SESSION_COOKIE
    )

    if token_anterior:
        revocar_token(token_anterior)

    token = crear_sesion(usuario)

    # Rotación del contexto CSRF.
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)

    registrar_acceso(
        correo,
        True,
        "LOGIN_CORRECTO"
    )

    auditar(
        "LOGIN",
        "Inicio de sesión correcto",
        usuario
    )

    response = make_response(
        jsonify({
            "mensaje": "Bienvenido",
            "usuario": usuario_publico(usuario)
        }),
        200
    )

    return cookie_sesion(
        response,
        token
    )


# ========================================================
# 14. USUARIO AUTENTICADO
# ========================================================

@app.get("/api/auth/me")
@requiere_rol()
def auth_me():
    return jsonify({
        "usuario": usuario_publico(
            g.usuario
        )
    })


# ========================================================
# 15. LOGOUT
# ========================================================

@app.post("/api/auth/logout")
def logout():
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if token:
        revocar_token(token)

    session.clear()

    response = make_response(
        jsonify({
            "mensaje": "Sesión cerrada"
        })
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/"
    )

    response.delete_cookie(
        app.config["SESSION_COOKIE_NAME"],
        path="/"
    )

    return response


# ========================================================
# 16. RECUPERACIÓN DE CONTRASEÑA
# ========================================================

@app.post("/api/auth/recuperar-solicitar")
@limiter.limit("3 per 15 minutes")
def recuperar_solicitar():
    data = json_body()

    correo = normalizar_email(
        data.get("correo")
    )

    if not validar_email(correo):
        return error_json(
            "Correo inválido"
        )

    respuesta_generica = {
        "mensaje": (
            "Si existe una cuenta asociada, "
            "recibirás un código de recuperación."
        )
    }

    usuario = consultar_uno(
        """
        SELECT id_usuario, nombre
        FROM usuarios
        WHERE correo = %s
            LIMIT 1
        """,
        (correo,)
    )

    if not usuario:
        return jsonify(
            respuesta_generica
        )

    codigo = "".join(
        secrets.choice("0123456789")
        for _ in range(6)
    )

    codigo_hash = hmac.new(
        SECRET_KEY.encode(),
        (
                str(usuario["id_usuario"])
                + ":"
                + codigo
        ).encode(),
        hashlib.sha256
    ).hexdigest()

    ejecutar(
        """
        UPDATE tokens_recuperacion
        SET usado = 1
        WHERE id_usuario = %s
          AND usado = 0
        """,
        (usuario["id_usuario"],)
    )

    ejecutar(
        """
        INSERT INTO tokens_recuperacion (
            id_usuario,
            token_hash,
            intentos,
            usado,
            fecha_creacion,
            fecha_expiracion
        )
        VALUES (
                   %s, %s, 0, 0,
                   UTC_TIMESTAMP(),
                   DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)
               )
        """,
        (
            usuario["id_usuario"],
            codigo_hash
        )
    )

    nombre_seguro = html.escape(
        usuario["nombre"] or "Usuario"
    )

    contenido = f"""
    <div style="font-family:Arial,sans-serif">
        <h2>Recuperación de contraseña</h2>
        <p>Hola, {nombre_seguro}.</p>
        <p>Tu código temporal es:</p>
        <h1>{codigo}</h1>
        <p>Este código expira en 15 minutos.</p>
        <p>Si no solicitaste el cambio, ignora este mensaje.</p>
    </div>
    """

    enviado = enviar_correo(
        correo,
        usuario["nombre"],
        "Recuperación de contraseña",
        contenido
    )

    if not enviado:
        # No revela la existencia de la cuenta.
        logger.warning(
            "No fue posible entregar recuperación"
        )

    return jsonify(
        respuesta_generica
    )


@app.post("/api/auth/recuperar-cambiar")
@limiter.limit("5 per 15 minutes")
def recuperar_cambiar():
    data = json_body()

    correo = normalizar_email(
        data.get("correo")
    )

    codigo = data.get("token")

    password = data.get(
        "nueva_password"
    )

    if not validar_email(correo):
        return error_json(
            "Solicitud inválida"
        )

    if (
            not isinstance(codigo, str)
            or not re.fullmatch(
        r"\d{6}",
        codigo
    )
    ):
        return error_json(
            "Código inválido o expirado"
        )

    if not password_valida(password):
        return error_json(
            "La contraseña debe tener entre 12 y 128 caracteres"
        )

    usuario = consultar_uno(
        """
        SELECT id_usuario
        FROM usuarios
        WHERE correo = %s
        """,
        (correo,)
    )

    if not usuario:
        return error_json(
            "Código inválido o expirado"
        )

    codigo_hash = hmac.new(
        SECRET_KEY.encode(),
        (
                str(usuario["id_usuario"])
                + ":"
                + codigo
        ).encode(),
        hashlib.sha256
    ).hexdigest()

    nuevo_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    # Validación y consumo dentro de la misma transacción.
    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """
            SELECT
                id_token,
                token_hash,
                intentos,
                fecha_expiracion
            FROM tokens_recuperacion
            WHERE id_usuario = %s
              AND usado = 0
            ORDER BY id_token DESC
                LIMIT 1
            FOR UPDATE
            """,
            (usuario["id_usuario"],)
        )

        registro = cursor.fetchone()

        if not registro:
            return error_json(
                "Código inválido o expirado"
            )

        if (
                registro["intentos"] >= 5
                or db_now() >= registro["fecha_expiracion"]
        ):
            return error_json(
                "Código inválido o expirado"
            )

        correcto = hmac.compare_digest(
            codigo_hash,
            registro["token_hash"]
        )

        cursor.execute(
            """
            UPDATE tokens_recuperacion
            SET intentos = intentos + 1,
                usado = %s,
                fecha_uso = CASE
                                WHEN %s = 1 THEN UTC_TIMESTAMP()
                                ELSE fecha_uso
                    END
            WHERE id_token = %s
            """,
            (
                int(correcto),
                int(correcto),
                registro["id_token"]
            )
        )

        if not correcto:
            conexion.commit()

            return error_json(
                "Código inválido o expirado"
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET password = %s
            WHERE id_usuario = %s
            """,
            (
                nuevo_hash,
                usuario["id_usuario"]
            )
        )

        cursor.execute(
            """
            UPDATE sesiones_usuario
            SET revocada = 1,
                fecha_revocacion = UTC_TIMESTAMP()
            WHERE id_usuario = %s
              AND revocada = 0
            """,
            (usuario["id_usuario"],)
        )

        conexion.commit()

    auditar(
        "PASSWORD_RESET",
        "Restablecimiento de contraseña"
    )

    return jsonify({
        "mensaje": "Contraseña actualizada correctamente"
    })


# ========================================================
# 16 BIS. VERIFICACIÓN DE CORREO
# ========================================================

def hash_verificacion_correo(id_usuario, codigo):
    # Dominio separado de los códigos de recuperación de contraseña.
    mensaje = f"verificar-correo:{id_usuario}:{codigo}"
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        mensaje.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


@app.post("/api/auth/verificacion-solicitar")
@limiter.limit("3 per 15 minutes")
def verificacion_solicitar():
    correo = normalizar_email(json_body().get("correo"))
    if not validar_email(correo):
        return error_json("Correo inválido")

    respuesta = {"mensaje": (
        "Si la cuenta existe y está pendiente de verificación, "
        "recibirás un código en tu correo."
    )}
    usuario = consultar_uno(
        """SELECT id_usuario, nombre, correo_verificado, bloqueado
           FROM usuarios WHERE correo = %s LIMIT 1""",
        (correo,)
    )
    if not usuario or usuario["correo_verificado"] or usuario["bloqueado"]:
        return jsonify(respuesta)

    id_usuario = usuario["id_usuario"]
    codigo = "".join(secrets.choice("0123456789") for _ in range(6))
    codigo_hash = hash_verificacion_correo(id_usuario, codigo)

    # Invalidar códigos previos y registrar el nuevo en una sola transacción.
    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """UPDATE verificaciones_correo SET usado = 1
               WHERE id_usuario = %s AND usado = 0""",
            (id_usuario,)
        )
        cursor.execute(
            """INSERT INTO verificaciones_correo
               (id_usuario, codigo_hash, intentos, usado,
                fecha_creacion, fecha_expiracion)
               VALUES (%s, %s, 0, 0, UTC_TIMESTAMP(),
                       DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE))""",
            (id_usuario, codigo_hash)
        )
        conexion.commit()

    nombre = html.escape(usuario["nombre"] or "Usuario")
    contenido = (
        '<div style="font-family:Arial,sans-serif">'
        '<h2>Verificación de correo de SecurityCampus</h2>'
        f'<p>Hola, {nombre}.</p>'
        f'<p>Tu código de verificación es: <strong>{codigo}</strong></p>'
        '<p>Caduca en 15 minutos. Si no lo solicitaste, ignora este mensaje.</p>'
        '</div>'
    )
    if not enviar_correo(correo, usuario["nombre"],
                         "Verifica tu correo en SecurityCampus", contenido):
        logger.warning("No fue posible entregar código de verificación")

    return jsonify(respuesta)


@app.post("/api/auth/verificacion-confirmar")
@limiter.limit("5 per 15 minutes")
def verificacion_confirmar():
    data = json_body()
    correo = normalizar_email(data.get("correo"))
    codigo = data.get("codigo")
    error = "Código inválido o expirado"
    if not validar_email(correo) or not isinstance(codigo, str) or not re.fullmatch(r"\d{6}", codigo):
        return error_json(error)

    usuario = consultar_uno(
        """SELECT id_usuario FROM usuarios
           WHERE correo = %s AND bloqueado = 0
             AND correo_verificado = 0 LIMIT 1""",
        (correo,)
    )
    if not usuario:
        return error_json(error)

    id_usuario = usuario["id_usuario"]
    esperado = hash_verificacion_correo(id_usuario, codigo)
    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """SELECT id_verificacion, codigo_hash, intentos,
                      fecha_expiracion
               FROM verificaciones_correo
               WHERE id_usuario = %s AND usado = 0
               ORDER BY id_verificacion DESC LIMIT 1 FOR UPDATE""",
            (id_usuario,)
        )
        registro = cursor.fetchone()
        if not registro:
            return error_json(error)

        if registro["intentos"] >= 5 or db_now() >= registro["fecha_expiracion"]:
            cursor.execute(
                "UPDATE verificaciones_correo SET usado = 1 WHERE id_verificacion = %s",
                (registro["id_verificacion"],)
            )
            conexion.commit()
            return error_json(error)

        correcto = hmac.compare_digest(esperado, registro["codigo_hash"])
        cursor.execute(
            """UPDATE verificaciones_correo
               SET intentos = intentos + 1,
                   usado = %s,
                   fecha_verificacion = CASE WHEN %s = 1
                       THEN UTC_TIMESTAMP() ELSE fecha_verificacion END
               WHERE id_verificacion = %s""",
            (int(correcto or registro["intentos"] + 1 >= 5), int(correcto), registro["id_verificacion"])
        )
        if not correcto:
            conexion.commit()
            return error_json(error)

        cursor.execute(
            """UPDATE usuarios SET correo_verificado = 1
               WHERE id_usuario = %s AND bloqueado = 0
                 AND correo_verificado = 0""",
            (id_usuario,)
        )
        if cursor.rowcount != 1:
            conexion.rollback()
            return error_json(error)
        conexion.commit()

    auditar("CORREO_VERIFICADO", f"Verificación de correo usuario {id_usuario}")
    return jsonify({"mensaje": "Correo verificado correctamente. Ya puedes iniciar sesión."})


# ========================================================
# 17. ADMINISTRADOR
# ========================================================

@app.get("/api/admin/stats")
@requiere_rol("admin")
def admin_stats():
    return jsonify(
        consultar_uno(
            """
            SELECT
                    (SELECT COUNT(*) FROM usuarios) AS usuarios,
                    (SELECT COUNT(*) FROM materias) AS materias,
                    (
                        SELECT COUNT(*)
                        FROM seguridad_accesos
                        WHERE exitoso = 0
                    ) AS alertas
            """
        )
    )


@app.get("/api/admin/usuarios")
@requiere_rol("admin")
def admin_usuarios():
    return jsonify(
        consultar_todos(
            """
            SELECT
                u.id_usuario,
                u.matricula,
                u.nombre,
                u.correo,
                u.rol,
                u.id_carrera,
                u.bloqueado,
                u.correo_verificado,
                c.nombre AS carrera
            FROM usuarios u
                     LEFT JOIN carreras c
                               ON c.id_carrera = u.id_carrera
            ORDER BY u.id_usuario DESC
                LIMIT 500
            """
        )
    )


@app.post("/api/admin/usuarios")
@requiere_rol("admin")
def admin_crear_usuario():
    data = json_body()

    rol = data.get("rol")
    nombre = str(data.get("nombre") or "").strip()
    correo = normalizar_email(data.get("correo"))
    id_carrera = entero_positivo(data.get("id_carrera"))

    if rol not in ROLES:
        return error_json("Rol inválido")

    if not 3 <= len(nombre) <= 120:
        return error_json("Nombre inválido")

    if not validar_email(correo):
        return error_json("Correo inválido")

    if rol != "admin" and not id_carrera:
        return error_json("Carrera obligatoria")

    # Credencial temporal aleatoria.
    # No se devuelve al frontend.
    password_temporal = secrets.token_urlsafe(24)

    password_hash = generate_password_hash(
        password_temporal,
        method="scrypt"
    )

    matricula = (
            "SC"
            + utc_now().strftime("%y%m%d")
            + secrets.token_hex(4).upper()
    )

    try:
        _, id_usuario = ejecutar(
            """
            INSERT INTO usuarios (
                matricula,
                nombre,
                correo,
                password,
                rol,
                id_carrera,
                semestre_actual,
                bloqueado,
                correo_verificado
            )
            VALUES (
                       %s, %s, %s, %s, %s,
                       %s, %s, 0, 0
                   )
            """,
            (
                matricula,
                nombre,
                correo,
                password_hash,
                rol,
                id_carrera,
                1 if rol == "alumno" else 0
            )
        )

    except mysql.connector.IntegrityError:
        return error_json(
            "Correo o matrícula duplicada",
            409
        )

    auditar(
        "CREAR_USUARIO",
        f"Usuario {id_usuario}, rol {rol}"
    )

    return jsonify({
        "mensaje": (
            "Usuario creado. "
            "Debe completar la activación de su cuenta."
        ),
        "id_usuario": id_usuario,
        "matricula": matricula
    }), 201


@app.put("/api/admin/usuarios/<int:id_usuario>/bloquear")
@requiere_rol("admin")
def admin_bloquear_usuario(id_usuario):
    if id_usuario == g.usuario["id_usuario"]:
        return error_json(
            "No puedes bloquear tu propia cuenta"
        )

    afectados, _ = ejecutar(
        """
        UPDATE usuarios
        SET bloqueado = NOT bloqueado
        WHERE id_usuario = %s
        """,
        (id_usuario,)
    )

    if not afectados:
        return error_json(
            "Usuario no encontrado",
            404
        )

    ejecutar(
        """
        UPDATE sesiones_usuario
        SET revocada = 1,
            fecha_revocacion = UTC_TIMESTAMP()
        WHERE id_usuario = %s
          AND revocada = 0
        """,
        (id_usuario,)
    )

    auditar(
        "CAMBIAR_BLOQUEO",
        f"Usuario {id_usuario}"
    )

    return jsonify({
        "mensaje": "Estado actualizado"
    })


@app.get("/api/admin/carreras")
@requiere_rol("admin")
def admin_carreras():
    return jsonify(
        consultar_todos(
            """
            SELECT
                id_carrera,
                clave,
                nombre,
                duracion_semestres,
                creditos_totales
            FROM carreras
            ORDER BY nombre
            """
        )
    )


@app.post("/api/admin/carreras")
@requiere_rol("admin")
def admin_crear_carrera():
    data = json_body()

    clave = str(
        data.get("clave") or ""
    ).strip().upper()

    nombre = str(
        data.get("nombre") or ""
    ).strip()

    semestres = entero_positivo(
        data.get("duracion_semestres")
    )

    creditos = entero_positivo(
        data.get("creditos_totales")
    )

    if not (
            clave
            and nombre
            and semestres
            and creditos
    ):
        return error_json(
            "Datos de carrera inválidos"
        )

    _, id_carrera = ejecutar(
        """
        INSERT INTO carreras (
            clave,
            nombre,
            duracion_semestres,
            creditos_totales
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            clave,
            nombre,
            semestres,
            creditos
        )
    )

    auditar(
        "CREAR_CARRERA",
        f"Carrera {id_carrera}"
    )

    return jsonify({
        "mensaje": "Carrera creada",
        "id_carrera": id_carrera
    }), 201


@app.get("/api/admin/materias")
@requiere_rol("admin")
def admin_materias():
    return jsonify(
        consultar_todos(
            """
            SELECT
                m.id_materia,
                m.clave,
                m.nombre,
                m.semestre,
                m.creditos,
                m.tipo,
                c.nombre AS carrera
            FROM materias m
                     JOIN carreras c
                          ON c.id_carrera = m.id_carrera
            ORDER BY m.semestre, m.nombre
            """
        )
    )


@app.post("/api/admin/materias")
@requiere_rol("admin")
def admin_crear_materia():
    data = json_body()

    id_carrera = entero_positivo(
        data.get("id_carrera")
    )

    nombre = str(
        data.get("nombre") or ""
    ).strip()

    semestre = entero_positivo(
        data.get("semestre")
    )

    creditos = entero_positivo(
        data.get("creditos")
    )

    tipo = str(
        data.get("tipo") or "Normal"
    ).strip()

    if not all([
        id_carrera,
        nombre,
        semestre,
        creditos
    ]):
        return error_json(
            "Datos de materia inválidos"
        )

    clave = (
            "MAT-"
            + secrets.token_hex(4).upper()
    )

    _, id_materia = ejecutar(
        """
        INSERT INTO materias (
            id_carrera,
            clave,
            nombre,
            semestre,
            creditos,
            tipo
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            id_carrera,
            clave,
            nombre,
            semestre,
            creditos,
            tipo
        )
    )

    auditar(
        "CREAR_MATERIA",
        f"Materia {id_materia}"
    )

    return jsonify({
        "mensaje": "Materia creada",
        "id_materia": id_materia,
        "clave": clave
    }), 201


@app.get("/api/admin/auditoria/accesos")
@requiere_rol("admin")
def admin_auditoria_accesos():
    return jsonify(
        consultar_todos(
            """
            SELECT *
            FROM seguridad_accesos
            ORDER BY fecha_intento DESC
                LIMIT 200
            """
        )
    )


@app.get("/api/admin/auditoria/operaciones")
@requiere_rol("admin")
def admin_auditoria_operaciones():
    return jsonify(
        consultar_todos(
            """
            SELECT *
            FROM auditoria_operaciones
            ORDER BY fecha DESC
                LIMIT 300
            """
        )
    )


@app.post("/api/admin/ban_ip")
@requiere_rol("admin")
def admin_ban_ip():
    data = json_body()

    ip = str(
        data.get("ip") or ""
    ).strip()

    try:
        ipaddress.ip_address(ip)

    except ValueError:
        return error_json(
            "Dirección IP inválida"
        )

    ejecutar(
        """
        INSERT INTO ips_bloqueadas (
            ip,
            motivo,
            bloqueada_por,
            activo
        )
        VALUES (%s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                                 activo = 1,
                                 motivo = VALUES(motivo),
                                 bloqueada_por = VALUES(bloqueada_por)
        """,
        (
            ip,
            "Bloqueo administrativo",
            g.usuario["id_usuario"]
        )
    )

    auditar(
        "BAN_IP",
        ip
    )

    return jsonify({
        "mensaje": "IP bloqueada"
    })


# ========================================================
# 18. ALUMNO
# ========================================================

@app.get("/api/alumno/perfil")
@requiere_rol("alumno")
def alumno_perfil():
    return jsonify(
        consultar_uno(
            """
            SELECT
                id_usuario,
                matricula,
                nombre,
                correo,
                curp,
                telefono,
                direccion,
                perfil_completo,
                semestre_actual
            FROM usuarios
            WHERE id_usuario = %s
            """,
            (g.usuario["id_usuario"],)
        )
    )


@app.put("/api/alumno/perfil")
@requiere_rol("alumno")
def alumno_actualizar_perfil():
    data = json_body()

    curp = str(
        data.get("curp") or ""
    ).strip().upper()

    telefono = str(
        data.get("telefono") or ""
    ).strip()

    direccion = str(
        data.get("direccion") or ""
    ).strip()

    if not re.fullmatch(
            r"[A-ZÑ&]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d",
            curp
    ):
        return error_json(
            "Formato CURP inválido"
        )

    if not re.fullmatch(
            r"\d{10}",
            telefono
    ):
        return error_json(
            "El teléfono debe tener 10 dígitos"
        )

    if not 10 <= len(direccion) <= 300:
        return error_json(
            "Dirección inválida"
        )

    ejecutar(
        """
        UPDATE usuarios
        SET curp = %s,
            telefono = %s,
            direccion = %s,
            perfil_completo = 1
        WHERE id_usuario = %s
        """,
        (
            curp,
            telefono,
            direccion,
            g.usuario["id_usuario"]
        )
    )

    auditar(
        "ACTUALIZAR_PERFIL",
        "Actualización de expediente"
    )

    return jsonify({
        "mensaje": "Expediente actualizado"
    })


@app.put("/api/alumno/password")
@requiere_rol("alumno")
def alumno_password():
    data = json_body()

    actual = data.get(
        "password_actual"
    )

    nueva = data.get(
        "password_nueva"
    )

    if not password_valida(nueva):
        return error_json(
            "La nueva contraseña debe tener entre 12 y 128 caracteres"
        )

    usuario = consultar_uno(
        """
        SELECT password
        FROM usuarios
        WHERE id_usuario = %s
        """,
        (g.usuario["id_usuario"],)
    )

    if not check_password_hash(
            usuario["password"],
            actual or ""
    ):
        return error_json(
            "Contraseña actual incorrecta",
            403
        )

    ejecutar(
        """
        UPDATE usuarios
        SET password = %s
        WHERE id_usuario = %s
        """,
        (
            generate_password_hash(
                nueva,
                method="scrypt"
            ),
            g.usuario["id_usuario"]
        )
    )

    ejecutar(
        """
        UPDATE sesiones_usuario
        SET revocada = 1,
            fecha_revocacion = UTC_TIMESTAMP()
        WHERE id_usuario = %s
        """,
        (g.usuario["id_usuario"],)
    )

    auditar(
        "CAMBIO_PASSWORD",
        "Cambio voluntario de contraseña"
    )

    return jsonify({
        "mensaje": (
            "Contraseña actualizada. "
            "Inicia sesión nuevamente."
        )
    })


@app.get("/api/alumno/progreso")
@requiere_rol("alumno")
def alumno_progreso():
    id_alumno = g.usuario["id_usuario"]

    carrera = consultar_uno(
        """
        SELECT c.*
        FROM usuarios u
                 JOIN carreras c
                      ON c.id_carrera = u.id_carrera
        WHERE u.id_usuario = %s
        """,
        (id_alumno,)
    )

    if not carrera:
        return error_json(
            "Carrera no encontrada",
            404
        )

    historial = consultar_todos(
        """
        SELECT
            m.clave,
            m.nombre,
            m.semestre,
            m.creditos,
            m.tipo,
            k.estatus,
            k.calificacion,
            g.horario,
            p.nombre AS profesor
        FROM kardex k
                 JOIN materias m
                      ON m.id_materia = k.id_materia
                 LEFT JOIN grupos g
                           ON g.id_grupo = k.id_grupo
                 LEFT JOIN usuarios p
                           ON p.id_usuario = g.id_profesor
        WHERE k.id_alumno = %s
        ORDER BY m.semestre, m.nombre
        """,
        (id_alumno,)
    )

    # Una materia aprobada cuenta una sola vez.
    materias_aprobadas = {}

    for materia in historial:
        if materia["estatus"] == "Aprobada":
            materias_aprobadas[
                materia["clave"]
            ] = materia["creditos"] or 0

    creditos_aprobados = sum(
        materias_aprobadas.values()
    )

    creditos_totales = (
            carrera["creditos_totales"] or 0
    )

    porcentaje = (
        round(
            creditos_aprobados
            / creditos_totales
            * 100,
            1
        )
        if creditos_totales
        else 0
    )

    return jsonify({
        "carrera": carrera["nombre"],
        "creditos_aprobados": creditos_aprobados,
        "creditos_totales": creditos_totales,
        "porcentaje_avance": min(porcentaje, 100),
        "servicio_liberado": any(
            m["tipo"] == "Servicio_Social"
            and m["estatus"] == "Aprobada"
            for m in historial
        ),
        "residencia_liberada": any(
            m["tipo"] == "Residencia"
            and m["estatus"] == "Aprobada"
            for m in historial
        ),
        "historial": historial
    })


# ========================================================
# 19. COORDINADORA
# ========================================================

def carrera_coordinadora():
    return g.usuario["id_carrera"]


@app.get("/api/coordinador/profesores")
@requiere_rol("coordinadora")
def coordinador_profesores():
    return jsonify(
        consultar_todos(
            """
            SELECT id_usuario, nombre
            FROM usuarios
            WHERE rol = 'profesor'
              AND bloqueado = 0
              AND id_carrera = %s
            ORDER BY nombre
            """,
            (carrera_coordinadora(),)
        )
    )


@app.get("/api/coordinador/materias_carrera")
@requiere_rol("coordinadora")
def coordinador_materias():
    return jsonify(
        consultar_todos(
            """
            SELECT
                id_materia,
                clave,
                nombre,
                semestre
            FROM materias
            WHERE id_carrera = %s
              AND activo = 1
            ORDER BY semestre, nombre
            """,
            (carrera_coordinadora(),)
        )
    )


@app.get("/api/coordinador/alumnos")
@requiere_rol("coordinadora")
def coordinador_alumnos():
    return jsonify(
        consultar_todos(
            """
            SELECT
                id_usuario,
                matricula,
                nombre,
                perfil_completo,
                semestre_actual
            FROM usuarios
            WHERE rol = 'alumno'
              AND bloqueado = 0
              AND id_carrera = %s
            ORDER BY nombre
            """,
            (carrera_coordinadora(),)
        )
    )


@app.get("/api/coordinador/grupos")
@requiere_rol("coordinadora")
def coordinador_grupos():
    return jsonify(
        consultar_todos(
            """
            SELECT
                g.id_grupo,
                g.nombre_grupo,
                g.horario,
                g.aula,
                g.cupo,
                m.id_materia,
                m.nombre AS materia,
                m.semestre,
                p.nombre AS profesor
            FROM grupos g
                     JOIN materias m
                          ON m.id_materia = g.id_materia
                     LEFT JOIN usuarios p
                               ON p.id_usuario = g.id_profesor
            WHERE m.id_carrera = %s
              AND g.activo = 1
            ORDER BY m.semestre, m.nombre
            """,
            (carrera_coordinadora(),)
        )
    )


@app.post("/api/coordinador/grupos")
@requiere_rol("coordinadora")
def coordinador_crear_grupo():
    data = json_body()

    id_materia = entero_positivo(
        data.get("id_materia")
    )

    id_profesor = entero_positivo(
        data.get("id_profesor")
    )

    nombre = str(
        data.get("nombre_grupo") or ""
    ).strip()

    horario = str(
        data.get("horario") or ""
    ).strip()

    aula = str(
        data.get("aula") or ""
    ).strip()

    cupo = entero_positivo(
        data.get("cupo")
    )

    if not all([
        id_materia,
        id_profesor,
        nombre,
        horario,
        aula,
        cupo
    ]):
        return error_json(
            "Datos del grupo incompletos"
        )

    materia = consultar_uno(
        """
        SELECT id_materia
        FROM materias
        WHERE id_materia = %s
          AND id_carrera = %s
          AND activo = 1
        """,
        (
            id_materia,
            carrera_coordinadora()
        )
    )

    profesor = consultar_uno(
        """
        SELECT id_usuario
        FROM usuarios
        WHERE id_usuario = %s
          AND id_carrera = %s
          AND rol = 'profesor'
          AND bloqueado = 0
        """,
        (
            id_profesor,
            carrera_coordinadora()
        )
    )

    if not materia or not profesor:
        return error_json(
            "Materia o profesor fuera de tu carrera",
            403
        )

    _, id_grupo = ejecutar(
        """
        INSERT INTO grupos (
            id_materia,
            id_profesor,
            nombre_grupo,
            horario,
            aula,
            cupo,
            activo
        )
        VALUES (%s, %s, %s, %s, %s, %s, 1)
        """,
        (
            id_materia,
            id_profesor,
            nombre,
            horario,
            aula,
            cupo
        )
    )

    auditar(
        "CREAR_GRUPO",
        f"Grupo {id_grupo}"
    )

    return jsonify({
        "mensaje": "Grupo creado",
        "id_grupo": id_grupo
    }), 201


@app.get(
    "/api/coordinador/grupos_disponibles/<int:id_alumno>"
)
@requiere_rol("coordinadora")
def coordinador_disponibles(id_alumno):
    alumno = consultar_uno(
        """
        SELECT id_usuario
        FROM usuarios
        WHERE id_usuario = %s
          AND id_carrera = %s
          AND rol = 'alumno'
        """,
        (
            id_alumno,
            carrera_coordinadora()
        )
    )

    if not alumno:
        return error_json(
            "Alumno fuera de tu carrera",
            403
        )

    return jsonify(
        consultar_todos(
            """
            SELECT
                g.id_grupo,
                g.nombre_grupo,
                g.horario,
                g.aula,
                g.cupo,
                m.id_materia,
                m.nombre AS materia,
                m.semestre,
                p.nombre AS profesor
            FROM grupos g
                     JOIN materias m
                          ON m.id_materia = g.id_materia
                     JOIN usuarios p
                          ON p.id_usuario = g.id_profesor
            WHERE m.id_carrera = %s
              AND g.activo = 1
              AND m.id_materia NOT IN (
                SELECT k.id_materia
                FROM kardex k
                WHERE k.id_alumno = %s
                  AND k.estatus IN (
                                    'Cursando',
                                    'Aprobada'
                    )
            )
            ORDER BY m.semestre
            """,
            (
                carrera_coordinadora(),
                id_alumno
            )
        )
    )


@app.post("/api/coordinador/inscribir")
@requiere_rol("coordinadora")
def coordinador_inscribir():
    data = json_body()

    id_alumno = entero_positivo(
        data.get("id_alumno")
    )

    id_grupo = entero_positivo(
        data.get("id_grupo")
    )

    if not id_alumno or not id_grupo:
        return error_json(
            "Alumno y grupo obligatorios"
        )

    # La comprobación de cupo e inscripción se hace
    # dentro de una transacción.
    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """
            SELECT id_usuario
            FROM usuarios
            WHERE id_usuario = %s
              AND id_carrera = %s
              AND rol = 'alumno'
              AND bloqueado = 0
            """,
            (
                id_alumno,
                carrera_coordinadora()
            )
        )

        if not cursor.fetchone():
            return error_json(
                "Alumno no autorizado",
                403
            )

        cursor.execute(
            """
            SELECT
                g.id_grupo,
                g.id_materia,
                g.cupo
            FROM grupos g
                     JOIN materias m
                          ON m.id_materia = g.id_materia
            WHERE g.id_grupo = %s
              AND m.id_carrera = %s
              AND g.activo = 1
                FOR UPDATE
            """,
            (
                id_grupo,
                carrera_coordinadora()
            )
        )

        grupo = cursor.fetchone()

        if not grupo:
            return error_json(
                "Grupo no autorizado",
                403
            )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM kardex
            WHERE id_grupo = %s
              AND estatus = 'Cursando'
            """,
            (id_grupo,)
        )

        inscritos = cursor.fetchone()["total"]

        if inscritos >= grupo["cupo"]:
            return error_json(
                "El grupo está lleno",
                409
            )

        cursor.execute(
            """
            SELECT id_kardex
            FROM kardex
            WHERE id_alumno = %s
              AND id_materia = %s
              AND estatus IN ('Cursando', 'Aprobada')
                LIMIT 1
            """,
            (
                id_alumno,
                grupo["id_materia"]
            )
        )

        if cursor.fetchone():
            return error_json(
                "El alumno ya cursa o aprobó la materia",
                409
            )

        cursor.execute(
            """
            INSERT INTO kardex (
                id_alumno,
                id_materia,
                id_grupo,
                estatus
            )
            VALUES (%s, %s, %s, 'Cursando')
            """,
            (
                id_alumno,
                grupo["id_materia"],
                id_grupo
            )
        )

        conexion.commit()

    auditar(
        "INSCRIBIR_ALUMNO",
        f"Alumno {id_alumno}, grupo {id_grupo}"
    )

    return jsonify({
        "mensaje": "Alumno inscrito correctamente"
    }), 201


# ========================================================
# 20. PROFESOR
# ========================================================

@app.get("/api/profesor/grupos")
@requiere_rol("profesor")
def profesor_grupos():
    return jsonify(
        consultar_todos(
            """
            SELECT
                g.id_grupo,
                g.nombre_grupo,
                g.horario,
                g.aula,
                m.id_materia,
                m.clave AS clave_materia,
                m.nombre AS nombre_materia,
                m.semestre,
                c.nombre AS carrera
            FROM grupos g
                     JOIN materias m
                          ON m.id_materia = g.id_materia
                     JOIN carreras c
                          ON c.id_carrera = m.id_carrera
            WHERE g.id_profesor = %s
              AND g.activo = 1
            ORDER BY m.semestre, m.nombre
            """,
            (g.usuario["id_usuario"],)
        )
    )


@app.get(
    "/api/profesor/grupo/<int:id_grupo>/alumnos"
)
@requiere_rol("profesor")
def profesor_alumnos(id_grupo):
    grupo = consultar_uno(
        """
        SELECT id_grupo
        FROM grupos
        WHERE id_grupo = %s
          AND id_profesor = %s
          AND activo = 1
        """,
        (
            id_grupo,
            g.usuario["id_usuario"]
        )
    )

    if not grupo:
        return error_json(
            "Grupo no autorizado",
            403
        )

    return jsonify(
        consultar_todos(
            """
            SELECT
                k.id_kardex,
                u.matricula,
                u.nombre,
                k.calificacion,
                k.estatus
            FROM kardex k
                     JOIN usuarios u
                          ON u.id_usuario = k.id_alumno
            WHERE k.id_grupo = %s
            ORDER BY u.nombre
            """,
            (id_grupo,)
        )
    )


@app.post("/api/profesor/calificar")
@requiere_rol("profesor")
def profesor_calificar():
    data = json_body()

    id_kardex = entero_positivo(
        data.get("id_kardex")
    )

    calificacion = data.get(
        "calificacion"
    )

    if not id_kardex:
        return error_json(
            "Inscripción inválida"
        )

    if (
            isinstance(calificacion, bool)
            or not isinstance(calificacion, int)
            or not 0 <= calificacion <= 100
    ):
        return error_json(
            "La calificación debe ser un entero entre 0 y 100"
        )

    estatus = (
        "Aprobada"
        if calificacion >= CALIFICACION_APROBATORIA
        else "Reprobada"
    )

    with db_cursor() as (conexion, cursor):
        cursor.execute(
            """
            SELECT
                k.id_kardex,
                k.estatus
            FROM kardex k
                     JOIN grupos g
                          ON g.id_grupo = k.id_grupo
            WHERE k.id_kardex = %s
              AND g.id_profesor = %s
              AND g.activo = 1
                FOR UPDATE
            """,
            (
                id_kardex,
                g.usuario["id_usuario"]
            )
        )

        registro = cursor.fetchone()

        if not registro:
            return error_json(
                "No puedes calificar esta inscripción",
                403
            )

        if registro["estatus"] != "Cursando":
            return error_json(
                "La calificación ya está cerrada",
                409
            )

        cursor.execute(
            """
            UPDATE kardex
            SET calificacion = %s,
                estatus = %s,
                fecha_calificacion = UTC_TIMESTAMP()
            WHERE id_kardex = %s
              AND estatus = 'Cursando'
            """,
            (
                calificacion,
                estatus,
                id_kardex
            )
        )

        if cursor.rowcount != 1:
            return error_json(
                "No se pudo actualizar la calificación",
                409
            )

        # Auditoría dentro de la misma transacción.
        cursor.execute(
            """
            INSERT INTO auditoria_operaciones (
                id_usuario,
                usuario,
                rol,
                accion,
                detalles,
                ip_origen
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                g.usuario["id_usuario"],
                g.usuario["correo"],
                "profesor",
                "ASENTAR_CALIFICACION",
                json_safe({
                    "id_kardex": id_kardex,
                    "calificacion": calificacion,
                    "estatus": estatus
                }),
                ip_cliente()
            )
        )

        conexion.commit()

    return jsonify({
        "mensaje": "Calificación asentada correctamente",
        "calificacion": calificacion,
        "estatus": estatus
    })


# ========================================================
# 21. SOPORTE TÉCNICO
# ========================================================

@app.post("/api/soporte/enviar")
@limiter.limit("3 per hour")
def soporte_enviar():
    data = json_body()

    nombre = str(
        data.get("nombre") or ""
    ).strip()

    correo = normalizar_email(
        data.get("correo")
    )

    asunto = str(
        data.get("asunto") or ""
    ).strip()

    mensaje = str(
        data.get("mensaje") or ""
    ).strip()

    asuntos_validos = {
        "Cuenta Bloqueada",
        "Error de Credenciales",
        "Falta de Modulos",
        "Otro"
    }

    if not 3 <= len(nombre) <= 120:
        return error_json(
            "Nombre inválido"
        )

    if not validar_email(correo):
        return error_json(
            "Correo inválido"
        )

    if asunto not in asuntos_validos:
        return error_json(
            "Asunto inválido"
        )

    if not 10 <= len(mensaje) <= 3000:
        return error_json(
            "Descripción inválida"
        )

    _, id_ticket = ejecutar(
        """
        INSERT INTO tickets_soporte (
            nombre,
            correo,
            asunto,
            mensaje,
            estatus
        )
        VALUES (%s, %s, %s, %s, 'Abierto')
        """,
        (
            nombre,
            correo,
            asunto,
            mensaje
        )
    )

    contenido = f"""
    <div style="font-family:Arial,sans-serif">
        <h2>Nuevo ticket de soporte</h2>
        <p><b>Ticket:</b> {id_ticket}</p>
        <p><b>Nombre:</b> {html.escape(nombre)}</p>
        <p><b>Correo:</b> {html.escape(correo)}</p>
        <p><b>Asunto:</b> {html.escape(asunto)}</p>
        <hr>
        <p>{html.escape(mensaje).replace(chr(10), "<br>")}</p>
    </div>
    """

    if EMAIL_SOPORTE:
        enviado = enviar_correo(
            EMAIL_SOPORTE,
            "Soporte TI",
            f"Ticket #{id_ticket}: {asunto}",
            contenido,
            reply_to={
                "email": correo,
                "name": nombre
            }
        )

        if not enviado:
            logger.warning(
                "Ticket guardado, pero correo no enviado: %s",
                id_ticket
            )

    return jsonify({
        "mensaje": "Ticket registrado correctamente",
        "id_ticket": id_ticket
    }), 201


# ========================================================
# 22. ERRORES
# ========================================================

@app.errorhandler(404)
def error_404(_):
    return error_json(
        "Ruta no encontrada",
        404
    )


@app.errorhandler(405)
def error_405(_):
    return error_json(
        "Método no permitido",
        405
    )


@app.errorhandler(429)
def error_429(_):
    return error_json(
        "Demasiadas solicitudes. Intenta más tarde.",
        429
    )


@app.errorhandler(mysql.connector.Error)
def error_database(error):
    logger.error(
        "Error de base de datos: %s",
        type(error).__name__
    )

    return error_json(
        "Servicio de base de datos temporalmente no disponible",
        503
    )


@app.errorhandler(Exception)
def error_general(error):
    logger.exception(
        "Error interno en SecurityCampus V2"
    )

    return error_json(
        "Error interno del servidor",
        500
    )


# ========================================================
# 23. INICIO LOCAL
# ========================================================

if __name__ == "__main__":
    puerto = int(
        os.getenv("PORT", "5000")
    )

    debug = (
            os.getenv("FLASK_DEBUG", "0") == "1"
            and not PRODUCTION
    )

    app.run(
        host="127.0.0.1",
        port=puerto,
        debug=debug
    )