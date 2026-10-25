import os
import getpass
import mysql.connector

from werkzeug.security import generate_password_hash


DB_NAME_PERMITIDA = "campus_security_v1"
MATRICULA_ADMIN = "ADMIN-001"


def validar_entorno():
    entorno = os.environ.get("APP_ENV", "").lower()
    db_name = os.environ.get("DB_NAME", "")

    if entorno != "development":
        raise RuntimeError(
            "Operación detenida: APP_ENV debe ser development."
        )

    if db_name != DB_NAME_PERMITIDA:
        raise RuntimeError(
            "Operación detenida: base de datos no autorizada."
        )

    requeridas = [
        "DB_HOST",
        "DB_USER",
        "DB_PASSWORD",
    ]

    faltantes = [
        variable
        for variable in requeridas
        if not os.environ.get(variable)
    ]

    if faltantes:
        raise RuntimeError(
            "Faltan variables: " + ", ".join(faltantes)
        )


def conectar():
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "4000")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        ssl_disabled=False,
        connection_timeout=20,
    )


def solicitar_datos():
    nombre = input("Nombre completo del administrador: ").strip()
    correo = input("Correo electrónico del administrador: ").strip().lower()

    if not nombre or len(nombre) > 120:
        raise ValueError("El nombre debe tener entre 1 y 120 caracteres.")

    if (
            not correo
            or len(correo) > 254
            or "@" not in correo
            or correo.startswith("@")
            or correo.endswith("@")
    ):
        raise ValueError("Introduce un correo electrónico válido.")

    password = getpass.getpass("Contraseña: ")
    confirmacion = getpass.getpass("Confirmar contraseña: ")

    if password != confirmacion:
        raise ValueError("Las contraseñas no coinciden.")

    if len(password) < 12:
        raise ValueError(
            "La contraseña debe contener al menos 12 caracteres."
        )

    return nombre, correo, password


def crear_administrador():
    validar_entorno()

    print("\n🛡️ SecurityCampus V2 — Crear administrador")
    print(f"Base de datos autorizada: {DB_NAME_PERMITIDA}")

    nombre, correo, password = solicitar_datos()

    hash_password = generate_password_hash(
        password,
        method="scrypt",
    )

    conexion = conectar()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            """
            SELECT id_usuario, matricula, correo
            FROM usuarios
            WHERE matricula = %s OR correo = %s
                LIMIT 1
            """,
            (MATRICULA_ADMIN, correo),
        )

        if cursor.fetchone():
            raise RuntimeError(
                "Ya existe un usuario con esa matrícula o correo. "
                "No se realizaron cambios."
            )

        cursor.execute(
            """
            INSERT INTO usuarios (
                matricula,
                nombre,
                correo,
                password,
                rol,
                id_carrera,
                semestre_actual,
                perfil_completo,
                estatus_pago,
                bloqueado,
                correo_verificado
            )
            VALUES (
                       %s, %s, %s, %s, 'admin',
                       NULL, 0, 0, 1, 0, 0
                   )
            """,
            (
                MATRICULA_ADMIN,
                nombre,
                correo,
                hash_password,
            ),
        )

        conexion.commit()

        print("\n✅ Administrador creado correctamente.")
        print(f"Matrícula: {MATRICULA_ADMIN}")
        print(f"Correo: {correo}")
        print("Estado del correo: pendiente de verificación.")

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()


if __name__ == "__main__":
    crear_administrador()