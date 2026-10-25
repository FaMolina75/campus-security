"""SecurityCampus V2: datos sintéticos para campus_security_v1 (esquema V2).

Ejecución explícita: APP_ENV=development ALLOW_V2_SEED=YES python backend/seeder.py
No crea administradores, no borra datos, no envía correos ni muestra contraseñas.
"""
import logging
import os
import random
import secrets
import string
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import mysql.connector
from werkzeug.security import generate_password_hash

LOG = logging.getLogger("securitycampus.seeder")
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

DB_NAME = "campus_security_v1"  # Nombre existente; contiene el esquema V2.
PREFIX = "V2TEST"
TOTAL_PROFESORES = 50
TOTAL_ALUMNOS = 450
CUPO = 30
RNG = random.Random(2026)  # Únicamente datos académicos ficticios.
NOMBRES = ("Ana", "Carlos", "María", "Jorge", "Lucía", "Pedro", "Sofía", "Diego", "Elena", "Luis", "Daniela", "Raúl", "Valeria", "Miguel")
APELLIDOS = ("García", "López", "Martínez", "Sánchez", "Pérez", "Flores", "Morales", "Cruz", "Ruiz", "Torres", "Mendoza")
HORARIOS = ("Lun/Mié 07:00-09:00", "Mar/Jue 09:00-11:00", "Lun/Mié 11:00-13:00", "Mar/Jue 14:00-16:00")
AULAS = ("A-101", "A-102", "B-201", "Lab-C1")


def validar_entorno():
    if os.getenv("ALLOW_V2_SEED") != "YES":
        raise RuntimeError("Para sembrar, establece ALLOW_V2_SEED=YES")
    if os.getenv("APP_ENV", "").lower() not in ("development", "test", "testing"):
        raise RuntimeError("Solo se permite APP_ENV=development/test/testing")
    if os.getenv("DB_NAME") != DB_NAME:
        raise RuntimeError("DB_NAME debe ser exactamente campus_security_v1 (con esquema V2)")
    for clave in ("DB_HOST", "DB_USER", "DB_PASSWORD"):
        if not os.getenv(clave):
            raise RuntimeError(f"Falta la variable {clave}")


def conectar():
    opciones = dict(host=os.environ["DB_HOST"], user=os.environ["DB_USER"],
                    password=os.environ["DB_PASSWORD"], database=DB_NAME,
                    port=int(os.getenv("DB_PORT", "4000")),
                    ssl_disabled=False, connection_timeout=15, autocommit=False)
    if os.getenv("DB_SSL_CA"):
        opciones["ssl_ca"] = os.environ["DB_SSL_CA"]
    return mysql.connector.connect(**opciones)


def nombre():
    return f"{RNG.choice(NOMBRES)} {RNG.choice(APELLIDOS)} {RNG.choice(APELLIDOS)}"


def hash_password():
    alfabeto = string.ascii_letters + string.digits + "!@#$%*-_"
    while True:
        valor = "".join(secrets.choice(alfabeto) for _ in range(20))
        if (any(c.islower() for c in valor) and any(c.isupper() for c in valor)
                and any(c.isdigit() for c in valor) and any(c in "!@#$%*-_" for c in valor)):
            return generate_password_hash(valor, method="scrypt")


def usuario_prueba(cursor, matricula, rol, carrera, correo, semestre=0, perfil=1):
    cursor.execute("""SELECT id_usuario,rol,id_carrera,correo FROM usuarios
                      WHERE matricula=%s LIMIT 1""", (matricula,))
    fila = cursor.fetchone()
    if fila:
        if (fila["rol"] != rol or fila["id_carrera"] != carrera
                or fila["correo"].lower() != correo.lower()):
            raise RuntimeError(f"Colisión de identidad: {matricula}; no se modificó")
        return fila["id_usuario"], False
    cursor.execute("""INSERT INTO usuarios
                      (matricula,nombre,correo,password,rol,id_carrera,semestre_actual,
                       perfil_completo,correo_verificado,bloqueado)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,0,0)""",
                   (matricula, nombre(), correo, hash_password(), rol, carrera, semestre, perfil))
    return cursor.lastrowid, True


def verificar_tablas(cursor):
    cursor.execute("SELECT DATABASE() AS db")
    if cursor.fetchone()["db"] != DB_NAME:
        raise RuntimeError("Base de datos inesperada")
    requeridas = {"carreras", "materias", "usuarios", "grupos", "kardex",
                  "sesiones_usuario", "verificaciones_correo", "desafios_captcha"}
    cursor.execute("""SELECT table_name FROM information_schema.tables
                      WHERE table_schema=%s""", (DB_NAME,))
    existentes = {r["table_name"] for r in cursor.fetchall()}
    if requeridas - existentes:
        raise RuntimeError(f"Faltan tablas V2: {sorted(requeridas - existentes)}")


def sembrar():
    validar_entorno()
    inicio = time.monotonic()
    conexion = conectar()
    cursor = None
    creados = Counter()
    try:
        cursor = conexion.cursor(dictionary=True)
        verificar_tablas(cursor)
        cursor.execute("""SELECT id_carrera,clave,duracion_semestres FROM carreras
                          WHERE activo=1 ORDER BY id_carrera""")
        carreras = cursor.fetchall()
        cursor.execute("""SELECT m.id_materia,m.id_carrera,m.semestre,m.tipo
                          FROM materias m JOIN carreras c ON c.id_carrera=m.id_carrera
                          WHERE m.activo=1 AND c.activo=1
                          ORDER BY m.id_carrera,m.semestre,m.id_materia""")
        materias = cursor.fetchall()
        por_carrera = defaultdict(list)
        for m in materias:
            por_carrera[m["id_carrera"]].append(m)
        carreras = [c for c in carreras if por_carrera[c["id_carrera"]]]
        if not carreras or len(carreras) > TOTAL_PROFESORES:
            raise RuntimeError("Se requieren entre 1 y 50 carreras activas con materias")
        LOG.info("Carreras activas con materias: %d", len(carreras))

        profesores = defaultdict(list)
        for i in range(1, TOTAL_PROFESORES + 1):
            carrera = carreras[(i - 1) % len(carreras)]["id_carrera"]
            uid, nuevo = usuario_prueba(cursor, f"{PREFIX}-PROF-{i:03d}", "profesor",
                                        carrera, f"v2test.profesor{i}@example.com")
            profesores[carrera].append(uid)
            creados["profesores"] += int(nuevo)

        for c in carreras:
            cid = c["id_carrera"]
            _, nuevo = usuario_prueba(cursor, f"{PREFIX}-COORD-{cid}", "coordinadora",
                                      cid, f"v2test.coord{cid}@example.com")
            creados["coordinadoras"] += int(nuevo)

        alumnos = []
        for i in range(1, TOTAL_ALUMNOS + 1):
            c = carreras[(i - 1) % len(carreras)]
            semestre = RNG.randint(1, min(9, c["duracion_semestres"]))
            uid, nuevo = usuario_prueba(cursor, f"{PREFIX}-AL-{i:04d}", "alumno",
                                        c["id_carrera"], f"v2test.alumno{i}@example.com",
                                        semestre=semestre, perfil=0)
            alumnos.append((uid, c["id_carrera"]))
            creados["alumnos"] += int(nuevo)

        grupos = defaultdict(list)
        for m in materias:
            cid = m["id_carrera"]
            if cid not in profesores:
                continue
            for letra in ("A", "B"):
                etiqueta = f"{PREFIX}-{m['id_materia']}-{letra}"
                cursor.execute("""SELECT g.id_grupo,g.id_profesor,g.cupo,g.activo,
                                         u.id_carrera AS carrera_profesor,u.rol AS rol_profesor
                                  FROM grupos g JOIN usuarios u ON u.id_usuario=g.id_profesor
                                  WHERE g.id_materia=%s AND g.nombre_grupo=%s LIMIT 1""",
                               (m["id_materia"], etiqueta))
                existente = cursor.fetchone()
                if existente:
                    if (existente["id_profesor"] not in profesores[cid]
                            or existente["carrera_profesor"] != cid
                            or existente["rol_profesor"] != "profesor"):
                        raise RuntimeError(f"Grupo de prueba inconsistente: {etiqueta}")
                    gid, cupo, activo = existente["id_grupo"], existente["cupo"], existente["activo"]
                else:
                    profesor = RNG.choice(profesores[cid])
                    cursor.execute("""INSERT INTO grupos
                                      (id_materia,id_profesor,id_ciclo,nombre_grupo,horario,aula,cupo,activo)
                                      VALUES (%s,%s,NULL,%s,%s,%s,%s,1)""",
                                   (m["id_materia"], profesor, etiqueta, RNG.choice(HORARIOS),
                                    RNG.choice(AULAS), CUPO))
                    gid, cupo, activo = cursor.lastrowid, CUPO, 1
                    creados["grupos"] += 1
                if activo:
                    grupos[m["id_materia"]].append((gid, cupo))

        cursor.execute("""SELECT id_grupo,COUNT(*) AS inscritos FROM kardex
                          WHERE id_grupo IS NOT NULL AND estatus='Cursando'
                          GROUP BY id_grupo""")
        ocupacion = {r["id_grupo"]: r["inscritos"] for r in cursor.fetchall()}
        # Reutilizar el semestre almacenado, sin modificar alumnos preexistentes.
        for uid, cid in alumnos:
            cursor.execute("SELECT semestre_actual FROM usuarios WHERE id_usuario=%s", (uid,))
            semestre_actual = cursor.fetchone()["semestre_actual"]
            for m in por_carrera[cid]:
                if m["semestre"] > semestre_actual:
                    continue
                mid = m["id_materia"]
                cursor.execute("""SELECT id_kardex FROM kardex
                                  WHERE id_alumno=%s AND id_materia=%s LIMIT 1""", (uid, mid))
                if cursor.fetchone():
                    continue
                if m["semestre"] < semestre_actual:
                    # El historial aprobado no ocupa cupo activo ni referencia grupos actuales.
                    estado, nota, gid = "Aprobada", RNG.randint(70, 100), None
                    fecha_nota = datetime.now(timezone.utc).replace(tzinfo=None)
                else:
                    # Solo las inscripciones actuales consumen cupo.
                    opciones = [(g, cupo) for g, cupo in grupos.get(mid, [])
                                if ocupacion.get(g, 0) < cupo]
                    if not opciones:
                        creados["omitidos_por_cupo"] += 1
                        continue
                    gid, _ = min(opciones, key=lambda x: (ocupacion.get(x[0], 0), x[0]))
                    estado, nota, fecha_nota = "Cursando", None, None
                cursor.execute("""INSERT INTO kardex
                                  (id_alumno,id_materia,id_grupo,estatus,calificacion,fecha_calificacion)
                                  VALUES (%s,%s,%s,%s,%s,%s)""", (uid, mid, gid, estado, nota, fecha_nota))
                creados["kardex"] += 1
                if gid is not None:
                    ocupacion[gid] = ocupacion.get(gid, 0) + 1

        conexion.commit()
        LOG.info("Siembra completada en %.1f segundos", time.monotonic() - inicio)
        for tipo in ("profesores", "coordinadoras", "alumnos", "grupos", "kardex", "omitidos_por_cupo"):
            LOG.info("%s nuevos: %d", tipo, creados[tipo])
        LOG.info("No se crearon administradores ni credenciales utilizables.")
        LOG.info("Las cuentas sintéticas permanecen sin verificar.")
    except Exception:
        conexion.rollback()
        LOG.exception("Siembra cancelada; se intentó revertir la transacción")
        raise
    finally:
        if cursor is not None:
            cursor.close()
        conexion.close()


if __name__ == "__main__":
    sembrar()
