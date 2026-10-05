# Archivo: backend/seeder.py

import mysql.connector
import random
import time

# ==========================================
# CONFIGURACIÓN DE BASE DE DATOS (NUBE - TiDB)
# ==========================================
DB_HOST = 'gateway01.us-east-1.prod.aws.tidbcloud.com'
DB_USER = 't6BEupECtGTsvUW.root'
DB_PASSWORD = 'GlrkiYV1MsMMGoIf'
DB_NAME = 'campus_security_v1'
DB_PORT = 4000

def get_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT,
        ssl_disabled=False
    )

NOMBRES = ["Juan", "María", "Carlos", "Ana", "Luis", "Elena", "Pedro", "Lucía", "Jorge", "Sofía", "Miguel", "Laura", "Fernando", "Carmen", "Diego", "Valeria", "Roberto", "Daniela", "Ricardo", "Camila", "Javier", "Alejandro", "Isabel", "Raúl", "Diana"]
APELLIDOS = ["García", "Martínez", "López", "González", "Pérez", "Rodríguez", "Sánchez", "Ramírez", "Cruz", "Flores", "Gómez", "Morales", "Vázquez", "Jiménez", "Reyes", "Díaz", "Torres", "Gutiérrez", "Ruiz", "Mendoza", "Aguilar", "Ortiz", "Moreno", "Castillo", "Romero"]
AULAS = ["Edificio A, Aula 1", "Edificio A, Aula 2", "Edificio B, Aula 10", "Edificio C, Lab 1", "Edificio C, Lab 2", "Auditorio Principal"]
DIAS = ["Lunes y Miércoles", "Martes y Jueves", "Lunes a Viernes", "Sábados"]
HORAS = ["07:00 - 09:00", "09:00 - 11:00", "11:00 - 13:00", "14:00 - 16:00", "16:00 - 18:00"]

def generar_nombre():
    return f"{random.choice(NOMBRES)} {random.choice(APELLIDOS)} {random.choice(APELLIDOS)}"

def sembrar_datos():
    print("Iniciando sembrado de datos (Data Seeding) hacia AWS TiDB Cloud...")
    inicio = time.time()
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id_carrera, clave FROM carreras")
        carreras = cursor.fetchall()
        if not carreras:
            print("❌ Error: No hay carreras en la base de datos. Ejecuta primero los scripts de SQL en TiDB.")
            return

        carreras_ids = [c['id_carrera'] for c in carreras]

        print("🧑‍🏫 Generando 50 Profesores...")
        profesores_ids = []
        for i in range(1, 51):
            nombre = generar_nombre()
            correo = f"profesor{i}@campus.edu.mx"
            cursor.execute("INSERT IGNORE INTO usuarios (matricula, nombre, correo, password, rol, perfil_completo) VALUES (%s, %s, %s, %s, %s, 1)",
                           (f"PROF-2026-{i:03}", nombre, correo, "123456", "profesor"))
        
        cursor.execute("SELECT id_usuario FROM usuarios WHERE rol = 'profesor'")
        profesores_ids = [p['id_usuario'] for p in cursor.fetchall()]

        print("👩‍💼 Generando Coordinadoras (1 por carrera)...")
        for carrera in carreras:
            nombre = generar_nombre()
            correo = f"coord_{carrera['clave'].lower()}@campus.edu.mx"
            cursor.execute("INSERT IGNORE INTO usuarios (matricula, nombre, correo, password, rol, id_carrera, perfil_completo) VALUES (%s, %s, %s, %s, %s, %s, 1)",
                           (f"COORD-{carrera['id_carrera']}", nombre, correo, "123456", "coordinadora", carrera['id_carrera']))

        print("🎓 Generando 450 Alumnos con perfil completo...")
        for i in range(1, 451):
            nombre = generar_nombre()
            correo = f"alumno{i}@campus.edu.mx"
            id_carrera = random.choice(carreras_ids)
            cursor.execute("""
                INSERT IGNORE INTO usuarios (matricula, nombre, correo, password, rol, id_carrera, curp, telefono, direccion, perfil_completo) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
            """, (f"AL-{2026000 + i}", nombre, correo, "123456", "alumno", id_carrera, f"CURP{i}TEST00000000", "7220000000", "Toluca, Estado de México"))
        
        conn.commit()

        print("🏫 Abriendo Grupos Académicos para el semestre actual...")
        cursor.execute("SELECT id_materia, id_carrera, semestre, nombre FROM materias")
        materias = cursor.fetchall()
        
        for materia in materias:
            for g in ["A", "B"]:
                id_profesor = random.choice(profesores_ids)
                horario = f"{random.choice(DIAS)} {random.choice(HORAS)}"
                aula = random.choice(AULAS)
                nombre_grupo = f"{materia['semestre']}{g}"
                
                cursor.execute("""
                    INSERT INTO grupos (id_materia, id_profesor, nombre_grupo, horario, aula) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (materia['id_materia'], id_profesor, nombre_grupo, horario, aula))
        
        conn.commit()

        print("📚 Inscribiendo alumnos en grupos y generando historial académico...")
        cursor.execute("SELECT id_usuario, id_carrera FROM usuarios WHERE rol = 'alumno'")
        alumnos = cursor.fetchall()
        
        for alumno in alumnos:
            cursor.execute("""
                SELECT g.id_grupo, m.id_materia, m.semestre, m.tipo 
                FROM grupos g JOIN materias m ON g.id_materia = m.id_materia 
                WHERE m.id_carrera = %s
            """, (alumno['id_carrera'],))
            grupos_carrera = cursor.fetchall()
            
            semestre_actual = random.randint(1, 9)
            
            for grupo in grupos_carrera:
                if grupo['semestre'] < semestre_actual:
                    calificacion = random.randint(70, 100)
                    cursor.execute("""
                        INSERT INTO kardex (id_alumno, id_materia, id_grupo, calificacion, estatus) 
                        VALUES (%s, %s, %s, %s, 'Aprobada')
                    """, (alumno['id_usuario'], grupo['id_materia'], grupo['id_grupo'], calificacion))
                
                elif grupo['semestre'] == semestre_actual:
                    cursor.execute("SELECT id_kardex FROM kardex WHERE id_alumno = %s AND id_materia = %s", (alumno['id_usuario'], grupo['id_materia']))
                    if not cursor.fetchone():
                        cursor.execute("""
                            INSERT INTO kardex (id_alumno, id_materia, id_grupo, estatus) 
                            VALUES (%s, %s, %s, 'Cursando')
                        """, (alumno['id_usuario'], grupo['id_materia'], grupo['id_grupo']))

        conn.commit()
        
        fin = time.time()
        print(f"\n✅ ¡Sembrado de datos finalizado con éxito en la nube TiDB en {round(fin - inicio, 2)} segundos!")
        print("\n--- CREDENCIALES DE PRUEBA EN LA NUBE ---")
        print("🔑 Todas las contraseñas son: 123456")
        print("🎓 Alumnos: alumno1@campus.edu.mx hasta alumno450@campus.edu.mx")
        print("👩‍💼 Coordinadoras: coord_ing-tic@campus.edu.mx (varía por carrera)")
        print("🧑‍🏫 Profesores: profesor1@campus.edu.mx hasta profesor50@campus.edu.mx")
        print("-----------------------------------------")

    except Exception as e:
        print(f"❌ Error durante el sembrado en TiDB: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    sembrar_datos()