from pathlib import Path
import ast
import shutil

ruta = Path('backend/app.py')
if not ruta.is_file():
    raise SystemExit('Ejecuta desde la raíz del proyecto; falta backend/app.py')
original = ruta.read_text(encoding='utf-8')
marker = '# ========================================================\n# 17. ADMINISTRADOR\n# ========================================================'
if marker not in original:
    raise SystemExit('No se encontró el bloque 17. No se modificó nada.')
if '/api/auth/verificacion-solicitar' in original:
    raise SystemExit('Las rutas ya existen. No se modificó nada.')

nuevo = '''# ========================================================
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
    if not validar_email(correo) or not isinstance(codigo, str) or not re.fullmatch(r"\\d{6}", codigo):
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
            (int(correcto), int(correcto), registro["id_verificacion"])
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


'''
resultado = original.replace(marker, nuevo + marker, 1)
ast.parse(resultado, filename=str(ruta))
respaldo = ruta.with_suffix('.py.pre_verificacion.bak')
if respaldo.exists():
    raise SystemExit(f'Ya existe {respaldo}. No se modificó nada.')
shutil.copy2(ruta, respaldo)
ruta.write_text(resultado, encoding='utf-8')
print(f'OK: actualizado {ruta}; respaldo: {respaldo}')
print('Sintaxis Python validada. Pendiente: pruebas funcionales antes de desplegar.')
