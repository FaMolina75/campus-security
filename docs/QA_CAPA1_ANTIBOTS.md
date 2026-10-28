# Capa 1 antibots — validación manual previa a producción

Estado: **PENDIENTE**. Las pruebas unitarias y HTTP aisladas no sustituyen la validación con Google reCAPTCHA real, la base de datos y los paneles.

## Preparación
- [ ] Usar un entorno de *staging* con HTTPS y una base de datos de pruebas (no cuentas reales).
- [ ] Configurar RECAPTCHA_SITE_KEY y RECAPTCHA_SECRET_KEY para el dominio de staging; añadir ese dominio a RECAPTCHA_ALLOWED_HOSTNAMES.
- [ ] Confirmar variables de sesión, CSRF, Redis y conexión a la base de datos sin imprimir secretos.
- [ ] Preparar cuentas de prueba para cada rol y una cuenta de alumno sin verificar.

## Pruebas de navegador
- [ ] Abrir la página; verificar que Google reCAPTCHA carga sin errores de consola.
- [ ] Login válido + reCAPTCHA válido: 200, sesión establecida y navegación al panel correspondiente.
- [ ] Login sin token, token inválido o vencido: 403, sin sesión creada y sin exponer detalles internos.
- [ ] Contraseña incorrecta + reCAPTCHA válido: 401, sin sesión creada.
- [ ] Alumno no verificado: 403 y mensaje esperado.
- [ ] Registro de alumno con datos válidos y reCAPTCHA válido: 201; verificar que se creó solo en la base de pruebas.
- [ ] Registro sin reCAPTCHA: 403; confirmar que no se creó usuario.
- [ ] Registro con correo/matrícula duplicados: 409.
- [ ] Logout: revoca la sesión; /api/auth/me ya no permite acceso.
- [ ] Revisar los cuatro paneles con cuentas de prueba y comprobar permisos por rol.
- [ ] Confirmar que /api/auth/captcha devuelve 410 y no revela respuestas.
- [ ] Revisar registros de auditoría para login correcto y reCAPTCHA inválido, sin guardar contraseñas ni tokens.

## Criterios de salida
- [ ] GitHub Actions en verde para el commit exacto que se fusionará.
- [ ] Evidencia de pruebas manuales (fecha, entorno, resultado; nunca contraseñas o tokens).
- [ ] Plan de reversión y respaldo de configuración de staging.
- [ ] Aprobación explícita antes de fusionar a main y desplegar Render.

No ejecutar pruebas de carga ni enviar tráfico automatizado a producción como parte de esta lista.
