# SecurityCampus — Preflight de seguridad (NO desplegar todavía)

Esta guía aplica exclusivamente a la rama `security-development`.
No activar `SESSION_V2_ENFORCE=1` ni fusionar con `main` hasta completar
todos los puntos y obtener autorización explícita del responsable.

## Bloqueadores críticos

- [ ] **Contraseñas heredadas**: identificar de forma segura las cuentas cuyo
  campo `password` aún contiene texto plano. Con `SESSION_V2_ENFORCE=1`
  esas cuentas **no podrán iniciar sesión**. Preparar migración con hash
  (scrypt/pbkdf2) sin registrar ni exponer contraseñas. No consultar datos
  reales desde pruebas automatizadas.
- [ ] **Cookies entre sitios**: probar login, `/api/auth/session`, POST con
  `X-CSRF-Token`, cierre de sesión y expiración real en los navegadores
  utilizados por los usuarios. Vercel y Render pueden estar en sitios
  distintos; algunos navegadores bloquean cookies de terceros aunque
  `SameSite=None; Secure` esté configurado.
- [ ] **Configuración de Render**: comprobar `SECRET_KEY` persistente,
  `FRONTEND_ORIGINS` exactos, `DB_HOST`, `DB_USER`, `DB_PASSWORD`,
  `DB_NAME`, `DB_PORT`, `BREVO_API_KEY` y HTTPS. No pegar valores en
  tickets, commits o registros.
- [ ] **Revocación de sesiones**: las sesiones Flask actuales se firman,
  pero no se guardan en servidor; el cierre de sesión no revoca una cookie
  previamente copiada. Diseñar invalidación server-side antes de prometer
  revocación inmediata.
- [ ] **Rate limiting**: Flask-Limiter usa memoria local. Reinicios o varias
  instancias reinician o separan contadores. Elegir almacenamiento compartido
  o controles perimetrales sin añadir otra base de datos de pago.
- [ ] **CAPTCHA**: el código sigue siendo entregado al navegador; comprobar
  resistencia frente a automatización, límite de intentos y accesibilidad.
- [ ] **Credenciales expuestas**: revisar `backend/seeder.py` y rotar
  cualquier contraseña publicada previamente, coordinando el cambio para
  evitar interrumpir el servicio.
- [ ] **Pruebas funcionales por rol**: alumno, profesor, coordinadora y admin;
  autorizaciones 401/403, operaciones legítimas, calificaciones y
  restricciones por carrera. Usar mocks o entorno aislado, nunca modificar
  TiDB de producción.

## Pruebas automatizadas sin acceso a TiDB

```bash
python -m unittest discover -s tests -v
```

GitHub Actions ejecuta estas pruebas en `security-development`. Un estado
verde **no garantiza** compatibilidad de navegador, cobertura de permisos
completa ni seguridad de producción.

## Activación y reversión

1. Conservar respaldo y confirmar ventana de mantenimiento.
2. Validar secretos, compatibilidad de cookies y migración de contraseñas.
3. Completar pruebas funcionales en entorno aislado.
4. Obtener aprobación explícita antes de cualquier cambio en `main`,
   Render, Vercel o TiDB Cloud.
5. Documentar cómo revertir el despliegue sin perder datos.
