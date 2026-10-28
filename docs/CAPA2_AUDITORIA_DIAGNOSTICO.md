# SecurityCampus — Capa 2.1: diagnóstico de auditoría (28/10/2026)

## Estado actual comprobado en main
La aplicación **ya tiene auditoría persistente**: `auditar()` escribe en `auditoria_operaciones` y `registrar_acceso()` escribe en `seguridad_accesos` usando `ejecutar()`. Los administradores ya cuentan con `GET /api/admin/auditoria/operaciones` (300 registros recientes) y `GET /api/admin/auditoria/accesos` (200 registros recientes), protegidos por `@requiere_rol("admin")`.

Acciones de auditoría detectadas en el código: REGISTRO_ALUMNO, LOGIN, PASSWORD_RESET, CORREO_VERIFICADO, CREAR_USUARIO, CAMBIAR_BLOQUEO, CREAR_CARRERA, CREAR_MATERIA, BAN_IP, ACTUALIZAR_PERFIL, CAMBIO_PASSWORD, CREAR_GRUPO e INSCRIBIR_ALUMNO.

## Riesgos y brechas por validar
1. Ambas funciones capturan excepciones y solo escriben en logger si falla la persistencia. Por ello, una caída de TiDB podría dejar huecos en la auditoría sin interrumpir la acción principal.
2. Los endpoints ofrecen una ventana limitada (200/300 filas), sin paginación ni filtros por fecha, acción o gravedad.
3. La cobertura no equivale a registrar cada operación de cada endpoint; realizar una matriz de rutas y eventos antes de ampliar.
4. Revisar la retención, acceso por rol, protección de IP/correos y minimización de datos personales.
5. No guardar cuerpos de solicitudes, contraseñas, cookies, claves ni tokens en registros.
6. Verificar índices y estructura real de las tablas antes de proponer migraciones; no asumir que el esquema histórico del ZIP coincide con producción.

## Plan de implementación sin interrumpir producción
- Fase A: inventario de rutas, clasificación de eventos y pruebas aisladas de `auditar` y `registrar_acceso`.
- Fase B: consulta paginada y filtrada, solo para administradores, con límites estrictos.
- Fase C: alertas por patrones de riesgo, reducción de falsos positivos y políticas de retención.
- Fase D: panel de seguridad con métricas de auditoría, respetando permisos.

## Criterios de aceptación
- No duplicar las tablas existentes ni alterar el contrato de los endpoints actuales.
- Los eventos se guardan con fecha, actor, acción y resultado cuando corresponda.
- Las consultas no exponen datos sensibles ni permiten acceso entre roles.
- CI en verde, revisión de cambios y plan de rollback antes de fusionar a main.
