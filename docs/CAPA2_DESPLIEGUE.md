# Capa 2 — Verificación y despliegue controlado

## Alcance
- Búsqueda de accesos y operaciones: endpoints nuevos, solo rol admin.
- Filtros validados, consultas SQL parametrizadas, paginación de 1 a 100 filas.
- Panel admin: filtros por fechas, acción, correo y resultado; navegación por páginas.
- Estado de IP bloqueada desde `ips_bloqueadas` (bloqueos activos no expirados).
- Alertas **informativas** por 5 o más intentos fallidos de una IP en 60 minutos; no se ejecutan bloqueos automáticos.
- No se agregan tablas ni migraciones.

## Antes de fusionar
1. Confirmar que GitHub Actions termina en verde con el último commit del PR.
2. Ejecutar `python -m unittest discover -s tests -p 'test_*.py' -v` con las dependencias instaladas.
3. Validar en entorno de prueba conectado a una base TiDB de prueba: endpoints de accesos, operaciones y alertas; fechas y paginación.
4. Iniciar sesión como administrador y verificar ambos paneles, CSV y botón Bloquear IP.
5. Verificar que un alumno y un usuario sin sesión reciben 403 y 401, respectivamente.
6. Revisar plan de retención y acceso a logs: contienen IP, correo y agente de usuario.
7. Revisar las consultas en TiDB con volumen representativo e índices para `seguridad_accesos(fecha_intento, exitoso, ip_origen)` según `EXPLAIN` y la carga real; no aplicar índices sin medir.

## Después de fusionar
- Observar errores HTTP 5xx, latencia y logs de la aplicación en Render.
- Probar lectura de auditoría con un administrador y verificar que no se muestran datos a otros roles.
- Si aparecen errores, revertir el commit de fusión desde GitHub y redeplegar la versión anterior.
- No ejecutar cambios manuales en TiDB sin respaldo y autorización.

## Limitaciones conocidas
- Los tests HTTP usan mocks; CI **no** comprueba la base TiDB real ni el comportamiento del navegador.
- Las alertas se calculan al consultar el endpoint, no se envían notificaciones ni se almacenan alertas independientes.
- La paginación usa OFFSET, apropiada para esta primera fase pero revisable con mucho volumen.
- El botón de CSV exporta las filas visibles, no todo el histórico.
