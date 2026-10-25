-- ============================================================
-- SECURITYCAMPUS V2
-- Base de datos: campus_security_v2
-- Motor: TiDB Cloud / MySQL compatible
--
-- SEGURIDAD:
-- - No incluye contraseñas predeterminadas.
-- - No crea administradores inseguros.
-- - No elimina bases de datos existentes.
-- - Incorpora verificación de correo.
-- - Incorpora sesiones revocables.
-- - Incorpora recuperación de contraseñas.
-- - Incorpora auditoría y bloqueo de IP.
--
-- IMPORTANTE:
-- Ejecutar únicamente en una base nueva.
-- No ejecutar sobre producción sin respaldo.
-- ============================================================


CREATE DATABASE IF NOT EXISTS campus_security_v2;

USE campus_security_v2;


-- ============================================================
-- 1. CARRERAS
-- ============================================================

CREATE TABLE IF NOT EXISTS carreras (
                                        id_carrera INT AUTO_INCREMENT PRIMARY KEY,

                                        clave VARCHAR(20) NOT NULL UNIQUE,
    nombre VARCHAR(150) NOT NULL,

    duracion_semestres INT NOT NULL,
    creditos_totales INT NOT NULL,

    activo BOOLEAN NOT NULL DEFAULT TRUE,

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_carreras_duracion
    CHECK (duracion_semestres > 0),

    CONSTRAINT chk_carreras_creditos
    CHECK (creditos_totales > 0)
    );


-- ============================================================
-- 2. USUARIOS
-- ============================================================

CREATE TABLE IF NOT EXISTS usuarios (
                                        id_usuario INT AUTO_INCREMENT PRIMARY KEY,

                                        matricula VARCHAR(20) NOT NULL UNIQUE,
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(100) NOT NULL UNIQUE,

    password VARCHAR(255) NOT NULL,

    rol ENUM(
                'admin',
                'coordinadora',
                'profesor',
                'alumno'
            ) NOT NULL,

    id_carrera INT NULL,

    semestre_actual INT NOT NULL DEFAULT 0,

    curp VARCHAR(18) NULL,
    telefono VARCHAR(20) NULL,
    direccion VARCHAR(255) NULL,

    perfil_completo BOOLEAN NOT NULL DEFAULT FALSE,

    estatus_pago BOOLEAN NOT NULL DEFAULT TRUE,

    bloqueado BOOLEAN NOT NULL DEFAULT FALSE,

    correo_verificado BOOLEAN NOT NULL DEFAULT FALSE,

    fecha_verificacion DATETIME NULL,

    intentos_fallidos INT NOT NULL DEFAULT 0,

    bloqueo_hasta DATETIME NULL,

    fecha_ultimo_acceso DATETIME NULL,

    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_actualizacion TIMESTAMP
    DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_usuarios_carrera
    FOREIGN KEY (id_carrera)
    REFERENCES carreras(id_carrera),

    CONSTRAINT chk_usuarios_semestre
    CHECK (semestre_actual >= 0),

    INDEX idx_usuarios_rol (rol),

    INDEX idx_usuarios_carrera (id_carrera),

    INDEX idx_usuarios_bloqueado (bloqueado)
    );


-- ============================================================
-- 3. VERIFICACIÓN DE CORREO
-- ============================================================

CREATE TABLE IF NOT EXISTS verificaciones_correo (
                                                     id_verificacion BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                     id_usuario INT NOT NULL,

                                                     codigo_hash VARCHAR(255) NOT NULL,

    intentos INT NOT NULL DEFAULT 0,

    usado BOOLEAN NOT NULL DEFAULT FALSE,

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_expiracion DATETIME NOT NULL,

    fecha_verificacion DATETIME NULL,

    CONSTRAINT fk_verificacion_usuario
    FOREIGN KEY (id_usuario)
    REFERENCES usuarios(id_usuario),

    INDEX idx_verificacion_usuario (id_usuario),

    INDEX idx_verificacion_expiracion (fecha_expiracion)
    );


-- ============================================================
-- 4. SESIONES SEGURAS
-- ============================================================

CREATE TABLE IF NOT EXISTS sesiones_usuario (
                                                id_sesion BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                id_usuario INT NOT NULL,

                                                token_hash CHAR(64) NOT NULL UNIQUE,

    ip_origen VARCHAR(45) NULL,

    user_agent VARCHAR(255) NULL,

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    ultima_actividad DATETIME NOT NULL,

    fecha_expiracion DATETIME NOT NULL,

    revocada BOOLEAN NOT NULL DEFAULT FALSE,

    fecha_revocacion DATETIME NULL,

    CONSTRAINT fk_sesion_usuario
    FOREIGN KEY (id_usuario)
    REFERENCES usuarios(id_usuario),

    INDEX idx_sesion_usuario (id_usuario),

    INDEX idx_sesion_expiracion (fecha_expiracion),

    INDEX idx_sesion_revocada (revocada)
    );


-- ============================================================
-- 5. RECUPERACIÓN DE CONTRASEÑAS
-- ============================================================

CREATE TABLE IF NOT EXISTS tokens_recuperacion (
                                                   id_token BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                   id_usuario INT NOT NULL,

                                                   token_hash VARCHAR(255) NOT NULL,

    intentos INT NOT NULL DEFAULT 0,

    usado BOOLEAN NOT NULL DEFAULT FALSE,

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_expiracion DATETIME NOT NULL,

    fecha_uso DATETIME NULL,

    CONSTRAINT fk_recuperacion_usuario
    FOREIGN KEY (id_usuario)
    REFERENCES usuarios(id_usuario),

    INDEX idx_recuperacion_usuario (id_usuario),

    INDEX idx_recuperacion_expiracion (fecha_expiracion)
    );


-- ============================================================
-- 6. REGISTRO DE ACCESOS
-- ============================================================

CREATE TABLE IF NOT EXISTS seguridad_accesos (
                                                 id_acceso BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                 correo_intentado VARCHAR(100) NOT NULL,

    ip_origen VARCHAR(45) NOT NULL,

    exitoso BOOLEAN NOT NULL,

    motivo VARCHAR(100) NULL,

    user_agent VARCHAR(255) NULL,

    fecha_intento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_accesos_correo (correo_intentado),

    INDEX idx_accesos_ip (ip_origen),

    INDEX idx_accesos_fecha (fecha_intento)
    );


-- ============================================================
-- 7. IP BLOQUEADAS
-- ============================================================

CREATE TABLE IF NOT EXISTS ips_bloqueadas (
                                              id_bloqueo BIGINT AUTO_INCREMENT PRIMARY KEY,

                                              ip VARCHAR(45) NOT NULL UNIQUE,

    motivo VARCHAR(255) NOT NULL,

    bloqueada_por INT NULL,

    fecha_bloqueo TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_expiracion DATETIME NULL,

    activo BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT fk_bloqueo_admin
    FOREIGN KEY (bloqueada_por)
    REFERENCES usuarios(id_usuario),

    INDEX idx_ip_activo (activo)
    );


-- ============================================================
-- 8. AUDITORÍA DE OPERACIONES
-- ============================================================

CREATE TABLE IF NOT EXISTS auditoria_operaciones (
                                                     id_auditoria BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                     id_usuario INT NULL,

                                                     usuario VARCHAR(100) NOT NULL,

    rol VARCHAR(30) NOT NULL,

    accion VARCHAR(100) NOT NULL,

    detalles TEXT NULL,

    ip_origen VARCHAR(45) NULL,

    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auditoria_usuario
    FOREIGN KEY (id_usuario)
    REFERENCES usuarios(id_usuario),

    INDEX idx_auditoria_accion (accion),

    INDEX idx_auditoria_fecha (fecha)
    );


-- ============================================================
-- 9. MATERIAS
-- ============================================================

CREATE TABLE IF NOT EXISTS materias (
                                        id_materia INT AUTO_INCREMENT PRIMARY KEY,

                                        id_carrera INT NOT NULL,

                                        clave VARCHAR(20) NOT NULL,

    nombre VARCHAR(100) NOT NULL,

    semestre INT NOT NULL,

    creditos INT NOT NULL,

    tipo ENUM(
                 'Teoria',
                 'Laboratorio',
                 'Optativa',
                 'Servicio_Social',
                 'Residencia'
             ) NOT NULL DEFAULT 'Teoria',

    activo BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT fk_materia_carrera
    FOREIGN KEY (id_carrera)
    REFERENCES carreras(id_carrera),

    CONSTRAINT uq_materia_carrera_clave
    UNIQUE (id_carrera, clave),

    CONSTRAINT chk_materia_semestre
    CHECK (semestre > 0),

    CONSTRAINT chk_materia_creditos
    CHECK (creditos >= 0),

    INDEX idx_materia_semestre (semestre)
    );


-- ============================================================
-- 10. CICLOS ESCOLARES
-- ============================================================

CREATE TABLE IF NOT EXISTS ciclos_escolares (
                                                id_ciclo INT AUTO_INCREMENT PRIMARY KEY,

                                                nombre VARCHAR(50) NOT NULL,

    fecha_inicio DATE NOT NULL,

    fecha_fin DATE NOT NULL,

    estatus ENUM(
                    'Planeacion',
                    'Activo',
                    'Cerrado'
                ) NOT NULL DEFAULT 'Planeacion',

    CONSTRAINT chk_ciclo_fechas
    CHECK (fecha_fin >= fecha_inicio)
    );


-- ============================================================
-- 11. GRUPOS
-- ============================================================

CREATE TABLE IF NOT EXISTS grupos (
                                      id_grupo INT AUTO_INCREMENT PRIMARY KEY,

                                      id_materia INT NOT NULL,

                                      id_profesor INT NOT NULL,

                                      id_ciclo INT NULL,

                                      nombre_grupo VARCHAR(50) NOT NULL,

    horario VARCHAR(150) NULL,

    aula VARCHAR(50) NULL,

    cupo INT NOT NULL DEFAULT 30,

    activo BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT fk_grupo_materia
    FOREIGN KEY (id_materia)
    REFERENCES materias(id_materia),

    CONSTRAINT fk_grupo_profesor
    FOREIGN KEY (id_profesor)
    REFERENCES usuarios(id_usuario),

    CONSTRAINT fk_grupo_ciclo
    FOREIGN KEY (id_ciclo)
    REFERENCES ciclos_escolares(id_ciclo),

    CONSTRAINT chk_grupo_cupo
    CHECK (cupo > 0),

    INDEX idx_grupo_profesor (id_profesor),

    INDEX idx_grupo_materia (id_materia)
    );


-- ============================================================
-- 12. KARDEX ACADÉMICO
-- ============================================================

CREATE TABLE IF NOT EXISTS kardex (
                                      id_kardex BIGINT AUTO_INCREMENT PRIMARY KEY,

                                      id_alumno INT NOT NULL,

                                      id_materia INT NOT NULL,

                                      id_grupo INT NULL,

                                      estatus ENUM(
                                      'Pendiente',
                                      'Cursando',
                                      'Aprobada',
                                      'Reprobada',
                                      'Baja'
) NOT NULL DEFAULT 'Pendiente',

    calificacion DECIMAL(5,2) NULL,

    fecha_inscripcion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_calificacion DATETIME NULL,

    CONSTRAINT fk_kardex_alumno
    FOREIGN KEY (id_alumno)
    REFERENCES usuarios(id_usuario),

    CONSTRAINT fk_kardex_materia
    FOREIGN KEY (id_materia)
    REFERENCES materias(id_materia),

    CONSTRAINT fk_kardex_grupo
    FOREIGN KEY (id_grupo)
    REFERENCES grupos(id_grupo),

    CONSTRAINT chk_kardex_calificacion
    CHECK (
              calificacion IS NULL
              OR (
              calificacion >= 0
              AND calificacion <= 100
                 )
    ),

    INDEX idx_kardex_alumno (id_alumno),

    INDEX idx_kardex_grupo (id_grupo),

    INDEX idx_kardex_estatus (estatus)
    );


-- ============================================================
-- 13. CAPTCHA / DESAFÍOS TEMPORALES
-- ============================================================

CREATE TABLE IF NOT EXISTS desafios_captcha (
                                                id_desafio BIGINT AUTO_INCREMENT PRIMARY KEY,

                                                identificador_hash CHAR(64) NOT NULL UNIQUE,

    respuesta_hash CHAR(64) NOT NULL,

    intentos INT NOT NULL DEFAULT 0,

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_expiracion DATETIME NOT NULL,

    utilizado BOOLEAN NOT NULL DEFAULT FALSE,

    INDEX idx_captcha_expiracion (fecha_expiracion)
    );


-- ============================================================
-- 14. TICKETS DE SOPORTE
-- ============================================================

CREATE TABLE IF NOT EXISTS tickets_soporte (
                                               id_ticket BIGINT AUTO_INCREMENT PRIMARY KEY,

                                               id_usuario INT NULL,

                                               nombre VARCHAR(100) NOT NULL,

    correo VARCHAR(100) NOT NULL,

    asunto VARCHAR(150) NOT NULL,

    mensaje TEXT NOT NULL,

    estatus ENUM(
                    'Abierto',
                    'En_Proceso',
                    'Resuelto',
                    'Cerrado'
                ) NOT NULL DEFAULT 'Abierto',

    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    fecha_actualizacion TIMESTAMP
    DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_ticket_usuario
    FOREIGN KEY (id_usuario)
    REFERENCES usuarios(id_usuario),

    INDEX idx_ticket_estatus (estatus),

    INDEX idx_ticket_fecha (fecha_creacion)
    );


-- ============================================================
-- 15. COMPROBACIÓN DEL ESQUEMA
-- ============================================================

SHOW TABLES;