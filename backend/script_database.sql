-- Archivo: backend/script_database.sql
CREATE DATABASE IF NOT EXISTS campus_security_v1;
USE campus_security_v1;

-- ==========================================
-- MÓDULO 1: SEGURIDAD E IDENTIDAD (IAM)
-- ==========================================
CREATE TABLE IF NOT EXISTS usuarios (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    matricula VARCHAR(20) UNIQUE NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    rol ENUM('admin', 'coordinadora', 'profesor', 'alumno') NOT NULL,
    estatus_pago BOOLEAN DEFAULT TRUE,
    bloqueado BOOLEAN DEFAULT FALSE,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS seguridad_accesos (
    id_acceso INT AUTO_INCREMENT PRIMARY KEY,
    correo_intentado VARCHAR(100) NOT NULL,
    ip_origen VARCHAR(45) NOT NULL,
    exitoso BOOLEAN NOT NULL,
    fecha_intento TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tokens_recuperacion (
    id_token INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    usado BOOLEAN DEFAULT FALSE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion DATETIME NOT NULL,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB;

-- ==========================================
-- MÓDULO 2: ESTRUCTURA ACADÉMICA Y LOGÍSTICA
-- ==========================================
CREATE TABLE IF NOT EXISTS materias (
    id_materia INT AUTO_INCREMENT PRIMARY KEY,
    clave VARCHAR(20) UNIQUE NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    creditos INT NOT NULL,
    tipo ENUM('Teoria', 'Laboratorio', 'Optativa') DEFAULT 'Teoria'
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ciclos_escolares (
    id_ciclo INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL, -- Ej. Agosto-Diciembre 2026
    fecha_inicio DATE NOT NULL,
    fecha_fin DATE NOT NULL,
    estatus ENUM('Planeacion', 'Activo', 'Cerrado') DEFAULT 'Planeacion'
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS grupos (
    id_grupo INT AUTO_INCREMENT PRIMARY KEY,
    nombre_grupo VARCHAR(50) NOT NULL,
    id_materia INT NOT NULL,
    id_profesor INT NOT NULL,
    id_ciclo INT NOT NULL,
    cupo INT NOT NULL,
    FOREIGN KEY (id_materia) REFERENCES materias(id_materia),
    FOREIGN KEY (id_profesor) REFERENCES usuarios(id_usuario),
    FOREIGN KEY (id_ciclo) REFERENCES ciclos_escolares(id_ciclo)
) ENGINE=InnoDB;

-- Insertar el Administrador Maestro por defecto
INSERT INTO usuarios (matricula, nombre, correo, password, rol) 
VALUES ('ADM-MASTER', 'Ing. Administrador', 'admin@campus.edu.mx', '123456', 'admin');