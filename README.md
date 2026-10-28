🛡️ SecurityCampus

Sistema de Gestión Académica y Seguridad Informática

SecurityCampus es una plataforma web diseñada para integrar la administración académica con mecanismos de seguridad informática, control de acceso y auditoría de actividades.

El proyecto busca proporcionar un entorno digital organizado y seguro para estudiantes, profesores, coordinadores y administradores.

⸻

🎯 Objetivo del proyecto

Desarrollar una plataforma web que permita gestionar procesos académicos y aplicar medidas de seguridad para proteger la información de los usuarios.

SecurityCampus combina funcionalidades administrativas, académicas y de monitoreo de seguridad dentro de un mismo sistema.

🚀 Funcionalidades principales

🔐 Autenticación y seguridad

* Inicio de sesión de usuarios.
* Autenticación mediante credenciales.
* CAPTCHA como mecanismo de protección.
* Recuperación de contraseñas.
* Registro de intentos de acceso.
* Control y bloqueo de direcciones IP.
* Restricción de funciones según el rol del usuario.

👨‍💼 Panel de administración

* Gestión de usuarios.
* Administración de carreras y materias.
* Bloqueo y desbloqueo de cuentas.
* Consulta de estadísticas.
* Consulta de registros de acceso.
* Auditoría de operaciones realizadas en el sistema.

🎓 Panel de estudiantes

* Consulta de información académica.
* Visualización del progreso académico.
* Actualización de información del perfil.

👨‍🏫 Panel de profesores

* Consulta de grupos asignados.
* Visualización de estudiantes.
* Registro de calificaciones.

🏫 Panel de coordinación

* Administración de grupos.
* Inscripción de estudiantes.
* Consulta de profesores.
* Gestión de materias y carreras.

🛠️ Tecnologías utilizadas

Tecnología	Función
Python	Desarrollo del backend
Flask	API y lógica del servidor
MySQL	Almacenamiento de información
HTML5	Estructura de la interfaz
CSS3	Diseño visual
JavaScript	Interactividad del frontend
Gunicorn	Ejecución del servidor en producción
Git	Control de versiones
GitHub	Repositorio del proyecto

📁 Estructura del proyecto

campus-security/
│
├── backend/
│   ├── app.py
│   ├── script_database.sql
│   └── seeder.py
│
├── frontend/
│   ├── index.html
│   │
│   └── dashboards/
│       ├── admin/
│       │   └── index.html
│       ├── alumno/
│       │   └── index.html
│       ├── coordinadora/
│       │   └── index.html
│       └── profesor/
│           └── index.html
│
├── requirements.txt
└── README.md

🛡️ Sistema de auditoría

SecurityCampus incorpora funciones para registrar y consultar actividades relacionadas con la seguridad y la administración del sistema.

Entre los eventos contemplados se encuentran:

* Intentos de inicio de sesión.
* Accesos exitosos y fallidos.
* Operaciones realizadas por usuarios.
* Identificación de direcciones IP.
* Consulta administrativa de registros de auditoría.

Estos mecanismos permiten revisar determinadas actividades y facilitar la identificación de comportamientos sospechosos.

Nota: La auditoría de la aplicación no debe confundirse con los registros de infraestructura de los servicios de alojamiento. Para disponer de una trazabilidad completa, es necesario verificar la persistencia y cobertura de los registros.

⚙️ Instalación

1. Clonar el repositorio

git clone URL_DEL_REPOSITORIO
cd campus-security

2. Crear un entorno virtual

python3 -m venv .venv

Activarlo en macOS o Linux:

source .venv/bin/activate

3. Instalar dependencias

pip install -r requirements.txt

4. Configurar la base de datos

El proyecto utiliza MySQL.

El archivo de referencia para la estructura de la base de datos se encuentra en:

backend/script_database.sql

Antes de ejecutar el sistema, deben configurarse las credenciales de conexión y las variables de entorno necesarias.

Importante: Nunca publiques contraseñas, claves privadas ni credenciales de producción en GitHub.

5. Ejecutar el backend

Una vez configurada la base de datos y el entorno:

python backend/app.py

🔒 Buenas prácticas de seguridad

El desarrollo de SecurityCampus contempla la importancia de:

* Proteger las credenciales de los usuarios.
* Controlar el acceso a funcionalidades administrativas.
* Registrar eventos relevantes de seguridad.
* Reducir los riesgos asociados a intentos de acceso no autorizados.
* Mantener las dependencias actualizadas.
* Evitar la exposición de información sensible.

La implementación de estas medidas debe verificarse mediante pruebas antes de considerar el sistema apto para producción.

📈 Mejoras futuras

Entre las posibles mejoras del proyecto se encuentran:

* Centralización de registros de seguridad.
* Alertas ante actividades sospechosas.
* Monitoreo avanzado de eventos.
* Fortalecimiento de los controles de autenticación.
* Pruebas automatizadas de seguridad.
* Optimización del rendimiento.
* Ampliación de los reportes administrativos.

🎓 Propósito académico

SecurityCampus es un proyecto de desarrollo tecnológico orientado a aplicar conocimientos de programación web, bases de datos, administración de sistemas y ciberseguridad.

Su propósito es demostrar cómo pueden integrarse diferentes tecnologías para desarrollar una plataforma de gestión académica con controles de seguridad y herramientas de auditoría.

⸻

SecurityCampus — Gestión académica, tecnología y seguridad en una sola plataforma.
