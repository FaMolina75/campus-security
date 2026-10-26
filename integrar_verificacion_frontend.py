from pathlib import Path

archivo = Path("frontend/index.html")
contenido = archivo.read_text(encoding="utf-8")

marcas = [
    'id="linkVerificarCorreo"',
    'id="modalVerificarCorreo"',
    'async function solicitarVerificacionCorreo(',
]

if any(marca in contenido for marca in marcas):
    raise SystemExit("Cancelado: la verificación ya parece estar integrada.")

enlace = '''
                    <a
                            href="#"
                            id="linkVerificarCorreo"
                            data-bs-toggle="modal"
                            data-bs-target="#modalVerificarCorreo"
                    >
                        <i class="fa-solid fa-envelope-circle-check me-1"></i>
                        Verificar mi correo institucional
                    </a>

'''

ancla_enlace = '''                    <a
                            href="#"
                            data-bs-toggle="modal"
                            data-bs-target="#modalSoporte"'''

modal = '''
<!-- MODAL: VERIFICACIÓN DE CORREO INSTITUCIONAL -->
<div class="modal fade" id="modalVerificarCorreo" tabindex="-1"
     aria-labelledby="tituloVerificarCorreo" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content border-0 shadow-lg">
            <div class="modal-header bg-primary text-white">
                <h5 class="modal-title fw-bold" id="tituloVerificarCorreo">
                    <i class="fa-solid fa-envelope-circle-check me-2"></i>
                    Verificar correo institucional
                </h5>
                <button type="button" class="btn-close btn-close-white"
                        data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body p-4 bg-light">
                <p class="text-muted small">
                    Solicita un código de seis dígitos. Si tu cuenta está
                    pendiente de verificación, lo recibirás por correo.
                    El código caduca en 15 minutos.
                </p>

                <form id="formSolicitarVerificacion" class="mb-4">
                    <label for="verCorreo" class="form-label fw-bold">
                        Correo institucional
                    </label>
                    <input type="email" id="verCorreo" class="form-control mb-3"
                           maxlength="254" autocomplete="email" required>
                    <button type="submit" id="btnSolicitarVerificacion"
                            class="btn btn-primary w-100">
                        Enviar código de verificación
                    </button>
                </form>

                <hr>

                <form id="formConfirmarVerificacion">
                    <label for="verCodigo" class="form-label fw-bold">
                        Código recibido
                    </label>
                    <input type="text" id="verCodigo"
                           class="form-control text-center font-monospace fs-4 mb-3"
                           inputmode="numeric" pattern="[0-9]{6}"
                           minlength="6" maxlength="6"
                           autocomplete="one-time-code"
                           placeholder="123456" required>
                    <button type="submit" id="btnConfirmarVerificacion"
                            class="btn btn-success w-100">
                        Confirmar verificación
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

'''

ancla_modal = '<!-- Bootstrap Bundle -->'

funciones = '''
    // VERIFICACIÓN DE CORREO INSTITUCIONAL
    async function solicitarVerificacionCorreo(evento) {
        evento.preventDefault();
        const correo = normalizarCorreo($("verCorreo").value);

        activarBoton("btnSolicitarVerificacion", true, "Enviando...");
        try {
            const respuesta = await apiRequest(
                "/auth/verificacion-solicitar",
                {method: "POST", body: {correo}}
            );
            await mostrarAlerta(
                "info",
                "Revisa tu correo",
                respuesta.mensaje ||
                "Si tu cuenta está pendiente, recibirás un código."
            );
        } catch (error) {
            await mostrarAlerta(
                "error", "No se pudo solicitar el código", error.message
            );
        } finally {
            activarBoton("btnSolicitarVerificacion", false);
        }
    }

    async function confirmarVerificacionCorreo(evento) {
        evento.preventDefault();
        const correo = normalizarCorreo($("verCorreo").value);
        const codigo = $("verCodigo").value.trim();

        if (!/^\\\\d{6}$/.test(codigo)) {
            await mostrarAlerta(
                "warning", "Código inválido", "Ingresa seis dígitos."
            );
            return;
        }

        activarBoton("btnConfirmarVerificacion", true, "Verificando...");
        try {
            const respuesta = await apiRequest(
                "/auth/verificacion-confirmar",
                {method: "POST", body: {correo, codigo}}
            );

            $("logCorreo").value = correo;
            $("verCodigo").value = "";
            bootstrap.Modal.getOrCreateInstance(
                $("modalVerificarCorreo")
            ).hide();

            await mostrarAlerta(
                "success",
                "Correo verificado",
                respuesta.mensaje || "Ya puedes iniciar sesión."
            );
            await cargarCaptcha();
        } catch (error) {
            await mostrarAlerta(
                "error", "No se pudo verificar el correo", error.message
            );
        } finally {
            activarBoton("btnConfirmarVerificacion", false);
        }
    }

'''

ancla_funciones = '    async function inicializarLogin() {'

eventos = '''        $("formSolicitarVerificacion").addEventListener(
            "submit", solicitarVerificacionCorreo
        );

        $("formConfirmarVerificacion").addEventListener(
            "submit", confirmarVerificacionCorreo
        );

        $("modalVerificarCorreo").addEventListener(
            "show.bs.modal",
            () => {
                const correoLogin = normalizarCorreo($("logCorreo").value);
                if (correoLogin) {
                    $("verCorreo").value = correoLogin;
                }
            }
        );

'''

ancla_eventos = '''        $("formLogin").addEventListener(
            "submit",
            realizarLogin
        );'''

cambios = [
    (ancla_enlace, enlace + ancla_enlace),
    (ancla_modal, modal + ancla_modal),
    (ancla_funciones, funciones + ancla_funciones),
    (ancla_eventos, eventos + ancla_eventos),
]

for original, reemplazo in cambios:
    cantidad = contenido.count(original)
    if cantidad != 1:
        raise SystemExit(
            f"Cancelado: se esperaban 1 coincidencia y hay {cantidad}: "
            f"{original[:65]!r}"
        )
    contenido = contenido.replace(original, reemplazo, 1)

archivo.write_text(contenido, encoding="utf-8")

print("OK: enlace de verificación añadido.")
print("OK: modal para solicitar y confirmar códigos añadido.")
print("OK: funciones JavaScript integradas.")
print("OK: eventos registrados en inicializarLogin.")
print("Pendiente: validar sintaxis y revisar cambios.")
