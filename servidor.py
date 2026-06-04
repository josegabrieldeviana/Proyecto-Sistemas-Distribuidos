"""
SERVIDOR — Hub de Red TCP (Arquitectura Estrella)
══════════════════════════════════════════════════════════════════
RESPONSABILIDADES EXCLUSIVAS:
  • Aceptar conexiones TCP entrantes (Monitor y Procesadores).
  • Registrar cada nodo por su nombre único.
  • Difundir (broadcast) mensajes al resto de la red.
  • Enrutar mensajes privados entre nodos  →  /w <destino> <texto>
  • Notificar conexiones y desconexiones al canal general.

RESTRICCIÓN ARQUITECTURAL:
  Este módulo NO contiene lógica de negocio, reglas de consenso,
  validación de hashes ni procesamiento blockchain de ningún tipo.
  Su único rol es el de relay de red transparente.
══════════════════════════════════════════════════════════════════
"""

import socket
import threading

# ── Configuración ─────────────────────────────────────────────────────
HOST: str        = "127.0.0.1"
PORT: int        = 5000
BUFFER_SIZE: int = 65_536     # 64 KiB – suficiente para bloques JSON grandes

# ── Estado global del hub  ────────────────────────────────────────────
_lock:    threading.Lock               = threading.Lock()
_clients: dict[str, socket.socket]    = {}    # { nombre_nodo → socket_tcp }


# ══════════════════════════ UTILIDADES ═══════════════════════════════

def _safe_send(sock: socket.socket, message: str) -> bool:
    """
    Envía un mensaje de texto con delimitador de línea '\\n'.
    Retorna True si tuvo éxito, False si el socket ya está roto.
    """
    try:
        sock.sendall((message + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def _broadcast(message: str, exclude: str | None = None) -> None:
    """
    Difunde 'message' a TODOS los nodos conectados.
    Si se especifica 'exclude', ese nodo NO recibe el mensaje
    (útil para el chat general donde el emisor no se escucha a sí mismo).
    """
    with _lock:
        snapshot = [(name, sock)
                    for name, sock in _clients.items()
                    if name != exclude]

    for _name, sock in snapshot:
        _safe_send(sock, message)


def _send_private(sender: str, target: str, payload: str) -> None:
    """
    Reenvía un mensaje privado al nodo destino con el prefijo:
        PRIVATE_FROM_<sender>: <payload>

    Este mecanismo es el canal indirecto que usan el Monitor y los
    Procesadores para intercambiar bloques y respuestas sin que el
    servidor interprete su contenido.
    Si el destino no existe, notifica al emisor.
    """
    with _lock:
        target_sock = _clients.get(target)
        sender_sock = _clients.get(sender)

    if target_sock is None:
        if sender_sock:
            _safe_send(
                sender_sock,
                f"[SERVIDOR] Nodo '{target}' no encontrado o no está conectado."
            )
        return

    _safe_send(target_sock, f"PRIVATE_FROM_{sender}: {payload}")


# ══════════════════════ MANEJO DE CONEXIONES ════════════════════════

def _handle_client(conn: socket.socket, name: str) -> None:
    """
    Bucle de recepción/enrutamiento para un nodo ya registrado.

    Formato de los comandos soportados:
      /w <nodo> <mensaje>    →  mensaje privado   via _send_private()
      /broadcast <mensaje>   →  broadcast a todos (incluye al emisor)
      <cualquier otro texto> →  broadcast general (excluye al emisor)

    Un mismo recv() puede devolver varias líneas si el SO las fusionó;
    por eso se itera sobre cada línea del chunk recibido.
    """
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break   # FIN TCP limpio

            # Dividir el chunk en líneas individuales (defensa ante fusión de paquetes)
            lines = data.decode("utf-8", errors="replace").split("\n")

            for raw in lines:
                raw = raw.strip()
                if not raw:
                    continue

                # ── /w  →  mensaje privado ────────────────────────────
                if raw.startswith("/w "):
                    rest      = raw[3:].strip()
                    sep_idx   = rest.find(" ")
                    if sep_idx == -1:
                        _safe_send(conn, "[SERVIDOR] Uso: /w <nodo> <mensaje>")
                    else:
                        target = rest[:sep_idx]
                        msg    = rest[sep_idx + 1:]
                        _send_private(name, target, msg)

                # ── /broadcast  →  difusión explícita (incluye emisor) ─
                elif raw.startswith("/broadcast "):
                    payload = raw[len("/broadcast "):].strip()
                    _broadcast(f"{name}: {payload}")

                # ── texto libre  →  broadcast general (excluye emisor) ─
                else:
                    _broadcast(f"{name}: {raw}", exclude=name)

    except OSError:
        pass    # Desconexión forzosa (RST, cierre inesperado del proceso, etc.)

    finally:
        # Desregistrar y notificar a la red
        with _lock:
            _clients.pop(name, None)
        print(f"[SERVIDOR] '{name}' desconectado.")
        _broadcast(f"[SERVIDOR] '{name}' se ha desconectado de la red.")
        try:
            conn.close()
        except OSError:
            pass


def _register_client(conn: socket.socket, addr: tuple) -> None:
    """
    Primer handshake con un nuevo cliente TCP.
    El PRIMER mensaje recibido es el nombre de nodo (identificador único).
    Validaciones:
      - No vacío.
      - Sin espacios (romperían el parseo de /w <nodo> …).
      - Único en la sesión actual.
    Tras el registro, delega el control a _handle_client().
    """
    try:
        data = conn.recv(1024)
        if not data:
            conn.close()
            return

        name = data.decode("utf-8", errors="replace").strip()

        if not name:
            _safe_send(conn, "[SERVIDOR] Error: nombre de nodo vacío.")
            conn.close()
            return

        if " " in name:
            _safe_send(conn, "[SERVIDOR] Error: el nombre no puede tener espacios.")
            conn.close()
            return

        with _lock:
            if name in _clients:
                _safe_send(conn, f"[SERVIDOR] El nombre '{name}' ya está en uso.")
                conn.close()
                return
            _clients[name] = conn

        print(f"[SERVIDOR] '{name}' conectado desde {addr[0]}:{addr[1]}")
        _broadcast(f"[SERVIDOR] '{name}' se ha unido a la red.", exclude=name)
        _handle_client(conn, name)

    except OSError:
        try:
            conn.close()
        except OSError:
            pass


# ══════════════════════════ PUNTO DE ENTRADA ════════════════════════

def main() -> None:
    """Levanta el hub TCP y acepta conexiones indefinidamente."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen()

    print("╔══════════════════════════════════════════════════╗")
    print("║  SERVIDOR HUB  —  Sistemas Distribuidos / DLT   ║")
    print(f"║  Escuchando en  {HOST}:{PORT}                       ║")
    print("╚══════════════════════════════════════════════════╝")
    print("[SERVIDOR] Esperando nodos... (Ctrl+C para apagar)\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(
                target=_register_client,
                args=(conn, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Señal de apagado recibida.")
    finally:
        with _lock:
            for sock in _clients.values():
                try:
                    sock.close()
                except OSError:
                    pass
        try:
            server_sock.close()
        except OSError:
            pass
        print("[SERVIDOR] Hub cerrado limpiamente.")


if __name__ == "__main__":
    main()
