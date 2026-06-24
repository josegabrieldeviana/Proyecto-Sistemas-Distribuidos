"""
SERVIDOR — Hub central de la red

Este es el servidor que conecta a todos los nodos de la red.
Funciona como una especie de "central telefonica": nadie habla
directamente con nadie, los mensajes pasan siempre por aqui.

    validador1 ──┐
    validador2 ──── servidor ──── monitor
    validador3 ──┘

De que se encarga este archivo:
- aceptar las conexiones de monitor y validadores
- registrar el nombre de cada nodo cuando se conecta
- reenviar mensajes de un nodo a otro sin leer el contenido
- responder /who con la lista de quien esta conectado
- avisar a todos cuando alguien entra o sale de la red

Importante: este modulo no tiene nada de logica de blockchain,
solo pasa mensajes. Eso lo hace el monitor y los validadores.
"""

import socket
import threading

# configuracion de red
HOST: str        = "127.0.0.1"   # solo loopback, cambiar a 0.0.0.0 para red real
PORT: int        = 5000           # puerto del servidor
BUFFER_SIZE: int = 65_536         # 64kb, suficiente para los mensajes JSON grandes

# estado del servidor
# _clients es el diccionario que guarda nombre → socket de cada nodo
# _lock protege ese diccionario para evitar problemas con multiples hilos
_lock:    threading.Lock            = threading.Lock()
_clients: dict[str, socket.socket] = {}


# ─── utilidades ──────────────────────────────────────────────────────────────

def _safe_send(sock: socket.socket, message: str) -> bool:
    """
    Manda un mensaje por el socket.
    Le agrega \\n al final porque los receptores necesitan ese caracter
    para saber donde termina el mensaje.
    Si el socket esta roto o el cliente se desconecto, devuelve False
    sin tirar error para que el servidor siga funcionando.
    """
    try:
        sock.sendall((message + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def _broadcast(message: str, exclude: str | None = None) -> None:
    """
    Manda el mensaje a todos los nodos conectados.
    Si se le pasa el parametro exclude, ese nodo no recibe nada
    (sirve para que el que envia no se escuche a si mismo).

    Primero hacemos una copia de los clientes dentro del lock y luego
    enviamos afuera del lock, para no bloquear el hilo mientras TCP
    transmite los datos.
    """
    with _lock:
        # hacemos copia rapida para no enviar dentro del lock
        snapshot = [(name, sock)
                    for name, sock in _clients.items()
                    if name != exclude]

    # enviamos afuera del lock, si un socket falla no afecta a los demas
    for _name, sock in snapshot:
        _safe_send(sock, message)


def _send_private(sender: str, target: str, payload: str) -> None:
    """
    Envia un mensaje privado de sender a target.
    El mensaje llega al destino con el formato:
        PRIVATE_FROM_sender: payload

    Si el nodo destino no existe o se desconecto, le avisamos
    al que intento enviar para que sepa que no llego.
    """
    with _lock:
        target_sock = _clients.get(target)
        sender_sock = _clients.get(sender)

    if target_sock is None:
        # el destino no esta, avisamos al origen
        if sender_sock:
            _safe_send(
                sender_sock,
                f"[SERVIDOR] Nodo '{target}' no encontrado o no esta conectado."
            )
        return

    # reenviar con el prefijo para que el receptor sepa quien lo mando
    _safe_send(target_sock, f"PRIVATE_FROM_{sender}: {payload}")


def _get_connected_nodes() -> list[str]:
    """
    Retorna una lista con los nombres de todos los nodos conectados ahora.
    La usa el monitor cuando pregunta /who para calcular el quorum.
    """
    with _lock:
        return list(_clients.keys())


# ─── manejo del buffer TCP ───────────────────────────────────────────────────

def _iter_lines(buf: bytearray) -> tuple[list[str], bytearray]:
    """
    Extrae las lineas completas del buffer acumulado.

    El problema con TCP es que es un protocolo de stream de bytes: a veces
    recv() devuelve solo un pedazo del mensaje, y a veces devuelve varios
    mensajes pegados. Si procesamos directamente lo que llega podemos
    cortar un mensaje JSON a la mitad y danar el bloque.

    La solucion es guardar todo en un buffer y solo procesar las partes
    que ya tienen \\n al final. Lo que queda sin \\n se guarda para el
    siguiente recv().

    Devuelve las lineas completas y el fragmento sobrante.
    """
    text  = buf.decode("utf-8", errors="replace")
    parts = text.split("\n")
    # parts[-1] es lo que no tiene \n todavia, puede estar incompleto
    complete = parts[:-1]
    leftover = parts[-1].encode("utf-8")
    return complete, bytearray(leftover)


# ─── conexiones de clientes ───────────────────────────────────────────────────

def _handle_client(conn: socket.socket, name: str) -> None:
    """
    Loop de recepcion y enrutamiento para un nodo ya registrado.

    Comandos que soporta (cada uno termina en \\n):

      /w nodo mensaje     → manda mensaje privado a ese nodo
      /broadcast mensaje  → lo reciben todos, incluso el que envia
      /who                → responde con la lista de nodos conectados
      texto libre         → broadcast a todos menos al emisor
                            (los validadores usan esto para mandar votos)

    Cada cliente corre en su propio hilo, asi varios pueden enviar
    mensajes al mismo tiempo sin bloquearse entre si.
    """
    buf = bytearray()   # buffer acumulado para este cliente
    try:
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break   # el cliente cerro la conexion limpiamente

            # acumular lo recibido y sacar solo las lineas ya completas
            buf.extend(chunk)
            lines, buf = _iter_lines(buf)

            for raw in lines:
                raw = raw.strip()
                if not raw:
                    continue   # linea vacia, ignorar

                # /w → mensaje privado
                if raw.startswith("/w "):
                    rest    = raw[3:].strip()
                    sep_idx = rest.find(" ")
                    if sep_idx == -1:
                        _safe_send(conn, "[SERVIDOR] Uso: /w <nodo> <mensaje>")
                    else:
                        target = rest[:sep_idx]
                        msg    = rest[sep_idx + 1:]
                        _send_private(name, target, msg)

                # /broadcast → difusion incluyendo al emisor
                elif raw.startswith("/broadcast "):
                    payload = raw[len("/broadcast "):].strip()
                    # sin exclude para que el monitor tambien reciba el eco
                    _broadcast(f"{name}: {payload}")

                # /who → lista de nodos (para que el monitor calcule el quorum)
                elif raw.strip() == "/who":
                    nodes = _get_connected_nodes()
                    # respondemos solo al que pregunto
                    _safe_send(conn, f"[SERVIDOR] Nodos conectados: {','.join(nodes)}")

                # texto libre → broadcast sin el emisor (para los votos de validadores)
                else:
                    # los validadores usan esta rama para emitir sus votos
                    _broadcast(f"{name}: {raw}", exclude=name)

    except OSError:
        # desconexion inesperada
        pass

    finally:
        # sacar al nodo del registro y notificar a los demas
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
    Registra a un cliente nuevo que acaba de conectarse.

    Lo primero que manda el cliente es su nombre. Lo leemos y validamos:
      - que no este vacio
      - que no tenga espacios (romperia el parseo de /w nodo mensaje)
      - que no haya otro nodo con el mismo nombre

    Si todo esta bien lo guardamos en _clients y lo mandamos a _handle_client.
    Si algo falla, mandamos un mensaje de error y cerramos la conexion.
    """
    try:
        # leer bytes hasta encontrar \n para tener el nombre completo
        buf = bytearray()
        while b"\n" not in buf and len(buf) < 1024:
            chunk = conn.recv(1024)
            if not chunk:
                conn.close()
                return
            buf.extend(chunk)

        # tomar la primera linea como nombre del nodo
        name = buf.decode("utf-8", errors="replace").split("\n")[0].strip()

        # nombre no vacio
        if not name:
            _safe_send(conn, "[SERVIDOR] Error: nombre de nodo vacio.")
            conn.close()
            return

        # sin espacios porque si no el comando /w no funcionaria
        if " " in name:
            _safe_send(conn, "[SERVIDOR] Error: el nombre no puede tener espacios.")
            conn.close()
            return

        # nombre unico (bajo lock para evitar que dos nodos se registren igual al mismo tiempo)
        with _lock:
            if name in _clients:
                _safe_send(conn, f"[SERVIDOR] El nombre '{name}' ya esta en uso.")
                conn.close()
                return
            _clients[name] = conn   # registrar al nodo

        print(f"[SERVIDOR] '{name}' conectado desde {addr[0]}:{addr[1]}")
        _broadcast(f"[SERVIDOR] '{name}' se ha unido a la red.", exclude=name)

        # pasar al loop de mensajes ya que el registro fue exitoso
        _handle_client(conn, name)

    except OSError:
        try:
            conn.close()
        except OSError:
            pass


# ─── punto de entrada ─────────────────────────────────────────────────────────

def main() -> None:
    """
    Arranca el servidor y se queda aceptando conexiones.

    Cada cliente nuevo corre en su propio hilo daemon para que varios
    nodos puedan conectarse y mandarse mensajes al mismo tiempo.

    SO_REUSEADDR sirve para poder reiniciar el servidor inmediatamente
    despues de cerrarlo sin esperar a que el puerto quede libre.
    Es muy util cuando uno lo cierra y lo vuelve a abrir enseguida.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen()   # backlog por defecto del SO

    print("╔══════════════════════════════════════════════════╗")
    print("║  SERVIDOR HUB  —  Sistemas Distribuidos / DLT   ║")
    print("║  Arquitectura Estrella (Star Topology)           ║")
    print(f"║  Escuchando en  {HOST}:{PORT}                       ║")
    print("╚══════════════════════════════════════════════════╝")
    print("[SERVIDOR] Esperando nodos... (Ctrl+C para apagar)\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            # hilo por cliente para que el servidor no se quede bloqueado esperando a uno
            threading.Thread(
                target=_register_client,
                args=(conn, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Senal de apagado recibida.")
    finally:
        # cerrar todos los sockets al apagar
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
