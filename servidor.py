"""
SERVIDOR — Hub Central de Red TCP
================================================================================
ARQUITECTURA ESTRELLA (Star Topology)
--------------------------------------------------------------------------------
Este modulo implementa el nodo central (hub) de una topologia en estrella.
En esta arquitectura:

  - El servidor es el UNICO punto de conexion de la red.
  - Ningun nodo habla directamente con otro nodo.
  - Todo mensaje pasa obligatoriamente por el hub, que lo reenvía
    al destinatario sin interpretar su contenido (relay transparente).

  Topologia:
        validador1 ─────┐
        validador2 ──── HUB (servidor.py) ──── monitor
        validador3 ─────┘

RESPONSABILIDADES EXCLUSIVAS DEL HUB:
  1. Aceptar conexiones TCP entrantes de Monitor y Validadores.
  2. Registrar cada nodo por su nombre unico (handshake inicial).
  3. Difundir mensajes al canal general (/broadcast o texto libre).
  4. Enrutar mensajes privados entre dos nodos (/w <destino> <payload>).
  5. Responder consultas de presencia (/who) para que el Monitor pueda
     calcular el quorum con nodos realmente conectados.
  6. Notificar conexiones y desconexiones a toda la red.

RESTRICCION ARQUITECTURAL CRITICA:
  Este modulo NO contiene logica de negocio, NO valida hashes, NO ejecuta
  reglas de consenso ni de blockchain. Es un relay de red puro.
  Separar el hub de la logica de aplicacion es un principio de diseno
  deliberado: permite reemplazar el hub por otro medio de transporte
  (UDP, WebSocket, etc.) sin tocar la logica de consenso.

PROTOCOLO DE MENSAJES:
  - Cada mensaje es una linea de texto terminada en '\\n' (delimitador).
  - El buffer acumulado por conexion (bytearray) reconstruye lineas
    parciales cuando TCP fragmenta paquetes grandes.
  - El primer mensaje de cada conexion nueva es el nombre del nodo.

CONCURRENCIA:
  - Un hilo daemon por cliente, lanzado en _register_client().
  - _lock protege el diccionario _clients ante accesos concurrentes.
================================================================================
"""

import socket
import threading

# ── Configuracion de red ──────────────────────────────────────────────────────
HOST: str        = "127.0.0.1"   # solo loopback; cambiar a "0.0.0.0" para red real
PORT: int        = 5000           # puerto TCP del hub
BUFFER_SIZE: int = 65_536         # 64 KiB: suficiente para bloques JSON grandes

# ── Estado global del hub (protegido por _lock) ───────────────────────────────
# _clients mapea nombre_nodo → socket_tcp activo.
# Es la tabla de enrutamiento del hub: para enviar a "validador1" se busca aquí.
_lock:    threading.Lock            = threading.Lock()
_clients: dict[str, socket.socket] = {}


# ════════════════════════════ UTILIDADES ═════════════════════════════════════

def _safe_send(sock: socket.socket, message: str) -> bool:
    """
    Envia 'message' por 'sock' añadiendo el delimitador de linea '\\n'.

    El '\\n' es el delimitador del protocolo: los receptores usan un buffer
    acumulado que solo procesa lineas completas (terminadas en '\\n'), por
    lo que todo mensaje debe terminar con este caracter.

    Retorna True si el envio fue exitoso, False si el socket esta roto.
    Los fallos se tratan silenciosamente: el hub no debe caerse porque
    un cliente se haya desconectado en mitad de un broadcast.
    """
    try:
        sock.sendall((message + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def _broadcast(message: str, exclude: str | None = None) -> None:
    """
    Difunde 'message' a TODOS los nodos conectados.

    Si se especifica 'exclude', ese nodo no recibe el mensaje.
    Esto se usa para el chat general donde el emisor no se escucha
    a si mismo (comportamiento estandar de chat en estrella).

    Implementacion segura ante concurrencia:
      1. Se toma snapshot de _clients bajo _lock (lectura critica).
      2. Los envios ocurren FUERA del lock para no bloquear otros hilos
         mientras se espera que la pila TCP escriba los datos.
    """
    with _lock:
        # Snapshot: copia de los pares (nombre, socket) en este instante
        snapshot = [(name, sock)
                    for name, sock in _clients.items()
                    if name != exclude]

    # Enviar fuera del lock: si un socket esta roto, _safe_send falla
    # silenciosamente sin afectar al resto del broadcast.
    for _name, sock in snapshot:
        _safe_send(sock, message)


def _send_private(sender: str, target: str, payload: str) -> None:
    """
    Enruta un mensaje privado de 'sender' a 'target'.

    El mensaje llega al destino con el prefijo:
        PRIVATE_FROM_<sender>: <payload>

    Este mecanismo es el canal indirecto que usan Monitor y Validadores
    para intercambiar bloques JSON y respuestas sin que el hub interprete
    el contenido (principio de relay transparente).

    Si el destino no existe o se desconecto, notifica al emisor para
    que pueda tomar accion (ej: recalcular quorum sin ese nodo).
    """
    with _lock:
        target_sock = _clients.get(target)
        sender_sock = _clients.get(sender)

    if target_sock is None:
        # El nodo destino no esta conectado: informar al emisor
        if sender_sock:
            _safe_send(
                sender_sock,
                f"[SERVIDOR] Nodo '{target}' no encontrado o no esta conectado."
            )
        return

    # Reenviar con prefijo de origen para que el receptor identifique al emisor
    _safe_send(target_sock, f"PRIVATE_FROM_{sender}: {payload}")


def _get_connected_nodes() -> list[str]:
    """
    Retorna la lista de nombres de nodos actualmente conectados al hub.

    Usada por el comando /who para que el Monitor calcule el quorum
    con validadores REALMENTE activos, no solo con nombres escritos
    por el usuario que podrian no estar en linea.
    """
    with _lock:
        return list(_clients.keys())


# ════════════════════════ BUFFER TCP ════════════════════════════════════════

def _iter_lines(buf: bytearray) -> tuple[list[str], bytearray]:
    """
    Extrae lineas completas (terminadas en '\\n') del buffer acumulado.

    PROBLEMA QUE RESUELVE — Fragmentacion y fusion de paquetes TCP:
      TCP es un protocolo de STREAM, no de mensajes. Un solo recv() puede:
        a) Devolver MENOS de una linea completa  (paquete fragmentado).
        b) Devolver VARIAS lineas fusionadas      (nagle / coalescing).

      Si se llama split('\\n') directamente sobre recv(), el caso (a)
      produce una linea incompleta que se procesa como si estuviera completa,
      corrompiendo el JSON del bloque.

    SOLUCION — Buffer acumulado por conexion:
      - Se extiende buf con cada chunk recibido.
      - Solo se procesan los fragmentos terminados en '\\n'.
      - El ultimo fragmento (posiblemente incompleto) queda en buf
        hasta que llegue el resto en el siguiente recv().

    Retorna:
      complete : lista de strings de lineas completas (sin '\\n' al final).
      leftover : bytearray con el fragmento incompleto restante.
    """
    text  = buf.decode("utf-8", errors="replace")
    parts = text.split("\n")
    # parts[-1] es el fragmento sin '\n' final (puede estar vacio o incompleto)
    complete = parts[:-1]
    leftover = parts[-1].encode("utf-8")
    return complete, bytearray(leftover)


# ══════════════════════ MANEJO DE CONEXIONES ═════════════════════════════════

def _handle_client(conn: socket.socket, name: str) -> None:
    """
    Bucle de recepcion y enrutamiento para un nodo ya registrado.

    Comandos soportados (cada uno en una linea terminada en '\\n'):

      /w <nodo> <mensaje>
          Mensaje privado al nodo indicado via _send_private().
          Usado por el Monitor para enviar bloques JSON a cada validador.

      /broadcast <mensaje>
          Difusion explicita que INCLUYE al propio emisor.
          Usado por el Monitor para anunciar CONSENSO_ALCANZADO y
          BIFURCACION_DETECTADA a toda la red.

      /who
          Consulta de presencia: el hub responde con la lista de nodos
          conectados en este momento.
          Usado por el Monitor para calcular el quorum real antes de
          distribuir bloques.

      <texto libre>
          Broadcast general que EXCLUYE al emisor.
          Usado por los Validadores para emitir votos publicos:
              VOTE|block_001|YES

    CONCURRENCIA:
      Cada cliente corre en su propio hilo daemon (ver main()).
      El buffer 'buf' es local a este hilo: no hay condicion de carrera
      entre clientes distintos.
    """
    buf = bytearray()   # buffer acumulado por conexion (TCP stream)
    try:
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break   # FIN TCP limpio: el cliente cerro la conexion

            # Acumular el chunk y extraer solo lineas completas
            buf.extend(chunk)
            lines, buf = _iter_lines(buf)

            for raw in lines:
                raw = raw.strip()
                if not raw:
                    continue   # ignorar lineas vacias (artefactos del delimitador)

                # ── /w → mensaje privado ──────────────────────────────────
                if raw.startswith("/w "):
                    rest    = raw[3:].strip()
                    sep_idx = rest.find(" ")
                    if sep_idx == -1:
                        _safe_send(conn, "[SERVIDOR] Uso: /w <nodo> <mensaje>")
                    else:
                        target = rest[:sep_idx]
                        msg    = rest[sep_idx + 1:]
                        _send_private(name, target, msg)

                # ── /broadcast → difusion explicita (incluye emisor) ──────
                elif raw.startswith("/broadcast "):
                    payload = raw[len("/broadcast "):].strip()
                    # Sin exclude: el emisor (Monitor) tambien recibe el eco
                    _broadcast(f"{name}: {payload}")

                # ── /who → lista de nodos conectados (para quorum real) ───
                elif raw.strip() == "/who":
                    nodes = _get_connected_nodes()
                    # Respuesta privada al nodo que pregunto
                    _safe_send(conn, f"[SERVIDOR] Nodos conectados: {','.join(nodes)}")

                # ── texto libre → broadcast general (excluye emisor) ──────
                else:
                    # Los validadores usan esta rama para emitir votos publicos
                    _broadcast(f"{name}: {raw}", exclude=name)

    except OSError:
        # Desconexion forzosa: RST, proceso terminado, red caida, etc.
        pass

    finally:
        # Limpiar registro y notificar a la red que el nodo se fue
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
    Handshake inicial con un nuevo cliente TCP.

    Protocolo de registro:
      1. El cliente envia su nombre de nodo como primera linea (con '\\n').
      2. El servidor valida: no vacio, sin espacios, nombre no en uso.
      3. Si pasa: registra en _clients y delega a _handle_client().
      4. Si falla: envia mensaje de error y cierra la conexion.

    Validaciones:
      - Nombre no vacio: un nodo sin nombre no puede ser enrutado.
      - Sin espacios: el espacio es el separador en '/w <nodo> <msg>',
        un nombre con espacios romperia el parseo del comando.
      - Nombre unico: evita que dos procesos compitan por el mismo slot
        y se sobreescriban mutuamente en _clients.

    El buffer acumulado garantiza que leemos el nombre completo incluso
    si el SO entrego el primer paquete partido.
    """
    try:
        # Acumular bytes hasta recibir el nombre completo (linea terminada en '\n')
        buf = bytearray()
        while b"\n" not in buf and len(buf) < 1024:
            chunk = conn.recv(1024)
            if not chunk:
                conn.close()
                return
            buf.extend(chunk)

        # Extraer solo la primera linea (el nombre del nodo)
        name = buf.decode("utf-8", errors="replace").split("\n")[0].strip()

        # Validacion 1: nombre no vacio
        if not name:
            _safe_send(conn, "[SERVIDOR] Error: nombre de nodo vacio.")
            conn.close()
            return

        # Validacion 2: sin espacios (romperia el parseo de /w)
        if " " in name:
            _safe_send(conn, "[SERVIDOR] Error: el nombre no puede tener espacios.")
            conn.close()
            return

        # Validacion 3: nombre unico (bajo lock para evitar race condition)
        with _lock:
            if name in _clients:
                _safe_send(conn, f"[SERVIDOR] El nombre '{name}' ya esta en uso.")
                conn.close()
                return
            _clients[name] = conn   # registro atomico

        print(f"[SERVIDOR] '{name}' conectado desde {addr[0]}:{addr[1]}")
        _broadcast(f"[SERVIDOR] '{name}' se ha unido a la red.", exclude=name)

        # Delegar el control al loop de mensajes del cliente
        _handle_client(conn, name)

    except OSError:
        try:
            conn.close()
        except OSError:
            pass


# ══════════════════════════ PUNTO DE ENTRADA ════════════════════════════════

def main() -> None:
    """
    Inicia el hub TCP y acepta conexiones indefinidamente.

    Modelo de concurrencia:
      - Un hilo daemon por cliente: cada _register_client() corre en su
        propio hilo, por lo que multiples nodos pueden conectarse y
        enviarse mensajes simultaneamente sin bloquear al servidor.
      - daemon=True: los hilos de cliente mueren automaticamente cuando
        el proceso principal termina (Ctrl+C), sin necesidad de join().

    SO_REUSEADDR: permite relanzar el servidor inmediatamente despues de
    cerrarlo sin esperar el TIME_WAIT de TCP (util en desarrollo).
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
            # Un hilo por cliente: el hub no se bloquea esperando a uno solo
            threading.Thread(
                target=_register_client,
                args=(conn, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Senal de apagado recibida.")
    finally:
        # Cierre limpio: cerrar todos los sockets de clientes activos
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
