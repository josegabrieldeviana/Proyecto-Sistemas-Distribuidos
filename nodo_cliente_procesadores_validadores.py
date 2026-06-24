"""
NODO PROCESADOR / VALIDADOR

Este modulo es un nodo validador de la red. Cada instancia es un nodo hoja
de la topologia estrella: solo se conecta al hub, nunca directamente a otros.

    Este nodo ─────> HUB (servidor.py) <───── monitor
                          ^
                          └──────────────────── otros validadores

Lo que hace:
  1. Conectarse al hub con un nombre unico
  2. Esperar bloques candidatos del Monitor por canal privado
  3. Verificar que el hash del bloque sea correcto (verificar_hash)
  4. Verificar que la prueba de trabajo sea valida (resolver_acertijo)
  5. Votar en el chat publico:
     VOTE|block_id|YES  si paso todo
     VOTE|block_id|NO   si algo fallo

La funcion compute_block_hash tiene que ser exactamente igual a la del monitor
para que los hashes coincidan. Si fueran distintas, el validador nunca
aprobaria ningun bloque.

Para comparar hashes se usa hmac.compare_digest en lugar de == porque es mas
seguro contra ataques de timing (siempre tarda el mismo tiempo, no para
cuando encuentra el primer byte distinto).

Para manejar que TCP puede fragmentar los mensajes, se usa un buffer acumulado
que solo procesa lineas completas con \\n al final.

Cada bloque se procesa en su propio hilo para que al listener no se le acumulen
mensajes si llegan varios bloques al mismo tiempo.
"""

# importaciones estandar
import hashlib    # SHA-256 para verificar hashes
import hmac       # compare_digest: comparacion segura contra ataques de timing
import json       # parsear los mensajes de bloque
import socket     # conexion TCP con el hub
import sys        # argumentos de linea de comandos
import threading  # hilo listener y hilos por bloque

# configuracion de red
HOST: str = "127.0.0.1"   # direccion del hub
PORT: int = 5000           # puerto del hub

# control de bloques ya procesados
# sirve para no re-procesar el mismo bloque si el monitor lo reenvía por alguna razon
_processed_lock: threading.Lock = threading.Lock()
_processed_ids:  set[str]       = set()


# ─── funciones criptograficas ─────────────────────────────────────────────────

def compute_block_hash(previous_hash: str,
                       block_id:      str,
                       block_text:    str) -> str:
    """
    Calcula el hash SHA-256 del bloque.

    Esta funcion tiene que ser identica a la del monitor porque ambos
    nodos tienen que llegar al mismo resultado con los mismos datos.
    Si hay cualquier diferencia (espacios, orden de claves) el hash
    seria distinto y el validador nunca aprobaria nada.

    Usa JSON con sort_keys=True para que el orden de construccion del dict
    no afecte el resultado. Sin espacios extra para que los bytes sean exactos.
    """
    # representacion canonica: orden fijo, sin espacios, UTF-8
    canonical = json.dumps(
        {
            "block_id":      block_id,
            "block_text":    block_text,
            "previous_hash": previous_hash,
        },
        sort_keys=True,         # orden deterministico: mismo dict → mismo JSON
        ensure_ascii=False,     # preservar Unicode tal cual
        separators=(",", ":"),  # formato compacto (sin espacios → bytes exactos)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verificar_hash(previous_hash: str,
                   block_id:      str,
                   block_text:    str,
                   proposed_hash: str) -> bool:
    """
    Paso 1 de validacion: verifica que el hash del bloque sea correcto.

    Recalcula el hash con los datos recibidos y lo compara con el proposed_hash
    que mando el monitor. Si alguien modifico el bloque en transito, el hash
    recalculado sera completamente distinto.

    Se usa hmac.compare_digest en lugar de == para que la comparacion tome
    siempre el mismo tiempo sin importar cuantos bytes coincidan.
    Esto evita que alguien mida tiempos de respuesta para adivinar el hash.

    Devuelve True si el bloque esta integro, False si el hash no coincide.
    """
    # recalcular con la misma funcion que uso el monitor
    recalculated = compute_block_hash(previous_hash, block_id, block_text)

    # Comparacion en tiempo constante (defense against timing attacks)
    return hmac.compare_digest(recalculated, proposed_hash)


def resolver_acertijo(block_text:  str,
                      nonce:       int,
                      puzzle_hash: str) -> bool:
    """
    Paso 2 de validacion: verifica que la prueba de trabajo sea correcta.

    Recalcula SHA-256(nonce:block_text) y verifica dos cosas:
      1. que el hash recalculado sea igual al puzzle_hash del monitor
      2. que el puzzle_hash empiece con '0' (dificultad requerida)

    Las dos tienen que cumplirse. Si una falla, el bloque se rechaza.

    El ':' entre el nonce y el texto es el separador para que no haya
    ambiguedad al reconstruir el input.

    Devuelve True si la prueba de trabajo es valida, False si no.
    """
    # reconstruir exactamente el mismo input que uso el monitor al minar
    candidate = f"{nonce}:{block_text}".encode("utf-8")

    # recalcular el hash del acertijo
    computed_puzzle = hashlib.sha256(candidate).hexdigest()

    # condicion 1: el hash recalculado tiene que coincidir con el declarado
    # usamos compare_digest para comparacion en tiempo constante
    hashes_match = hmac.compare_digest(computed_puzzle, puzzle_hash)

    # condicion 2: el hash tiene que satisfacer la dificultad requerida
    satisfies_pow = puzzle_hash.startswith("0")

    # valido solo si ambas condiciones se cumplen
    return hashes_match and satisfies_pow


# ─── logica de procesamiento ─────────────────────────────────────────────────

def process_block(client_socket: socket.socket,
                  node_name:     str,
                  block_data:    dict) -> None:
    """
    Procesa un bloque candidato en un hilo separado.

    Extrae los datos del JSON, hace las dos verificaciones (hash y prueba de
    trabajo) y emite el voto en el chat publico para que el monitor lo cuente.

    El voto va al chat publico porque el monitor escucha el canal general
    para recolectar todos los votos. El servidor se lo redistribuye a todos
    incluyendo al monitor.
    """
    # extraer los campos del JSON del bloque
    block_id      = block_data.get("block_id",      "")
    sequence      = block_data.get("sequence",      "?/?")
    previous_hash = block_data.get("previous_hash", "")
    block_text    = block_data.get("text",          "")
    proposed_hash = block_data.get("proposed_hash", "")
    nonce         = block_data.get("nonce",         -1)
    puzzle_hash   = block_data.get("puzzle_hash",   "")

    # log de recepcion
    print(f"\n[{node_name}] ─── BLOQUE RECIBIDO ────────────────────")
    print(f"[{node_name}] ID       : {block_id}  ({sequence})")
    print(f"[{node_name}] Prev hash: {previous_hash[:16]}...")
    print(f"[{node_name}] PropHash : {proposed_hash[:16]}...")
    print(f"[{node_name}] Nonce    : {nonce}  puzzle={puzzle_hash[:12]}...")
    print(f"[{node_name}] Texto    : {block_text[:60].replace(chr(10), ' | ')}...")

    # paso 1: verificar el hash SHA-256 del bloque
    # recalcula el hash y lo compara con el que mando el monitor
    hash_ok = verificar_hash(previous_hash, block_id, block_text, proposed_hash)
    print(f"[{node_name}] verificar_hash()    -> {'OK si' if hash_ok else 'FALLO no'}")

    # paso 2: verificar la prueba de trabajo
    # recomputa el hash del nonce y chequea que empiece con el prefijo requerido
    puzzle_ok = resolver_acertijo(block_text, nonce, puzzle_hash)
    print(f"[{node_name}] resolver_acertijo() -> {'OK si' if puzzle_ok else 'FALLO no'}")

    # decidir el voto: tiene que pasar las dos verificaciones
    if hash_ok and puzzle_ok:
        vote_decision = "YES"
        label         = "BLOQUE_OK"
    else:
        vote_decision = "NO"
        label         = "BLOQUE_INVALIDO"
        # mostrar que fue lo que fallo para diagnostico
        if not hash_ok:
            print(f"[{node_name}] ALERTA: hash corrupto o bloque alterado en transito.")
        if not puzzle_ok:
            print(f"[{node_name}] ALERTA: acertijo PoW invalido o nonce incorrecto.")

    # emitir el voto en el canal publico
    # se agrega \n para que el buffer del monitor reconozca el fin de linea
    vote_message = f"VOTE|{block_id}|{vote_decision}"
    try:
        client_socket.sendall((vote_message + "\n").encode("utf-8"))
        print(f"[{node_name}] VOTO EMITIDO: {vote_message}  [{label}]")
    except OSError as e:
        print(f"[{node_name}] ERROR al emitir voto: {e}")

    print(f"[{node_name}] ─────────────────────────────────────────\n")


# ─── listener de mensajes ────────────────────────────────────────────────────

def handle_message(client_socket: socket.socket,
                   node_name:     str,
                   raw:           str) -> None:
    """
    Clasifica el mensaje recibido y actua en consecuencia.

    Casos:
      A) PRIVATE_FROM_monitor: {JSON}
         El monitor mando un bloque para validar. Se parsea el JSON
         y se lanza un hilo separado para no bloquear al listener.

      B) Cualquier otra cosa (votos de otros, anuncios del monitor, etc.)
         Solo se imprime en consola para que el operador este informado.

    Guarda los block_id ya procesados para ignorar duplicados por si
    el monitor reenvía algun bloque.
    """
    raw = raw.strip()
    if not raw:
        return   # linea vacia por el delimitador, ignorar

    # caso A: mensaje privado del monitor con un bloque
    if raw.startswith("PRIVATE_FROM_"):
        rest = raw[len("PRIVATE_FROM_"):]

        try:
            # separar "PRIVATE_FROM_sender: payload"
            sender, payload = rest.split(": ", 1)
        except ValueError:
            return   # formato raro, descartar

        # intentar parsear el payload como JSON de bloque
        try:
            block_data = json.loads(payload)
        except json.JSONDecodeError:
            # el mensaje privado no era JSON
            print(f"[{node_name}] Mensaje privado de '{sender}' (no-JSON): {payload[:80]}")
            return

        # verificar que sea un bloque y no otro tipo de mensaje JSON
        if block_data.get("type") != "BLOCK":
            return   # tipo desconocido, ignorar

        block_id = block_data.get("block_id", "")

        # anti-duplicados: si ya procesamos este bloque, ignorar
        with _processed_lock:
            if block_id in _processed_ids:
                print(f"[{node_name}] Bloque duplicado ignorado: {block_id}")
                return
            _processed_ids.add(block_id)   # marcar como procesado

        # lanzar hilo dedicado para no bloquear al listener
        t = threading.Thread(
            target=process_block,
            args=(client_socket, node_name, block_data),
            daemon=True,
        )
        t.start()

    # casos B/C/D: mensajes del chat general y del sistema
    else:
        # imprimir en consola para informacion del operador
        print(f"[{node_name}] << {raw}")


def receive_messages(client_socket: socket.socket, node_name: str) -> None:
    """
    Hilo daemon que escucha el socket continuamente.

    Usa buffer acumulado para manejar la fragmentacion de TCP.
    Solo procesa las lineas que tienen \\n al final (completas).
    El fragmento sin \\n se guarda para el siguiente recv().
    """
    buf = bytearray()   # buffer para acumular entre recv() consecutivos
    try:
        while True:
            chunk = client_socket.recv(65_536)

            if not chunk:
                # el servidor cerro la conexion
                print(f"\n[{node_name}] Servidor desconectado.")
                break

            buf.extend(chunk)

            # separar las lineas completas del fragmento incompleto
            text  = buf.decode("utf-8", errors="replace")
            parts = text.split("\n")
            # parts[-1] es lo que quedo sin \n, se guarda para el siguiente recv()
            buf   = bytearray(parts[-1].encode("utf-8"))

            # procesar solo las que tenian \n al final
            for line in parts[:-1]:
                handle_message(client_socket, node_name, line)

    except OSError:
        # socket cerrado (Ctrl+C u otro motivo)
        pass


# ─── punto de entrada ─────────────────────────────────────────────────────────

def start_validator() -> None:
    """
    Arranca el nodo validador.

    Lee el nombre del nodo (por argumento CLI o interactivamente),
    se conecta al hub, manda el nombre como primer mensaje y lanza
    el hilo listener. Luego espera hasta que el listener se detenga
    o el usuario presione Ctrl+C.

    El nombre se puede pasar como argumento:
        python nodo_cliente_procesadores_validadores.py validador1
    """
    # leer el nombre del nodo: argumento o input
    if len(sys.argv) > 1:
        node_name = sys.argv[1].strip()
    else:
        node_name = input("Nombre de este nodo validador: ").strip()

    if not node_name or " " in node_name:
        print("[ERROR] El nombre no puede estar vacio ni contener espacios.")
        return

    # conectar al hub
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[ERROR] No se pudo conectar a {HOST}:{PORT}. ¿Esta el servidor activo?")
        return

    # handshake: el primer mensaje al hub es el nombre con \n
    # el servidor espera ese \n para considerar el nombre completo
    client_socket.sendall((node_name + "\n").encode("utf-8"))

    print(f"\n[{node_name}] Conectado al hub en {HOST}:{PORT}.")
    print(f"[{node_name}] Esperando bloques del Monitor...  (Ctrl+C para salir)\n")

    # lanzar el hilo listener (daemon: muere con el proceso principal)
    listener = threading.Thread(
        target=receive_messages,
        args=(client_socket, node_name),
        daemon=True,
    )
    listener.start()

    # loop principal: solo espera, el procesamiento ocurre en los hilos
    try:
        while listener.is_alive():
            listener.join(timeout=1.0)   # revisar cada segundo si el hilo sigue vivo
    except KeyboardInterrupt:
        print(f"\n[{node_name}] Senal de salida recibida. Desconectando...")
    finally:
        try:
            client_socket.close()
        except OSError:
            pass
        print(f"[{node_name}] Nodo cerrado limpiamente.")


if __name__ == "__main__":
    start_validator()
