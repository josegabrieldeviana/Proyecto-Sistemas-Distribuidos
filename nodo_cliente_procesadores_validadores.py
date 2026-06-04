"""
NODO PROCESADOR / VALIDADOR
══════════════════════════════════════════════════════════════════
Rol en la red blockchain simulada:

  1. Conectarse al Hub (servidor) con un nombre de nodo único.
  2. Esperar bloques candidatos del Monitor vía canal privado (/w).
  3. Verificar la integridad criptográfica con  verificar_hash().
  4. Resolver el acertijo de prueba de trabajo con resolver_acertijo().
  5. Emitir el voto en el chat PÚBLICO para que el Monitor lo contabilice:
       VOTE|<block_id>|YES   →  bloque válido
       VOTE|<block_id>|NO    →  bloque inválido

Arquitectura de hilos:
  • Hilo principal    : interfaz de usuario mínima (estado, salida).
  • Hilo listener     : recibe mensajes del servidor indefinidamente.
  • Hilo por bloque   : procesa cada bloque en paralelo (uno por bloque recibido).

Uso:
  python nodo_cliente_procesadores_validadores.py
  └─ Ingresar nombre de nodo cuando se solicite (ej: validador1)
══════════════════════════════════════════════════════════════════
"""

# ── Importaciones estándar ────────────────────────────────────────────
import hashlib    # SHA-256 para verificar_hash y resolver_acertijo
import hmac       # hmac.compare_digest: comparación segura contra timing attacks
import json       # parseo de mensajes de bloque (formato JSON del Monitor)
import socket     # comunicación TCP con el servidor hub
import sys        # leer argumentos de línea de comandos
import threading  # hilo listener y hilo por bloque

# ── Configuración de red ──────────────────────────────────────────────
HOST: str        = "127.0.0.1"   # dirección del servidor hub
PORT: int        = 5000           # puerto TCP del hub

# ── Estado local del nodo ─────────────────────────────────────────────
# Conjunto de block_ids ya procesados; evita doble-procesamiento si
# el Monitor re-envía el mismo bloque (p. ej. por retransmisión).
_processed_lock: threading.Lock = threading.Lock()
_processed_ids:  set[str]       = set()


# ══════════════════════════════════════════════════════════════════════
#  FUNCIONES CRIPTOGRÁFICAS
# ══════════════════════════════════════════════════════════════════════

def compute_block_hash(previous_hash: str,
                       block_id:      str,
                       block_text:    str) -> str:
    """
    Recalcula el hash SHA-256 canónico del bloque.

    DEBE ser idéntica a la homónima del Monitor para que la verificación
    sea consistente entre nodos.

    Technique: serialización JSON con claves ordenadas.
      → Evita colisiones por intercambio/concatenación de campos:
          SHA-256('{"block_id":"A","block_text":"BC","previous_hash":"D"}')
          ≠  SHA-256('{"block_id":"AB","block_text":"C","previous_hash":"D"}')
        porque JSON preserva los límites de cada campo con comillas.

    Parámetros:
      previous_hash : hash del bloque anterior en la cadena (hex 64 chars).
      block_id      : identificador único del bloque (ej: "block_001").
      block_text    : contenido de las transacciones del bloque.

    Retorna: cadena hexadecimal SHA-256 de 64 caracteres.
    """
    # Construir la representación canónica con claves ordenadas y sin espacios
    canonical = json.dumps(
        {
            "block_id":      block_id,
            "block_text":    block_text,
            "previous_hash": previous_hash,
        },
        sort_keys=True,         # garantía de orden determinístico
        ensure_ascii=False,
        separators=(",", ":"),  # sin espacios → formato compacto canónico
    )
    # Codificar a bytes UTF-8 y calcular SHA-256
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verificar_hash(previous_hash: str,
                   block_id:      str,
                   block_text:    str,
                   proposed_hash: str) -> bool:
    """
    PASO 1 de validación — Integridad criptográfica del bloque.

    Recalcula SHA-256(datos del bloque) y lo compara con el hash
    propuesto por el Monitor.

    Razonamiento:
      • Si alguien alteró block_text en tránsito, el hash recalculado
        diferirá del proposed_hash → detección garantizada.
      • SHA-256 es resistente a colisiones: imposible forjar un bloque
        distinto que produzca el mismo hash (2^128 operaciones aprox.).

    Parámetros:
      previous_hash : hash del bloque anterior (encadenamiento).
      block_id      : identificador del bloque candidato.
      block_text    : contenido de las transacciones a verificar.
      proposed_hash : hash que el Monitor afirma que tiene el bloque.

    Retorna: True si el hash es correcto, False si fue alterado/corrupto.
    """
    # Recalcular localmente usando la misma función canónica del Monitor
    recalculated = compute_block_hash(previous_hash, block_id, block_text)

    # Comparación segura (constante en tiempo para evitar timing attacks)
    return hmac.compare_digest(recalculated, proposed_hash)


def resolver_acertijo(block_text:  str,
                      nonce:       int,
                      puzzle_hash: str) -> bool:
    """
    PASO 2 de validación — Prueba de Trabajo (Proof of Work ligera).

    Verifica que el Monitor realmente minó un nonce válido:
        SHA-256(str(nonce) + ":" + block_text)  ==  puzzle_hash
        Y  puzzle_hash  empieza con "0"  (dificultad 1 nibble)

    Razonamiento de la separación "nonce:texto":
      • nonce es siempre un entero → no puede contener ":"
      • La ":" separa inequívocamente nonce de block_text
      • Por tanto, distintos (nonce, block_text) producen distintos inputs
        → sin colisión por concatenación

    Parámetros:
      block_text  : contenido de las transacciones del bloque.
      nonce       : entero que el Monitor minó (N ≥ 0).
      puzzle_hash : SHA-256(str(nonce)+":"+block_text) que el Monitor calculó.

    Retorna: True si el acertijo es válido, False si fue manipulado.
    """
    # Reconstruir exactamente el mismo input que usó el Monitor
    candidate = f"{nonce}:{block_text}".encode("utf-8")

    # Calcular el hash del candidato (intento de solución del acertijo)
    computed_puzzle = hashlib.sha256(candidate).hexdigest()

    # Condición 1: el hash recalculado coincide con el declarado por el Monitor
    hashes_match = hmac.compare_digest(computed_puzzle, puzzle_hash)

    # Condición 2: el hash satisface la dificultad requerida (prefijo "0")
    satisfies_pow = puzzle_hash.startswith("0")

    # Ambas condiciones deben cumplirse para un acertijo válido
    return hashes_match and satisfies_pow


# ══════════════════════════════════════════════════════════════════════
#  LÓGICA DE PROCESAMIENTO DE BLOQUES
# ══════════════════════════════════════════════════════════════════════

def process_block(client_socket: socket.socket,
                  node_name:     str,
                  block_data:    dict) -> None:
    """
    Hilo de procesamiento para un único bloque candidato.
    Se ejecuta en paralelo con otros bloques si llegan simultáneamente.

    Flujo:
      1. Extraer campos del bloque JSON.
      2. verificar_hash()    → integridad SHA-256 del bloque.
      3. resolver_acertijo() → validez de la Prueba de Trabajo.
      4. Determinar veredicto: YES (ambos OK) / NO (alguno falló).
      5. Emitir voto en el chat general: VOTE|<block_id>|YES/NO

    Parámetros:
      client_socket : socket TCP hacia el servidor hub.
      node_name     : nombre de este nodo (para logs).
      block_data    : diccionario parseado del JSON recibido del Monitor.
    """
    # ── Extraer todos los campos del mensaje de bloque ───────────────
    block_id      = block_data.get("block_id",      "")
    sequence      = block_data.get("sequence",      "?/?")
    previous_hash = block_data.get("previous_hash", "")
    block_text    = block_data.get("text",          "")
    proposed_hash = block_data.get("proposed_hash", "")
    nonce         = block_data.get("nonce",         -1)
    puzzle_hash   = block_data.get("puzzle_hash",   "")

    print(f"\n[{node_name}] ─── BLOQUE RECIBIDO ────────────────────")
    print(f"[{node_name}] ID       : {block_id}  ({sequence})")
    print(f"[{node_name}] Prev hash: {previous_hash[:16]}…")
    print(f"[{node_name}] PropHash : {proposed_hash[:16]}…")
    print(f"[{node_name}] Nonce    : {nonce}  puzzle={puzzle_hash[:12]}…")
    print(f"[{node_name}] Texto    : {block_text[:60].replace(chr(10), ' | ')}…")

    # ── PASO 1: verificar_hash ───────────────────────────────────────
    # Recalcula SHA-256(canonical_block) y lo compara con proposed_hash.
    # Detecta cualquier alteración del contenido del bloque en tránsito.
    hash_ok = verificar_hash(previous_hash, block_id, block_text, proposed_hash)
    print(f"[{node_name}] verificar_hash()    → {'OK ✓' if hash_ok else 'FALLO ✗'}")

    # ── PASO 2: resolver_acertijo ────────────────────────────────────
    # Verifica que el nonce produce un hash con el prefijo de dificultad.
    # Confirma que el Monitor realizó la Prueba de Trabajo correctamente.
    puzzle_ok = resolver_acertijo(block_text, nonce, puzzle_hash)
    print(f"[{node_name}] resolver_acertijo() → {'OK ✓' if puzzle_ok else 'FALLO ✗'}")

    # ── Determinar veredicto ─────────────────────────────────────────
    # El bloque es válido solo si AMBAS verificaciones pasan.
    # Cualquier fallo individual es suficiente para rechazar el bloque.
    if hash_ok and puzzle_ok:
        vote_decision = "YES"
        label         = "BLOQUE_OK"
    else:
        vote_decision = "NO"
        label         = "BLOQUE_INVALIDO"
        # Reportar motivo específico del rechazo para diagnóstico
        if not hash_ok:
            print(f"[{node_name}] ALERTA: hash corrupto o bloque alterado.")
        if not puzzle_ok:
            print(f"[{node_name}] ALERTA: acertijo PoW inválido o nonce incorrecto.")

    # ── Emitir voto en el chat PÚBLICO ──────────────────────────────
    # El servidor difunde este mensaje a todos (incluido el Monitor).
    # Formato obligatorio: VOTE|<block_id>|YES  o  VOTE|<block_id>|NO
    vote_message = f"VOTE|{block_id}|{vote_decision}"
    try:
        client_socket.sendall(vote_message.encode("utf-8"))
        print(f"[{node_name}] VOTO EMITIDO: {vote_message}  [{label}]")
    except OSError as e:
        print(f"[{node_name}] ERROR al emitir voto: {e}")

    print(f"[{node_name}] ─────────────────────────────────────────\n")


# ══════════════════════════════════════════════════════════════════════
#  LISTENER DE MENSAJES
# ══════════════════════════════════════════════════════════════════════

def handle_message(client_socket: socket.socket,
                   node_name:     str,
                   raw:           str) -> None:
    """
    Clasifica y enruta un mensaje recibido del servidor.

    Casos posibles:
      A) PRIVATE_FROM_monitor: <JSON_bloque>
           → El Monitor envió un bloque para validar.
           → Lanzar hilo de procesamiento para no bloquear el listener.

      B) <otro_nodo>: VOTE|block_xxx|YES/NO
           → Voto público de otro validador en el chat general.
           → Solo imprimir (el Monitor es quien contabiliza).

      C) monitor: CONSENSO_ALCANZADO …  o  monitor: BIFURCACION_DETECTADA …
           → Notificación de resultado desde el Monitor.
           → Solo imprimir para conocimiento del nodo.

      D) [SERVIDOR] …
           → Notificación administrativa del hub (conexiones, etc.).
           → Solo imprimir.

    Parámetros:
      client_socket : socket TCP (necesario para enviar el voto tras procesar).
      node_name     : nombre de este nodo validador.
      raw           : línea de texto recibida (ya sin '\n').
    """
    raw = raw.strip()
    if not raw:
        return   # ignorar líneas vacías (artefactos de separadores TCP)

    # ── CASO A: mensaje privado del Monitor ─────────────────────────
    if raw.startswith("PRIVATE_FROM_"):
        # Separar "PRIVATE_FROM_<sender>: <payload>" en sus componentes
        rest = raw[len("PRIVATE_FROM_"):]

        try:
            sender, payload = rest.split(": ", 1)
        except ValueError:
            # Formato inesperado; descartar silenciosamente
            return

        # Intentar parsear el payload como JSON → mensaje de bloque
        try:
            block_data = json.loads(payload)
        except json.JSONDecodeError:
            # El mensaje privado no era JSON (podría ser texto libre)
            print(f"[{node_name}] Mensaje privado de '{sender}' (no-JSON): {payload[:80]}")
            return

        # Verificar que es efectivamente un mensaje de tipo BLOCK
        if block_data.get("type") != "BLOCK":
            # Mensaje JSON privado pero de otro tipo; ignorar por ahora
            return

        block_id = block_data.get("block_id", "")

        # Protección anti-duplicados: si ya procesamos este bloque, ignorar
        with _processed_lock:
            if block_id in _processed_ids:
                print(f"[{node_name}] Bloque duplicado ignorado: {block_id}")
                return
            _processed_ids.add(block_id)

        # Lanzar un hilo dedicado para no bloquear el listener mientras
        # se realiza la criptografía (permite procesar otro bloque en paralelo)
        t = threading.Thread(
            target=process_block,
            args=(client_socket, node_name, block_data),
            daemon=True,
        )
        t.start()

    # ── CASO B / C / D: mensajes del chat general / sistema ─────────
    else:
        # Simplemente mostrar en consola para auditoría del operador
        # (votos de otros validadores, consensos, desconexiones, etc.)
        print(f"[{node_name}] << {raw}")


def receive_messages(client_socket: socket.socket, node_name: str) -> None:
    """
    Hilo daemon: escucha el socket indefinidamente y procesa todas
    las líneas de mensajes que llegan del servidor.

    TCP es un protocolo de stream: un solo recv() puede devolver
    varias líneas fusionadas por el SO.  Por eso se divide siempre
    por '\n' antes de procesar.
    """
    try:
        while True:
            # Leer hasta 64 KiB del buffer TCP
            data = client_socket.recv(65_536)

            if not data:
                # El servidor cerró la conexión (FIN TCP)
                print(f"\n[{node_name}] Servidor desconectado.")
                break

            # Decodificar y dividir en líneas individuales
            text  = data.decode("utf-8", errors="replace")
            lines = text.split("\n")

            for line in lines:
                handle_message(client_socket, node_name, line)

    except OSError:
        # Socket cerrado externamente (p. ej. al presionar Ctrl+C)
        pass


# ══════════════════════════════════════════════════════════════════════
#  PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════

def start_validator() -> None:
    """
    Conecta el nodo validador al hub y lanza el hilo listener.
    El nombre del nodo se puede pasar como argumento en línea de comandos
    o se solicita de forma interactiva.
    """
    # ── Obtener nombre del nodo ──────────────────────────────────────
    if len(sys.argv) > 1:
        # Uso: python nodo_cliente_procesadores_validadores.py validador1
        node_name = sys.argv[1].strip()
    else:
        node_name = input("Nombre de este nodo validador: ").strip()

    if not node_name or " " in node_name:
        print("[ERROR] El nombre no puede estar vacío ni contener espacios.")
        return

    # ── Conectar al servidor hub ─────────────────────────────────────
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[ERROR] No se pudo conectar a {HOST}:{PORT}. ¿Está el servidor activo?")
        return

    # Registro: el primer mensaje enviado es el nombre del nodo
    client_socket.sendall(node_name.encode("utf-8"))

    print(f"\n[{node_name}] Conectado al hub en {HOST}:{PORT}.")
    print(f"[{node_name}] Esperando bloques del Monitor…  (Ctrl+C para salir)\n")

    # ── Lanzar hilo listener (daemon → muere con el proceso principal) ─
    listener = threading.Thread(
        target=receive_messages,
        args=(client_socket, node_name),
        daemon=True,
    )
    listener.start()

    # ── Loop principal: simple espera con opción de salida limpia ────
    # El procesamiento real ocurre en los hilos de listener y por bloque.
    try:
        while listener.is_alive():
            listener.join(timeout=1.0)   # revisar cada segundo
    except KeyboardInterrupt:
        print(f"\n[{node_name}] Señal de salida recibida. Desconectando…")
    finally:
        try:
            client_socket.close()
        except OSError:
            pass
        print(f"[{node_name}] Nodo cerrado limpiamente.")


if __name__ == "__main__":
    start_validator()
