"""
NODO PROCESADOR / VALIDADOR
================================================================================
ROL EN LA ARQUITECTURA ESTRELLA
--------------------------------------------------------------------------------
Cada instancia de este modulo es un nodo hoja de la topologia en estrella:
se conecta UNICAMENTE al hub (servidor.py), nunca directamente a otros nodos.

  Topologia:
      Este nodo ─────> HUB (servidor.py) <───── monitor
                            ^
                            └──────────────────── otros validadores

RESPONSABILIDADES:
  1. Conectarse al hub con un nombre unico.
  2. Esperar bloques candidatos enviados por el Monitor via canal privado.
  3. Verificar la INTEGRIDAD CRIPTOGRAFICA del bloque (verificar_hash).
  4. Verificar la PRUEBA DE TRABAJO (resolver_acertijo).
  5. Emitir el voto en el CHAT PUBLICO para que el Monitor lo contabilice:
       VOTE|<block_id>|YES   (ambas verificaciones superadas)
       VOTE|<block_id>|NO    (alguna verificacion fallo)

CRIPTOGRAFIA SHA-256 — DISEÑO ANTI-COLISION
--------------------------------------------------------------------------------
compute_block_hash() — IDENTICA a la del Monitor:
  Ambos nodos DEBEN usar exactamente la misma funcion para que el hash
  recalculado localmente sea identico al proposed_hash del Monitor.
  Si hubiera la minima diferencia (orden de claves, espacios en JSON,
  codificacion), el validador nunca aprobariam un bloque valido.

  Mecanismo anti-colision:
    - JSON con sort_keys=True: orden deterministico de claves.
    - separators=(',', ':'):   forma compacta sin espacios extra.
    - ensure_ascii=False:      Unicode preservado byte a byte.
  Resultado: ("ab","cd","ef") y ("a","bcd","ef") producen JSON distintos
  porque las comillas JSON delimitan cada campo → hashes distintos.

verificar_hash() — Comparacion segura con hmac.compare_digest:
  Usa hmac.compare_digest en lugar de '==' porque:
    - Comparacion en tiempo CONSTANTE: no se detiene al primer byte distinto.
    - Elimina ataques de timing: un atacante no puede deducir cuantos bytes
      coinciden midiendo el tiempo de respuesta.

resolver_acertijo() — Separador ':' anti-colision en PoW:
  El nonce es siempre un entero → nunca contiene ':'.
  Por tanto, SHA-256(str(N) + ':' + text) no tiene ambiguedad:
    nonce=1, text="2:TX" → input="1:2:TX"
    nonce=12, text="TX"  → input="12:TX"
  Son inputs distintos y producen hashes distintos.
  Sin el separador podria haber colision por concatenacion de prefijo.

BUFFER TCP
--------------------------------------------------------------------------------
receive_messages() acumula bytes en un bytearray y solo procesa lineas
completas (terminadas en '\\n'). Resuelve la fragmentacion y fusion de
paquetes inherente al protocolo de stream TCP.

MODELO DE CONCURRENCIA
--------------------------------------------------------------------------------
  Hilo principal  : espera Ctrl+C, no hace procesamiento.
  Hilo listener   : receive_messages() — escucha al servidor.
  Hilo por bloque : process_block()    — lanzado por cada bloque recibido.

El hilo listener nunca se bloquea esperando el resultado criptografico:
lanza un hilo dedicado por bloque que puede correr en paralelo si llegan
varios bloques simultaneamente. El listener sigue disponible para nuevos
mensajes mientras se procesa un bloque anterior.
================================================================================
"""

# ── Importaciones estandar ────────────────────────────────────────────────────
import hashlib    # SHA-256: verificar_hash y resolver_acertijo
import hmac       # hmac.compare_digest: comparacion segura en tiempo constante
import json       # parseo de mensajes de bloque en formato JSON
import socket     # comunicacion TCP con el hub
import sys        # argumentos de linea de comandos
import threading  # hilo listener y hilo por bloque

# ── Configuracion de red ──────────────────────────────────────────────────────
HOST: str = "127.0.0.1"   # direccion del hub (servidor.py)
PORT: int = 5000           # puerto TCP del hub

# ── Estado local del nodo ─────────────────────────────────────────────────────
# Proteccion anti-duplicados: evita re-procesar el mismo bloque si
# el Monitor lo reenvía (retransmision por timeout de alguna ronda anterior).
_processed_lock: threading.Lock = threading.Lock()
_processed_ids:  set[str]       = set()


# ════════════════════════ FUNCIONES CRIPTOGRAFICAS ═══════════════════════════

def compute_block_hash(previous_hash: str,
                       block_id:      str,
                       block_text:    str) -> str:
    """
    Recalcula el hash SHA-256 canonico del bloque.

    IDENTICA a la funcion homologa del Monitor — este es el contrato
    fundamental de la red: ambos nodos usan la misma funcion canonica
    para que la verificacion sea consistente.

    DISEÑO ANTI-COLISION POR SERIALIZACION JSON:
      Se construye un dict con los tres campos del bloque y se serializa
      a JSON con:
        - sort_keys=True       : orden de claves siempre alfabetico
                                 (block_id < block_text < previous_hash)
        - separators=(',',':') : forma compacta, sin espacios extra
        - ensure_ascii=False   : Unicode preservado

      Esto garantiza que cambiar cualquier campo cambia el JSON y por
      tanto el hash. Ademas, los campos no pueden confundirse entre si
      porque JSON los enmarca en comillas:

        {"block_id":"A","block_text":"BC","previous_hash":"D"}
        ≠ {"block_id":"AB","block_text":"C","previous_hash":"D"}

      Los bytes son distintos (la 'A' de block_id esta seguida de '"',
      no de 'B'), por lo que los SHA-256 son distintos aunque el
      contenido total parezca similar.

    Retorna: hexdigest SHA-256 de 64 caracteres (256 bits).
    """
    # Representacion canonica: orden fijo, sin espacios, UTF-8
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
    PASO 1 de validacion — Integridad criptografica del bloque.

    Recalcula localmente SHA-256(bloque canonico) y lo compara con
    el proposed_hash que envio el Monitor.

    POR QUE DETECTA ALTERACIONES:
      SHA-256 tiene resistencia a preimagen y resistencia a colisiones.
      - Resistencia a preimagen: dado proposed_hash, es computacionalmente
        inviable construir datos distintos que produzcan ese mismo hash.
        (Requeriria aprox. 2^256 operaciones.)
      - Resistencia a colisiones: dado un bloque, es computacionalmente
        inviable encontrar otro bloque distinto con el mismo hash.
        (Requeriria aprox. 2^128 operaciones — birthday paradox.)

      Si alguien altero block_text en transito, el validador recalculara
      un hash completamente distinto al proposed_hash. La comparacion
      fallara y el validador emitira VOTE|block_id|NO.

    POR QUE hmac.compare_digest EN LUGAR DE '==':
      La comparacion de strings en Python termina en el primer byte distinto.
      Un atacante podria medir el tiempo de respuesta para deducir cuantos
      bytes del hash recalculado coinciden con el propuesto, obteniendo
      informacion parcial del hash. hmac.compare_digest compara SIEMPRE
      todos los bytes, tomando tiempo constante independientemente del resultado.

    Retorna True si el bloque es integro, False si fue modificado.
    """
    # Recalcular con la misma funcion canonica que uso el Monitor
    recalculated = compute_block_hash(previous_hash, block_id, block_text)

    # Comparacion en tiempo constante (defense against timing attacks)
    return hmac.compare_digest(recalculated, proposed_hash)


def resolver_acertijo(block_text:  str,
                      nonce:       int,
                      puzzle_hash: str) -> bool:
    """
    PASO 2 de validacion — Prueba de Trabajo (Proof of Work ligera).

    Verifica que el Monitor realmente encontro un nonce valido:
        SHA-256(str(nonce) + ':' + block_text) == puzzle_hash
        AND puzzle_hash.startswith('0')

    AMBAS condiciones deben cumplirse. Esto previene dos ataques:
      A) El Monitor declara un puzzle_hash falso que empieza con '0'
         pero no corresponde al nonce y block_text dados.
         → La primera condicion (igualdad de hashes) lo detecta.
      B) El Monitor envía un nonce que produce un hash valido pero no
         satisface la dificultad requerida (no empieza con '0').
         → La segunda condicion (prefijo) lo detecta.

    DISEÑO ANTI-COLISION DEL SEPARADOR ':':
      El nonce es un entero no negativo: nunca puede contener ':'.
      Usar ':' como separador entre nonce y block_text garantiza que
      el input al SHA-256 es inequivoco:

        nonce=1,  text="0:TX ABC"  →  SHA-256("1:0:TX ABC")
        nonce=10, text="TX ABC"    →  SHA-256("10:TX ABC")

      Estos son inputs distintos aunque la concatenacion sin separador
      ("10:TXABC" vs "10TXABC") podria crear ambiguedad en otros esquemas.
      Con ':' y nonce entero, no hay posibilidad de colision de prefijo.

    DIFICULTAD ACTUAL:
      NONCE_PREFIX = "0": el hash hexadecimal debe empezar con '0'.
      Probabilidad: 1/16 por intento → promedio ~16 intentos (trivial).
      En Bitcoin la dificultad equivale a ~18 ceros iniciales.

    Retorna True si el acertijo es valido, False si fue manipulado.
    """
    # Reconstruir exactamente el mismo input que uso el Monitor al minar
    candidate = f"{nonce}:{block_text}".encode("utf-8")

    # Recalcular el hash del acertijo localmente
    computed_puzzle = hashlib.sha256(candidate).hexdigest()

    # Condicion 1: el hash recalculado debe coincidir con el declarado
    # Uso de compare_digest: comparacion en tiempo constante
    hashes_match = hmac.compare_digest(computed_puzzle, puzzle_hash)

    # Condicion 2: el hash debe satisfacer la dificultad PoW requerida
    satisfies_pow = puzzle_hash.startswith("0")

    # El bloque es valido solo si AMBAS condiciones se cumplen
    return hashes_match and satisfies_pow


# ════════════════════════ LOGICA DE PROCESAMIENTO ════════════════════════════

def process_block(client_socket: socket.socket,
                  node_name:     str,
                  block_data:    dict) -> None:
    """
    Hilo de procesamiento para un unico bloque candidato.

    Se ejecuta en un hilo dedicado lanzado por handle_message() para no
    bloquear al listener mientras se realizan las operaciones criptograficas.
    Multiples bloques pueden procesarse en paralelo si llegan simultaneamente.

    FLUJO:
      1. Extraer los 7 campos del JSON recibido del Monitor.
      2. verificar_hash()    → integridad SHA-256 del bloque.
      3. resolver_acertijo() → validez de la Prueba de Trabajo.
      4. Determinar veredicto:
           YES (BLOQUE_OK)       : ambas verificaciones superadas.
           NO  (BLOQUE_INVALIDO) : alguna verificacion fallo.
      5. Emitir voto en el chat PUBLICO con '\n' para que llegue completo:
           VOTE|<block_id>|YES   o   VOTE|<block_id>|NO

    El voto se emite en el chat PUBLICO (no privado) porque el Monitor
    escucha el canal general para contabilizar votos de todos los validadores.
    El servidor hace broadcast del voto a todos los nodos, incluyendo al Monitor.
    """
    # ── Extraer campos del JSON recibido ─────────────────────────────
    block_id      = block_data.get("block_id",      "")
    sequence      = block_data.get("sequence",      "?/?")
    previous_hash = block_data.get("previous_hash", "")
    block_text    = block_data.get("text",          "")
    proposed_hash = block_data.get("proposed_hash", "")
    nonce         = block_data.get("nonce",         -1)
    puzzle_hash   = block_data.get("puzzle_hash",   "")

    # Log de recepcion
    print(f"\n[{node_name}] ─── BLOQUE RECIBIDO ────────────────────")
    print(f"[{node_name}] ID       : {block_id}  ({sequence})")
    print(f"[{node_name}] Prev hash: {previous_hash[:16]}...")
    print(f"[{node_name}] PropHash : {proposed_hash[:16]}...")
    print(f"[{node_name}] Nonce    : {nonce}  puzzle={puzzle_hash[:12]}...")
    print(f"[{node_name}] Texto    : {block_text[:60].replace(chr(10), ' | ')}...")

    # ── PASO 1: verificar integridad SHA-256 del bloque ───────────────
    # Recalcula SHA-256(JSON canonico del bloque) y compara con proposed_hash.
    # Detecta cualquier modificacion del contenido en transito.
    hash_ok = verificar_hash(previous_hash, block_id, block_text, proposed_hash)
    print(f"[{node_name}] verificar_hash()    -> {'OK si' if hash_ok else 'FALLO no'}")

    # ── PASO 2: verificar Prueba de Trabajo ───────────────────────────
    # Recomputa SHA-256(nonce:block_text) y verifica el prefijo requerido.
    # Confirma que el Monitor realizo el trabajo computacional honestamente.
    puzzle_ok = resolver_acertijo(block_text, nonce, puzzle_hash)
    print(f"[{node_name}] resolver_acertijo() -> {'OK si' if puzzle_ok else 'FALLO no'}")

    # ── Determinar veredicto ─────────────────────────────────────────
    # El bloque es valido SOLO si AMBAS verificaciones son exitosas.
    # Un solo fallo es suficiente para rechazar el bloque.
    if hash_ok and puzzle_ok:
        vote_decision = "YES"
        label         = "BLOQUE_OK"
    else:
        vote_decision = "NO"
        label         = "BLOQUE_INVALIDO"
        # Reportar la causa especifica del rechazo para diagnostico
        if not hash_ok:
            print(f"[{node_name}] ALERTA: hash corrupto o bloque alterado en transito.")
        if not puzzle_ok:
            print(f"[{node_name}] ALERTA: acertijo PoW invalido o nonce incorrecto.")

    # ── Emitir voto en el CHAT PUBLICO ────────────────────────────────
    # El servidor difunde este mensaje a todos, incluyendo al Monitor.
    # Se agrega '\n' para que el buffer acumulado del Monitor reconozca
    # el fin de la linea y procese el voto completo.
    vote_message = f"VOTE|{block_id}|{vote_decision}"
    try:
        client_socket.sendall((vote_message + "\n").encode("utf-8"))
        print(f"[{node_name}] VOTO EMITIDO: {vote_message}  [{label}]")
    except OSError as e:
        print(f"[{node_name}] ERROR al emitir voto: {e}")

    print(f"[{node_name}] ─────────────────────────────────────────\n")


# ════════════════════════ LISTENER DE MENSAJES ══════════════════════════════

def handle_message(client_socket: socket.socket,
                   node_name:     str,
                   raw:           str) -> None:
    """
    Clasifica y enruta cada linea de mensaje recibida del servidor.

    CASOS POSIBLES:

      A) PRIVATE_FROM_monitor: <JSON_bloque>
           El Monitor envio un bloque para validar via canal privado /w.
           Se parsea el JSON, se verifica que sea tipo BLOCK y se lanza
           un hilo dedicado para no bloquear al listener.

      B) <otro_nodo>: VOTE|block_xxx|YES/NO
           Voto publico de otro validador en el chat general.
           Solo se imprime: el Monitor es quien contabiliza los votos,
           no los otros validadores.

      C) monitor: CONSENSO_ALCANZADO ...  o  BIFURCACION_DETECTADA ...
           Notificacion de resultado del Monitor tras el consenso.
           Solo se imprime para informacion del operador del nodo.

      D) [SERVIDOR] ...
           Notificacion administrativa del hub (conexiones, desconexiones).
           Solo se imprime.

    PROTECCION ANTI-DUPLICADOS:
      _processed_ids guarda los block_ids ya procesados.
      Si el Monitor reenvía un bloque (por timeout de alguna ronda anterior
      o retransmision), el segundo envio se descarta sin lanzar otro hilo.
    """
    raw = raw.strip()
    if not raw:
        return   # linea vacia: artefacto del delimitador, ignorar

    # ── CASO A: mensaje privado del Monitor ──────────────────────────
    if raw.startswith("PRIVATE_FROM_"):
        rest = raw[len("PRIVATE_FROM_"):]

        try:
            # Separar "PRIVATE_FROM_<sender>: <payload>"
            sender, payload = rest.split(": ", 1)
        except ValueError:
            return   # formato inesperado, descartar

        # Intentar parsear el payload como JSON de bloque
        try:
            block_data = json.loads(payload)
        except json.JSONDecodeError:
            # El mensaje privado no era JSON (texto libre u otro protocolo)
            print(f"[{node_name}] Mensaje privado de '{sender}' (no-JSON): {payload[:80]}")
            return

        # Verificar que sea un mensaje de tipo BLOCK (no otro tipo de JSON)
        if block_data.get("type") != "BLOCK":
            return   # tipo desconocido, ignorar por ahora

        block_id = block_data.get("block_id", "")

        # Anti-duplicados: verificar si ya procesamos este bloque
        with _processed_lock:
            if block_id in _processed_ids:
                print(f"[{node_name}] Bloque duplicado ignorado: {block_id}")
                return
            _processed_ids.add(block_id)   # marcar como procesado

        # Lanzar hilo dedicado: el listener no se bloquea durante el calculo
        # criptografico (puede tardar si hay muchas transacciones o dificultad alta)
        t = threading.Thread(
            target=process_block,
            args=(client_socket, node_name, block_data),
            daemon=True,
        )
        t.start()

    # ── CASOS B / C / D: mensajes del chat general y del sistema ─────
    else:
        # Mostrar en consola para auditoria del operador del nodo
        # (votos de otros validadores, anuncios de consenso, desconexiones)
        print(f"[{node_name}] << {raw}")


def receive_messages(client_socket: socket.socket, node_name: str) -> None:
    """
    Hilo daemon: escucha el socket indefinidamente y procesa lineas completas.

    BUFFER ACUMULADO — solucion al problema TCP stream:
      El protocolo TCP garantiza entrega ORDENADA de bytes, pero NO garantiza
      que los bytes lleguen agrupados en los mismos paquetes en que se enviaron.
      Un solo recv() puede devolver:
        a) Menos bytes que una linea completa  → no procesar, esperar mas
        b) Exactamente una linea completa      → procesar normalmente
        c) Varias lineas fusionadas            → separar y procesar cada una
        d) Una linea y media                  → procesar la completa, acumular la mitad

      Sin buffer, el caso (a) generaria una linea incompleta que al parsearse
      como JSON arrojaria json.JSONDecodeError y el bloque se perderia.

    IMPLEMENTACION:
      buf acumula bytes entre llamadas a recv().
      Despues de cada recv(), se decodifica buf, se parte por '\\n' y solo
      se procesan los fragmentos con '\\n' al final (lineas completas).
      El ultimo fragmento (posiblemente incompleto) se re-codifica en buf
      y espera el siguiente recv().
    """
    buf = bytearray()   # buffer acumulado entre recv() consecutivos
    try:
        while True:
            chunk = client_socket.recv(65_536)

            if not chunk:
                # El servidor cerro la conexion (FIN TCP)
                print(f"\n[{node_name}] Servidor desconectado.")
                break

            buf.extend(chunk)

            # Separar lineas completas del fragmento posiblemente incompleto
            text  = buf.decode("utf-8", errors="replace")
            parts = text.split("\n")
            # parts[-1] es el fragmento sin '\n' final → guardarlo en buf
            buf   = bytearray(parts[-1].encode("utf-8"))

            # Procesar solo las lineas que tenian '\n' al final (completas)
            for line in parts[:-1]:
                handle_message(client_socket, node_name, line)

    except OSError:
        # Socket cerrado externamente (Ctrl+C u otro motivo)
        pass


# ════════════════════════ PUNTO DE ENTRADA ═══════════════════════════════════

def start_validator() -> None:
    """
    Conecta el nodo validador al hub y lanza el hilo listener.

    SECUENCIA DE INICIO:
      1. Leer nombre del nodo (argumento de linea de comandos o input).
      2. Abrir socket TCP y conectar al hub.
      3. Enviar nombre con '\\n' (handshake inicial del hub).
      4. Lanzar hilo daemon receive_messages.
      5. Esperar en el loop principal (el procesamiento ocurre en hilos).

    El nombre puede pasarse como primer argumento:
        python nodo_cliente_procesadores_validadores.py validador1
    O se solicita interactivamente si no se proporciona.
    """
    # Obtener nombre del nodo: argumento CLI o input interactivo
    if len(sys.argv) > 1:
        node_name = sys.argv[1].strip()
    else:
        node_name = input("Nombre de este nodo validador: ").strip()

    if not node_name or " " in node_name:
        print("[ERROR] El nombre no puede estar vacio ni contener espacios.")
        return

    # Conectar al hub TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[ERROR] No se pudo conectar a {HOST}:{PORT}. ¿Esta el servidor activo?")
        return

    # Handshake: el primer mensaje al hub es el nombre del nodo con '\n'
    # El buffer del servidor espera el delimitador '\n' para leer el nombre completo
    client_socket.sendall((node_name + "\n").encode("utf-8"))

    print(f"\n[{node_name}] Conectado al hub en {HOST}:{PORT}.")
    print(f"[{node_name}] Esperando bloques del Monitor...  (Ctrl+C para salir)\n")

    # Lanzar hilo listener daemon (muere automaticamente con el proceso principal)
    listener = threading.Thread(
        target=receive_messages,
        args=(client_socket, node_name),
        daemon=True,
    )
    listener.start()

    # Loop principal: simple espera; el procesamiento ocurre en los hilos
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
