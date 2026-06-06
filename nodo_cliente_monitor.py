"""
NODO MONITOR — Orquestador y Coordinador de Consenso
================================================================================
ROL EN LA ARQUITECTURA ESTRELLA
--------------------------------------------------------------------------------
El Monitor es el cliente "maestro" de la red. Se conecta al hub (servidor.py)
igual que cualquier otro nodo, pero tiene la responsabilidad de:

  1. Segmentar el archivo de transacciones en bloques candidatos.
  2. Consultar al hub los nodos REALMENTE conectados para calcular el quorum.
  3. Pre-computar la cadena de hashes y minar nonces (Proof of Work ligera).
  4. Distribuir bloques a los validadores activos via mensajes privados (/w).
  5. Escuchar el chat publico y contabilizar votos VOTE|block_id|YES/NO.
  6. Confirmar bloques en el ledger en ORDEN ESTRICTO de envio.
  7. Detectar y clasificar bifurcaciones (forks) segun su causa.
  8. Notificar a la red: CONSENSO_ALCANZADO / BIFURCACION_DETECTADA.

QUORUM DINAMICO REAL
--------------------------------------------------------------------------------
Antes de distribuir, el Monitor envia '/who' al hub y espera la respuesta
con la lista de nodos realmente conectados. Filtra los validadores pedidos
por el usuario contra esa lista. El quorum se calcula solo sobre validadores
que estan en linea, no sobre nombres escritos por el usuario.

  quorum = floor(N / 2) + 1    donde N = validadores activos confirmados

Esto garantiza que un validador caido o inexistente no infle artificialmente
el denominador del quorum ni bloquee el proceso de consenso.

CONFIRMACION EN ORDEN ESTRICTO
--------------------------------------------------------------------------------
Los bloques se distribuyen todos a la vez (para paralelizar validacion), pero
se confirman en el ledger en el MISMO ORDEN en que fueron enviados.

Estructuras de control:
  _confirm_order : lista con el orden de envio de block_ids
  _confirm_queue : dict con bloques que alcanzaron quorum pero esperan turno

Si block_002 alcanza quorum antes que block_001:
  - Se encola en _confirm_queue
  - No se inserta en el ledger hasta que block_001 haya confirmado primero
  - Asi previous_hash siempre corresponde al hash que los validadores vieron

BIFURCACIONES DETECTADAS
--------------------------------------------------------------------------------
Se modelan tres tipos de bifurcacion real:
  1. 'votos_divididos'       : matematicamente imposible alcanzar quorum
                               con los votos restantes (deteccion temprana).
  2. 'quorum_no_alcanzado'   : todos votaron, YES < quorum.
  3. 'timeout'               : no todos respondieron en BLOCK_TIMEOUT_SECONDS.

CRIPTOGRAFIA SHA-256 CON CONTROL DE COLISIONES
--------------------------------------------------------------------------------
compute_block_hash() usa serializacion JSON con claves ordenadas:
  - sort_keys=True         → orden deterministico: mismo input → mismo hash
  - separators=(',', ':')  → formato compacto sin espacios extra
  - ensure_ascii=False     → soporte completo de Unicode (UTF-8)
  - Colision por concatenacion imposible: JSON enmarca cada campo con comillas
    → ("ab","cd") y ("a","bcd") producen JSON distintos → hashes distintos

mine_nonce() usa separador ':' entre nonce y texto:
  - nonce es siempre un entero → no puede contener ':'
  - Por tanto, no existe ambiguedad ni colision de prefijo posible

BUFFER TCP
--------------------------------------------------------------------------------
receive_messages() acumula bytes en un bytearray y solo procesa lineas
completas (terminadas en '\\n'). Resuelve la fragmentacion y fusion de
paquetes inherente al protocolo de stream TCP.

MODELO DE HILOS
--------------------------------------------------------------------------------
  - Hilo principal     : loop interactivo de usuario (input).
  - Hilo daemon        : receive_messages() escucha al servidor.
  - Hilo por bloque    : NO en el monitor; los validadores lo usan.
  - threading.Timer    : uno por bloque para detectar timeout.
================================================================================
"""

import hashlib
import json
import math
import re
import socket
import threading
from pathlib import Path

# ── Configuracion de red ──────────────────────────────────────────────────────
HOST:         str = "127.0.0.1"   # direccion del hub (servidor.py)
PORT:         int = 5000           # puerto TCP del hub
MONITOR_NAME: str = "monitor"     # nombre de registro en la red

# ── Parametros de bloque y consenso ──────────────────────────────────────────
BLOCK_LINE_COUNT:      int = 5    # lineas de transacciones por bloque
BLOCK_TIMEOUT_SECONDS: int = 30   # segundos antes de declarar timeout/bifurcacion
NONCE_PREFIX:          str = "0"  # prefijo requerido en el hash PoW (dificultad 1 nibble)

# ── Estado global del Monitor (protegido por state_lock) ─────────────────────
state_lock: threading.Lock = threading.Lock()

# Bloques en vuelo: esperando votos de validadores
# Estructura: { block_id → { text, validators, voters, yes_votes, no_votes,
#                             quorum, proposed_hash, previous_hash, timer } }
pending_blocks: dict = {}

# Ledger definitivo: lista de bloques confirmados en orden
# Cada entrada: { block_id, hash, previous_hash, text, yes_votes, quorum }
confirmed_chain: list = []

# Cola de confirmacion ordenada:
#   _confirm_order : orden de envio de bloques (block_001, block_002, ...)
#   _confirm_queue : bloques con quorum alcanzado esperando su turno
_confirm_order: list = []
_confirm_queue: dict = {}

# Variables auxiliares para el mecanismo de consulta /who al servidor
_who_response: str | None      = None
_who_event:    threading.Event = threading.Event()


# ══════════════════════════ CRIPTOGRAFIA SHA-256 ═════════════════════════════

def compute_block_hash(previous_hash: str,
                       block_id:      str,
                       block_text:    str) -> str:
    """
    Calcula el hash SHA-256 canonico del bloque.

    DISEÑO ANTI-COLISION:
    Se usa serializacion JSON con claves ordenadas en lugar de concatenacion
    simple de strings. Esto es fundamental para prevenir colisiones:

      Concatenacion simple (VULNERABLE):
        hash("block_001" + "TX ABC" + "0000...") podria colisionar con
        hash("block_0"   + "01TX ABC" + "0000...")
        porque los bytes son identicos si se concatenan sin separadores.

      JSON con sort_keys (SEGURO):
        '{"block_id":"block_001","block_text":"TX ABC","previous_hash":"0000..."}'
        nunca puede confundirse con otro arreglo de los mismos datos porque
        JSON enmarca cada valor entre comillas y los separa con ':' y ','.
        Un campo no puede "deslizarse" dentro del siguiente.

    DETERMINISTMO:
      sort_keys=True garantiza que independientemente del orden en que se
      construyo el dict, el JSON siempre tiene las claves en orden alfabetico.
      Esto es critico: Monitor y Validadores deben producir exactamente el
      mismo string canonico para obtener el mismo SHA-256.

    CODIFICACION:
      ensure_ascii=False + .encode('utf-8') garantiza que caracteres Unicode
      en transacciones (tildes, etc.) se representan igual en todos los nodos.
    """
    # Representacion canonica: claves ordenadas, sin espacios extra, UTF-8
    canonical = json.dumps(
        {
            "block_id":      block_id,
            "block_text":    block_text,
            "previous_hash": previous_hash,
        },
        sort_keys=True,        # deterministico: mismo dict → mismo JSON siempre
        ensure_ascii=False,    # preservar Unicode tal cual
        separators=(",", ":"), # compacto: sin espacios → bytes exactos
    )
    # SHA-256 sobre los bytes UTF-8 del JSON canonico
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mine_nonce(block_text: str) -> tuple[int, str]:
    """
    Proof of Work (PoW) ligera: busca el menor nonce N >= 0 tal que
        SHA-256(str(N) + ':' + block_text)  empiece con NONCE_PREFIX.

    DISEÑO ANTI-COLISION DEL SEPARADOR ':':
      nonce es siempre un entero no negativo → nunca puede contener ':'.
      Por tanto, el separador ':' es inequivoco: el receptor puede siempre
      reconstruir el mismo input sin ambiguedad, sin importar el contenido
      de block_text.

      Ejemplo de colision que SE EVITA:
        nonce=1, text="2:TX"  → input  = "1:2:TX"
        Si no hubiera separador fijo:
        nonce=12, text="TX"   → input  = "12TX"  ← distinto, sin colision
        Pero con ':', nonce=1 → "1:2:TX" nunca se confunde con nonce=12 → "12:TX"

    DIFICULTAD:
      NONCE_PREFIX="0" → el hash debe empezar con '0' → ~1/16 probabilidad.
      Promedio de iteraciones: ~16 (trivial en CPU).
      Para produccion se usaria "000" o mas (mineria real Bitcoin = "0"*18).

    Retorna:
      (nonce, puzzle_hash) donde puzzle_hash comienza con NONCE_PREFIX.
    """
    nonce = 0
    while True:
        # Formato "N:texto": el entero N nunca contiene ':', separacion inequivoca
        candidate   = f"{nonce}:{block_text}".encode("utf-8")
        puzzle_hash = hashlib.sha256(candidate).hexdigest()
        if puzzle_hash.startswith(NONCE_PREFIX):
            return nonce, puzzle_hash
        nonce += 1


# ══════════════════════════ COMUNICACION ════════════════════════════════════

def send_private_message(client_socket: socket.socket,
                         target_node:   str,
                         message:       str) -> None:
    """
    Envia un mensaje privado al nodo destino a traves del hub.

    El hub reenviara el mensaje al socket de 'target_node' con el prefijo:
        PRIVATE_FROM_monitor: <message>

    Se agrega '\\n' para que el buffer acumulado del receptor reconozca el
    final de la linea y procese el mensaje completo.
    """
    client_socket.sendall(f"/w {target_node} {message}\n".encode("utf-8"))


def query_connected_nodes(client_socket: socket.socket,
                          timeout: float = 2.0) -> set[str]:
    """
    Consulta al hub la lista de nodos realmente conectados en este instante.

    MECANISMO:
      1. Envia el comando '/who' al hub.
      2. El hub responde con: "[SERVIDOR] Nodos conectados: n1,n2,n3"
      3. handle_incoming_message() detecta ese prefijo y señaliza _who_event.
      4. Esta funcion espera el Event hasta 'timeout' segundos.
      5. Parsea la lista y descarta al propio monitor (no vota).

    IMPORTANCIA PARA EL QUORUM REAL:
      Sin este mecanismo, el quorum se calcula con los nombres que el usuario
      escribe, que podrian no estar conectados. Con /who, se filtra la lista
      real y el quorum refleja el estado actual de la red.

    MODO CONSERVADOR:
      Si el servidor no responde en 'timeout' segundos (o falla el envio),
      retorna conjunto vacio.  El llamador (distribute_blocks) decide si
      continuar con los nombres escritos o abortar.
    """
    global _who_response, _who_event

    # Reiniciar el mecanismo de sincronizacion
    _who_response = None
    _who_event    = threading.Event()

    try:
        client_socket.sendall(b"/who\n")
    except OSError:
        return set()   # no se pudo enviar: asumir sin info

    # Esperar hasta que receive_messages() señalice el resultado
    _who_event.wait(timeout=timeout)

    with state_lock:
        resp = _who_response

    if resp is None:
        return set()   # timeout sin respuesta

    # Parsear "nodo1,nodo2,nodo3" → conjunto de nombres
    names = {n.strip() for n in resp.split(",") if n.strip()}
    names.discard(MONITOR_NAME)   # el monitor no es validador, no vota
    return names


# ══════════════════════════ BLOCKCHAIN / LEDGER ═══════════════════════════

def split_transactions_into_blocks(file_path:       str,
                                   block_line_count: int = BLOCK_LINE_COUNT
                                   ) -> list[str]:
    """
    Lee el archivo de transacciones y lo segmenta en bloques.

    Cada bloque contiene exactamente 'block_line_count' lineas de transacciones
    (el ultimo bloque puede tener menos si el total no es multiplo exacto).

    Retorna lista de strings, uno por bloque, listos para ser hasheados.
    """
    path  = Path(file_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks = []
    for i in range(0, len(lines), block_line_count):
        chunk = "\n".join(lines[i : i + block_line_count]).strip()
        if chunk:
            blocks.append(chunk)
    return blocks


def print_global_blockchain_state() -> None:
    """
    Imprime el estado completo del ledger confirmado.

    Muestra para cada bloque: id, hash (primeros 20 chars), previous_hash
    y los votos SI obtenidos vs quorum requerido.
    El encadenamiento de hashes (previous_hash de bloque N = hash de bloque N-1)
    es la propiedad que hace inmutable la cadena.
    """
    print("\n╔══ ESTADO GLOBAL DE LA BLOCKCHAIN ══╗")
    if not confirmed_chain:
        print("║  (sin bloques confirmados todavia)  ║")
        print("╚═════════════════════════════════════╝")
        return
    for i, block in enumerate(confirmed_chain, start=1):
        print(f"║  {i:02d}. {block['block_id']}")
        print(f"║      hash     : {block['hash'][:20]}...")
        print(f"║      prev_hash: {block['previous_hash'][:20]}...")
        print(f"║      quorum   : {block['yes_votes']}/{block['quorum']}  [OK]")
    print("╚═════════════════════════════════════╝\n")


# ══════════════════════════ GESTION DE BLOQUES ═══════════════════════════════

def schedule_block_timeout(client_socket: socket.socket,
                           block_id:      str) -> threading.Timer:
    """
    Programa un timer de timeout para un bloque en vuelo.

    Si el bloque no se resuelve (quorum o fork) antes de BLOCK_TIMEOUT_SECONDS,
    el timer dispara y lo clasifica como bifurcacion tipo 'timeout'.

    NODOS CAIDOS:
      El timeout es el mecanismo que detecta validadores que no responden.
      Cuando expira, se reportan cuantos votaron vs cuantos deberian haber
      votado, lo que permite identificar los nodos ausentes.

    CANCELACION:
      confirm_block() y register_vote() cancelan el timer cuando el bloque
      se resuelve antes del timeout, evitando la bifurcacion falsa.

    Retorna el timer para que el llamador pueda guardarlo y cancelarlo.
    """
    def _timeout() -> None:
        # Intentar sacar el bloque de pending (puede ya haber sido resuelto)
        with state_lock:
            info = pending_blocks.pop(block_id, None)
        if info is None:
            return   # el bloque ya fue resuelto antes del timeout

        yes    = info["yes_votes"]
        no     = info.get("no_votes", 0)
        total  = len(info["voters"])
        quorum = info["quorum"]
        print(f"\n[TIMEOUT] {block_id} expiro tras {BLOCK_TIMEOUT_SECONDS}s.")
        print(f"[TIMEOUT] Votos SI: {yes} | NO: {no} | Respondieron: {total} | Quorum: {quorum}")
        print(f"[TIMEOUT] Nodos sin respuesta: {info['validators'] - info['voters']}")
        detect_fork(client_socket, block_id, yes, no, total, quorum, "timeout")

    timer = threading.Timer(BLOCK_TIMEOUT_SECONDS, _timeout)
    timer.daemon = True   # muere con el proceso principal
    timer.start()
    return timer


def detect_fork(client_socket:    socket.socket,
                block_id:         str,
                yes_votes:        int,
                no_votes:         int,
                total_validators: int,
                quorum:           int,
                fork_reason:      str = "quorum_no_alcanzado") -> None:
    """
    Detecta, clasifica y anuncia una bifurcacion (fork) de la cadena.

    TIPOS DE BIFURCACION MODELADOS:

      1. 'votos_divididos'
         La red esta partida: hay votos NO que hacen matematicamente imposible
         alcanzar el quorum aunque todos los restantes voten YES.
         Formula: yes_votes + votos_restantes < quorum
         Esta es la deteccion TEMPRANA: no espera a que voten todos.
         Representa una bifurcacion real donde dos grupos tienen visiones
         distintas del bloque (por ejemplo, uno recibio una version corrupta).

      2. 'quorum_no_alcanzado'
         Todos los validadores emitieron su voto pero los YES no alcanzan
         el quorum. La red voto mayoritariamente en contra del bloque.

      3. 'timeout'
         No todos los validadores respondieron en BLOCK_TIMEOUT_SECONDS.
         Indica nodos caidos o con latencia excesiva.
         El bloque no puede confirmarse ni rechazarse definitivamente.

    ACCION:
      - El bloque se rechaza: NO se inserta en el ledger.
      - Se elimina de _confirm_queue y _confirm_order para no bloquear
        la confirmacion de bloques anteriores o posteriores.
      - Se difunde BIFURCACION_DETECTADA con razon e informacion completa.
    """
    print(f"\n╔══ BIFURCACION_DETECTADA ══╗")
    print(f"║  Bloque    : {block_id}")
    print(f"║  Votos SI  : {yes_votes} / NO: {no_votes} / Total: {total_validators}")
    print(f"║  Quorum    : {quorum}  ->  NO alcanzado")
    print(f"║  Tipo      : {fork_reason}")
    print(f"║  Accion    : bloque RECHAZADO, no se inserta en el ledger.")
    print(f"╚════════════════════════════╝\n")

    # Limpiar el bloque de las estructuras de confirmacion ordenada
    with state_lock:
        _confirm_queue.pop(block_id, None)
        if block_id in _confirm_order:
            _confirm_order.remove(block_id)

    # Anunciar a toda la red con informacion detallada del fork
    try:
        client_socket.sendall(
            f"/broadcast BIFURCACION_DETECTADA {block_id} "
            f"si={yes_votes} no={no_votes} razon={fork_reason}\n"
            .encode("utf-8")
        )
    except OSError:
        pass


def confirm_block(client_socket: socket.socket, block_id: str) -> None:
    """
    Mueve el bloque aprobado a la cola ordenada e intenta confirmar
    todos los bloques consecutivos listos.

    GARANTIA DE ORDEN:
      Los bloques llegan a quorum en orden aleatorio (los validadores procesan
      en paralelo y pueden tardar distinto). Sin embargo, el ledger debe ser
      una cadena lineal donde:
          hash(bloque_N) = SHA-256(previous_hash_N, block_id_N, text_N)
          previous_hash_N = hash(bloque_{N-1})

      Si block_002 se confirma antes que block_001, su previous_hash seria
      el genesis (o el ultimo confirmado), que NO coincide con el hash de
      block_001 que los validadores calcularon cuando votaron YES.
      Esto rompe la integridad de la cadena.

    SOLUCION — Cola doble:
      _confirm_order : lista con el orden de envio [block_001, block_002, ...]
      _confirm_queue : dict de bloques con quorum listos para insertar

      El drain loop solo saca de _confirm_queue el bloque que este primero
      en _confirm_order. Si block_002 llega antes, queda en _confirm_queue
      hasta que block_001 salga de pending_blocks.

    HASH RECALCULADO CON previous_hash REAL:
      Cuando un bloque finalmente se inserta, su previous_hash se toma del
      ultimo bloque ya confirmado en el ledger (no del valor provisional usado
      al enviar). Esto garantiza que el hash almacenado es el correcto.
    """
    with state_lock:
        info = pending_blocks.pop(block_id, None)
        if info is None:
            return   # ya fue procesado (por fork u otro camino)

        # Cancelar el timer de timeout: el bloque se resolvio
        timer = info.get("timer")
        if timer:
            timer.cancel()

        # Mover a la cola de confirmacion ordenada
        _confirm_queue[block_id] = info

        # Drenar la cola: confirmar todos los bloques consecutivos listos
        while _confirm_order and _confirm_order[0] in _confirm_queue:
            next_id   = _confirm_order.pop(0)
            next_info = _confirm_queue.pop(next_id)

            # previous_hash REAL: el ultimo bloque ya en el ledger (o genesis)
            previous_hash = (confirmed_chain[-1]["hash"]
                             if confirmed_chain else "0" * 64)

            # Recalcular el hash con el previous_hash definitivo del ledger
            # (puede diferir del provisional usado al distribuir si algun
            # bloque anterior fue rechazado)
            block_hash = compute_block_hash(previous_hash, next_id, next_info["text"])

            # Insertar en el ledger definitivo
            confirmed_chain.append({
                "block_id":      next_id,
                "hash":          block_hash,
                "previous_hash": previous_hash,
                "text":          next_info["text"],
                "yes_votes":     next_info["yes_votes"],
                "quorum":        next_info["quorum"],
            })

            print(f"\n[QUORUM ALCANZADO] {next_id} aprobado e insertado en el ledger.")
            print_global_blockchain_state()

            # Difundir confirmacion a toda la red
            try:
                client_socket.sendall(
                    f"/broadcast CONSENSO_ALCANZADO {next_id} | hash={block_hash[:12]}...\n"
                    .encode("utf-8")
                )
            except OSError:
                pass


# ══════════════════════════ VOTACION ══════════════════════════════════════════

def register_vote(client_socket: socket.socket,
                  block_id:      str,
                  voter:         str,
                  decision:      bool) -> bool:
    """
    Registra el voto de un validador para un bloque en vuelo.

    LOGICA DE DECISION (en orden de evaluacion):

      1. QUORUM ALCANZADO (yes_votes >= quorum):
         Se llama confirm_block() inmediatamente. No se espera a los demas.
         La confirmacion es anticipada: en cuanto se tiene mayoria suficiente.

      2. DETECCION TEMPRANA DE FORK (votos_divididos):
         Condicion: yes_votes + votos_restantes < quorum
         Si incluso con todos los votos pendientes votando YES no se llega
         al quorum, es matematicamente imposible aprobar el bloque.
         Se detecta el fork sin esperar a que el resto vote.
         Esto reduce la latencia ante particiones de red reales.

      3. QUORUM NO ALCANZADO (todos votaron, YES < quorum):
         Todos los validadores respondieron pero la mayoria dijo NO.
         Fork tipo 'quorum_no_alcanzado'.

      4. VOTO PARCIAL: se actualiza el estado y se imprime el progreso.

    PROTECCION ANTI-DUPLICADOS:
      info["voters"] es un set: si el mismo nodo envia el voto dos veces
      (posible por retransmision TCP o bug del validador), el segundo se ignora.

    Retorna True si el voto fue aceptado y procesado, False si fue ignorado.
    """
    with state_lock:
        info = pending_blocks.get(block_id)
        if info is None:
            return False   # bloque ya confirmado, rechazado o desconocido
        if voter in info["voters"]:
            return False   # voto duplicado: ignorar

        # Registrar el voto
        info["voters"].add(voter)
        if decision:
            info["yes_votes"] += 1
        else:
            info["no_votes"] = info.get("no_votes", 0) + 1

        # Leer estado local para evaluar fuera del lock
        yes_votes        = info["yes_votes"]
        no_votes         = info.get("no_votes", 0)
        quorum           = info["quorum"]
        total_voters     = len(info["voters"])
        total_validators = len(info["validators"])

    # ── CASO 1: quorum alcanzado → confirmar de inmediato ────────────
    if yes_votes >= quorum:
        confirm_block(client_socket, block_id)
        return True

    # ── CASO 2: deteccion temprana de fork (votos divididos) ─────────
    # Si todos los votos restantes fueran YES, aun no se llegaria al quorum
    remaining = total_validators - total_voters
    if yes_votes + remaining < quorum:
        with state_lock:
            pending_blocks.pop(block_id, None)
            timer = info.get("timer")
        if timer:
            timer.cancel()
        detect_fork(client_socket, block_id, yes_votes, no_votes,
                    total_validators, quorum, "votos_divididos")
        return True

    # ── CASO 3: todos votaron y no hay quorum ──────────────────────────
    if total_voters >= total_validators:
        with state_lock:
            pending_blocks.pop(block_id, None)
            timer = info.get("timer")
        if timer:
            timer.cancel()
        detect_fork(client_socket, block_id, yes_votes, no_votes,
                    total_validators, quorum, "quorum_no_alcanzado")
        return True

    # ── CASO 4: voto parcial, seguir esperando ─────────────────────────
    print(f"[VOTO REGISTRADO] {block_id}: {yes_votes}/{quorum} SI, "
          f"{no_votes} NO  ({total_voters}/{total_validators} respondieron)")
    return True


def parse_vote_message(message: str) -> tuple[str | None, bool | None]:
    """
    Extrae (block_id, decision) de un mensaje de voto recibido.

    Soporta multiples formatos para compatibilidad con variaciones
    de implementacion de los validadores:

      VOTE|block_001|YES         (formato primario pipe-separado)
      VOTE|block_001|NO
      VOTE block_001 YES         (variante con espacios)
      BLOQUE_OK|block_001        (formato alternativo del spec)
      BLOQUE_INVALIDO|block_001

    La regex es case-insensitive y acepta '|' o espacio como separador,
    lo que hace el protocolo robusto ante pequeñas variaciones de formato.
    """
    message = message.strip()

    # Formato VOTE|bid|YES/NO o VOTE bid YES/NO
    m = re.search(
        r"VOTE[|\s]+(?P<block>block_\w+)[|\s]+(?P<decision>YES|NO|SI)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() in {"YES", "SI"}
        return m.group("block"), decision

    # Formato BLOQUE_OK|bid o BLOQUE_INVALIDO|bid
    m = re.search(
        r"(?P<decision>BLOQUE_OK|BLOQUE_INVALIDO)[|\s]+(?P<block>block_\w+)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() == "BLOQUE_OK"
        return m.group("block"), decision

    return None, None   # mensaje no reconocido como voto


def handle_incoming_message(client_socket: socket.socket,
                             message:      str) -> None:
    """
    Clasifica y procesa cada linea de mensaje recibida del servidor.

    TIPOS DE MENSAJE:

      [SERVIDOR] Nodos conectados: n1,n2,...
          Respuesta al comando /who. Señaliza _who_event para desbloquear
          query_connected_nodes() que esta esperando el resultado.

      PRIVATE_FROM_<sender>: <payload>
          Mensaje privado (normalmente bloques JSON de algun validador).
          En la practica el Monitor no recibe bloques de validadores, pero
          el canal privado esta disponible para futuras extensiones.

      <sender>: <payload>   (chat general)
          Los validadores emiten sus votos en este canal:
              validador1: VOTE|block_001|YES
          parse_vote_message extrae el voto y register_vote lo contabiliza.

      Mensajes propios (monitor:) y del servidor ([SERVIDOR]) se ignoran
      para evitar auto-procesamiento y bucles.
    """
    global _who_response, _who_event

    message = message.strip()
    if not message:
        return

    print(message)   # log de auditoria: todo lo que llega queda en consola

    # ── Respuesta a /who: desbloquear query_connected_nodes() ────────
    PREFIX_WHO = "[SERVIDOR] Nodos conectados:"
    if message.startswith(PREFIX_WHO):
        with state_lock:
            _who_response = message[len(PREFIX_WHO):].strip()
        _who_event.set()   # señalizar que la respuesta esta lista
        return

    sender:  str | None = None
    payload: str | None = None

    # ── Mensaje privado: PRIVATE_FROM_<sender>: <payload> ────────────
    if message.startswith("PRIVATE_FROM_"):
        try:
            rest = message[len("PRIVATE_FROM_"):]
            sender, payload = rest.split(": ", 1)
        except ValueError:
            return

    # ── Chat general: <sender>: <payload> ────────────────────────────
    else:
        try:
            sender, payload = message.split(": ", 1)
        except ValueError:
            return

    # Descartar mensajes propios y del sistema
    if not sender or sender == MONITOR_NAME or sender.startswith("[SERVIDOR]"):
        return

    # Intentar interpretar como voto de validador
    block_id, decision = parse_vote_message(payload)
    if block_id is None:
        return   # no es un voto, ignorar

    register_vote(client_socket, block_id, sender, decision)


def receive_messages(client_socket: socket.socket) -> None:
    """
    Hilo daemon: escucha continuamente el socket del hub y procesa
    cada linea de mensaje que llega.

    BUFFER ACUMULADO — resolucion de fragmentacion TCP:
      TCP es un protocolo de STREAM: recv() puede devolver fragmentos
      parciales de un mensaje JSON, o fusionar varios mensajes en un chunk.
      Si se procesa cada recv() directamente con split('\\n'), una linea
      cuya segunda mitad llega en el siguiente recv() nunca queda completa.

    SOLUCION:
      buf acumula bytes entre recv() consecutivos.
      Solo se procesan los fragmentos terminados en '\\n' (lineas completas).
      El resto queda en buf hasta el proximo recv().
    """
    buf = bytearray()   # buffer persistente entre llamadas a recv()
    try:
        while True:
            chunk = client_socket.recv(65_536)
            if not chunk:
                print("[MONITOR] El servidor cerro la conexion.")
                break

            buf.extend(chunk)
            # Separar lineas completas del fragmento incompleto
            text  = buf.decode("utf-8", errors="replace")
            parts = text.split("\n")
            buf   = bytearray(parts[-1].encode("utf-8"))  # residuo sin '\n'

            # Procesar solo lineas completas
            for line in parts[:-1]:
                handle_incoming_message(client_socket, line)
    except OSError:
        pass


# ══════════════════════ DISTRIBUCION DE BLOQUES ══════════════════════════════

def distribute_blocks(client_socket:   socket.socket,
                      file_path:        str,
                      validator_nodes:  list[str]) -> None:
    """
    Orquesta una ronda completa de consenso distribuido.

    FLUJO COMPLETO:

      FASE 1 — Verificacion de presencia (quorum real):
        Envia /who al hub y espera la lista de nodos activos.
        Filtra 'validator_nodes' para quedarse solo con los online.
        Calcula quorum = floor(N_activos / 2) + 1.

      FASE 2 — Segmentacion del archivo:
        Lee el archivo de transacciones y lo divide en bloques de
        BLOCK_LINE_COUNT lineas cada uno.

      FASE 3 — Por cada bloque (en orden):
        a. Registrar el bloque en _confirm_order (garantia de orden).
        b. Calcular proposed_hash = SHA-256(bloque canonico) encadenado
           con el tip actual de la cadena provisional.
        c. Minar nonce: buscar N tal que SHA-256(N:text) empiece con NONCE_PREFIX.
        d. Empaquetar todo en JSON y enviar a cada validador activo via /w.
        e. Registrar el bloque en pending_blocks con su estado inicial.
        f. Arrancar el timer de timeout para ese bloque.

    CADENA PROVISIONAL:
      Al distribuir todos los bloques a la vez, se usa un 'provisional_prev'
      que avanza bloque a bloque para el encadenamiento de proposed_hash.
      Esto permite que los validadores reciban el hash correcto para validar
      la integridad relativa de la cadena completa.
      La insercion definitiva en el ledger (confirm_block) recalcula el hash
      real usando el tip del ledger en ese momento.
    """
    blocks = split_transactions_into_blocks(file_path)
    if not blocks:
        print("[AVISO] El archivo no contiene transacciones validas.")
        return
    if not validator_nodes:
        print("[ERROR] Debes indicar al menos un nodo validador.")
        return

    # ── FASE 1: quorum dinamico REAL ─────────────────────────────────
    # Consultar al hub que nodos estan realmente conectados ahora
    connected = query_connected_nodes(client_socket)
    if not connected:
        print("[AVISO] El servidor no reporto nodos conectados. "
              "Se usaran los nombres indicados sin verificar.")
        active_validators = list(validator_nodes)
    else:
        # Filtrar: solo los validadores indicados que esten online
        active_validators = [v for v in validator_nodes if v in connected]
        offline = [v for v in validator_nodes if v not in connected]
        if offline:
            print(f"[AVISO] Nodos NO conectados (excluidos del quorum): {', '.join(offline)}")

    if not active_validators:
        print("[ERROR] Ninguno de los validadores indicados esta conectado al hub.")
        return

    # quorum = mayoria simple: mas de la mitad de los activos
    quorum = math.floor(len(active_validators) / 2) + 1
    print(f"\n[CARGA] {len(blocks)} bloque(s) candidato(s) desde '{file_path}'.")
    print(f"[CARGA] Validadores activos: {', '.join(active_validators)}")
    print(f"[CARGA] Quorum dinamico real: {quorum}/{len(active_validators)}\n")

    # Tip provisional de la cadena para encadenamiento de proposed_hash
    with state_lock:
        provisional_prev = (confirmed_chain[-1]["hash"]
                            if confirmed_chain else "0" * 64)

    total = len(blocks)
    for index, block_text in enumerate(blocks, start=1):
        block_id = f"block_{index:03d}"

        # Registrar en la cola de confirmacion ANTES de enviar
        # (el drain loop de confirm_block necesita este orden)
        with state_lock:
            _confirm_order.append(block_id)

        # Hash propuesto encadenado con el tip provisional
        proposed_hash = compute_block_hash(provisional_prev, block_id, block_text)

        # Minado del nonce de Prueba de Trabajo
        print(f"[MINANDO] {block_id} — buscando nonce con prefijo '{NONCE_PREFIX}'...")
        nonce, puzzle_hash = mine_nonce(block_text)
        print(f"[NONCE]   {block_id} -> nonce={nonce}  puzzle_hash={puzzle_hash[:12]}...")

        # Mensaje JSON completo para los validadores
        block_msg = json.dumps({
            "type":          "BLOCK",       # tipo de mensaje (para routing en validador)
            "block_id":      block_id,      # identificador unico del bloque
            "sequence":      f"{index}/{total}",  # posicion en la tanda
            "previous_hash": provisional_prev,    # hash del bloque previo (encadenamiento)
            "text":          block_text,    # contenido de las transacciones
            "proposed_hash": proposed_hash, # SHA-256 canonico del bloque
            "nonce":         nonce,         # nonce que satisface la PoW
            "puzzle_hash":   puzzle_hash,   # SHA-256(nonce:text) con prefijo requerido
        }, ensure_ascii=False)

        # Registrar el bloque en pending_blocks con estado inicial
        with state_lock:
            pending_blocks[block_id] = {
                "text":          block_text,
                "validators":    set(active_validators),  # quienes DEBEN votar
                "voters":        set(),                   # quienes ya votaron
                "yes_votes":     0,
                "no_votes":      0,
                "quorum":        quorum,
                "proposed_hash": proposed_hash,
                "previous_hash": provisional_prev,
                "timer":         None,   # asignado justo despues
            }

        # Arrancar timer de timeout para este bloque especifico
        timer = schedule_block_timeout(client_socket, block_id)
        with state_lock:
            if block_id in pending_blocks:
                pending_blocks[block_id]["timer"] = timer

        # Enviar a TODOS los validadores activos simultaneamente (via hub)
        for validator in active_validators:
            send_private_message(client_socket, validator, block_msg)
        print(f"[ENVIADO] {block_id} -> {', '.join(active_validators)}")

        # Avanzar el tip provisional para el siguiente bloque de la tanda
        provisional_prev = proposed_hash


# ══════════════════════ INTERFAZ DE USUARIO ══════════════════════════════════

def parse_load_command(command: str) -> tuple[str | None, list[str] | None]:
    """
    Parsea el comando interactivo del operador:
        cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)

    Retorna (file_path, [nodos]) si el formato es correcto.
    Retorna (None, None) si el formato es incorrecto.

    La regex acepta nombres de archivo con puntos, guiones y barras,
    y nombres de nodos alfanumericos separados por comas.
    """
    m = re.fullmatch(
        r"cargar_bloques\(\s*(?P<file>[^,]+?)\s*,\s*(?P<nodes>.+?)\s*\)",
        command.strip(),
        flags=re.IGNORECASE,
    )
    if not m:
        return None, None

    file_path = m.group("file").strip().strip("\"'")
    raw_nodes = m.group("nodes").strip()
    nodes     = [n.strip().strip("\"'") for n in raw_nodes.split(",") if n.strip()]
    return file_path, nodes


def start_monitor() -> None:
    """
    Punto de entrada del Monitor.

    SECUENCIA DE INICIO:
      1. Abrir socket TCP y conectar al hub.
      2. Enviar nombre de registro 'monitor\\n' (handshake inicial del hub).
      3. Lanzar hilo daemon receive_messages (escucha votos en background).
      4. Entrar al loop interactivo: esperar comandos del operador.

    COMANDO PRINCIPAL:
      cargar_bloques(archivo.txt, v1, v2, v3)
        → verifica nodos activos → distribuye bloques → espera votos

    El hilo de receive_messages y el loop de input corren en paralelo:
    mientras el operador escribe, los votos llegan y se contabilizan
    automaticamente en background.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    # El nombre se envia con '\n' para que el buffer del servidor lo reconozca
    client_socket.sendall((MONITOR_NAME + "\n").encode("utf-8"))

    print(f"[CONECTADO] Monitor registrado como '{MONITOR_NAME}' en {HOST}:{PORT}.")
    print("Comandos disponibles:")
    print("  cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)")
    print("  salir")
    print(f"Timeout por bloque: {BLOCK_TIMEOUT_SECONDS}s  |  Prefijo PoW: '{NONCE_PREFIX}'\n")

    # Hilo daemon: escucha mensajes entrantes (votos, notificaciones /who, etc.)
    threading.Thread(
        target=receive_messages, args=(client_socket,), daemon=True
    ).start()

    try:
        while True:
            command = input("monitor> ").strip()
            if not command:
                continue

            if command.lower() in {"salir", "exit", "quit"}:
                break

            file_path, validator_nodes = parse_load_command(command)
            if file_path is None:
                print("[ERROR] Comando no reconocido.")
                print("  Uso: cargar_bloques(archivo.txt, nodo1, nodo2, ...)")
                continue

            # Placeholder para uso interactivo sin especificar nodos en el comando
            if not validator_nodes or validator_nodes == ["nodos_validadores"]:
                raw = input("Nodos validadores (separados por coma): ").strip()
                validator_nodes = [n.strip().strip("\"'")
                                   for n in raw.split(",") if n.strip()]

            try:
                distribute_blocks(client_socket, file_path, validator_nodes)
            except FileNotFoundError:
                print(f"[ERROR] Archivo no encontrado: {file_path}")
            except UnicodeDecodeError:
                print(f"[ERROR] No se pudo leer como UTF-8: {file_path}")
            except OSError as exc:
                print(f"[ERROR] Problema de I/O: {exc}")

    except (KeyboardInterrupt, EOFError):
        print("\n[SALIENDO] Cerrando monitor...")
    finally:
        try:
            client_socket.close()
        except OSError:
            pass


if __name__ == "__main__":
    start_monitor()
