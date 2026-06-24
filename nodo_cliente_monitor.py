"""
NODO MONITOR — Coordinador del proceso de consenso

El monitor es el nodo "maestro" de la red. Se conecta al hub igual que
cualquier otro nodo pero tiene la responsabilidad de organizar todo.

Lo que hace:
  1. Divide el archivo de transacciones en bloques candidatos
  2. Pregunta al servidor que nodos estan conectados para calcular el quorum real
  3. Calcula los hashes de los bloques y busca el nonce de prueba de trabajo
  4. Distribuye los bloques a los validadores activos por mensaje privado
  5. Escucha los votos VOTE|block_id|YES/NO del chat publico
  6. Confirma los bloques en el ledger en el mismo orden en que se enviaron
  7. Detecta cuando hay bifurcaciones (forks) y avisa a la red

Quorum dinamico:
El monitor manda /who al servidor y espera la respuesta con los nodos activos.
Filtra la lista de validadores pedidos para quedarse solo con los que estan online.
quorum = (N // 2) + 1  donde N = validadores activos confirmados
Asi un nodo caido no bloquea el proceso.

Orden de confirmacion:
Los bloques se mandan todos a la vez para que los validadores los procesen en paralelo,
pero se insertan en el ledger en el mismo orden en que se enviaron.
Si block_002 llega al quorum antes que block_001, se guarda en cola y espera.
Esto es importante para que el previous_hash de cada bloque sea correcto.

Tipos de fork que detecta:
  - votos_divididos: ya es matematicamente imposible alcanzar el quorum
  - quorum_no_alcanzado: todos votaron pero no hay suficientes YES
  - timeout: algun validador no respondio en el tiempo limite

Los hashes se calculan con JSON serializado con sort_keys=True y sin espacios extra,
para que el resultado siempre sea el mismo independientemente de como se armo el dict.
"""

import hashlib
import json
import math
import re
import socket
import threading
from pathlib import Path

# configuracion de red
HOST:         str = "127.0.0.1"   # direccion del hub
PORT:         int = 5000           # puerto del hub
MONITOR_NAME: str = "monitor"     # nombre con el que se registra en la red

# parametros de consenso
BLOCK_LINE_COUNT:      int = 5    # cuantas lineas de transacciones por bloque
BLOCK_TIMEOUT_SECONDS: int = 30   # segundos de espera antes de declarar timeout
NONCE_PREFIX:          str = "0"  # prefijo requerido en el hash de prueba de trabajo

# estado global del monitor (protegido por state_lock)
state_lock: threading.Lock = threading.Lock()

# bloques en vuelo esperando votos
# estructura: { block_id → { text, validators, voters, yes_votes, no_votes,
#                             quorum, proposed_hash, previous_hash, timer } }
pending_blocks: dict = {}

# ledger con los bloques confirmados en orden
# cada entrada: { block_id, hash, previous_hash, text, yes_votes, quorum }
confirmed_chain: list = []

# cola para confirmar en orden estricto:
#   _confirm_order guarda el orden en que se enviaron los bloques
#   _confirm_queue guarda los que ya tienen quorum pero todavia no es su turno
_confirm_order: list = []
_confirm_queue: dict = {}

# variables para el mecanismo /who
_who_response: str | None      = None
_who_event:    threading.Event = threading.Event()


# ─── funciones de hash ───────────────────────────────────────────────────────

def compute_block_hash(previous_hash: str,
                       block_id:      str,
                       block_text:    str) -> str:
    """
    Calcula el hash SHA-256 del bloque.

    Usa JSON con sort_keys=True para que el orden de las claves en el
    diccionario no afecte el resultado. Tiene que producir exactamente
    el mismo string que la funcion equivalente del validador, si no
    la verificacion nunca pasaria.
    """
    # serializamos el bloque a JSON antes de hashear
    """
    Aquí lo que hace el JSON es convertir un objeto en una cadena de texto JSON.
    En este caso, contiene el ID del bloque candidato, el texto del bloque, el HASH previo
    se serializa el JSON en forma de un diccionario

    el sort_keys lo que hace es ordenar las llaves del diccionario alfabéticamente
    ensure_ascii=False es para que todos los caracteres no ascii los deje tal cual como estan.


    despues con los separators se define como es que se separan los elementos.
    Esto es importante porque en la criptografía espacios en blancos pueden distringuir
    a uns hashes de otros.
    """
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
    """lo que hace hashlib es una función matemática que convierte una cantidad d edatos
    y los convierte en una cadeja fija de 256 bits, hashlib.sha256
    el encode(utf-8) convierte todo a bytes usando un estñandar utf-8"""
    # calcular el sha256 del JSON
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mine_nonce(block_text: str) -> tuple[int, str]:
    """
    Prueba de trabajo: busca el numero mas chico N >= 0 tal que
    SHA-256(str(N) + ':' + block_text) empiece con NONCE_PREFIX.

    El ':' entre el nonce y el texto es un separador para que no haya
    ambiguedad al reconstruir el input en el validador.

    Con NONCE_PREFIX="0" el hash tiene que empezar con '0', lo cual
    pasa aproximadamente 1 de cada 16 intentos, muy rapido.

    Devuelve el nonce encontrado y el hash que lo satisface.
    """
    nonce = 0
    while True:
        # formato "N:texto": el entero N nunca contiene ':', separacion inequivoca
        candidate   = f"{nonce}:{block_text}".encode("utf-8")
        puzzle_hash = hashlib.sha256(candidate).hexdigest()
        if puzzle_hash.startswith(NONCE_PREFIX):
            return nonce, puzzle_hash
        nonce += 1


# ─── comunicacion con el servidor ────────────────────────────────────────────

def send_private_message(client_socket: socket.socket,
                         target_node:   str,
                         message:       str) -> None:
    """
    Envia un mensaje privado a otro nodo usando el hub como intermediario.
    El hub reenviara el mensaje al destino con el prefijo PRIVATE_FROM_monitor.
    """
    client_socket.sendall(f"/w {target_node} {message}\n".encode("utf-8"))


def query_connected_nodes(client_socket: socket.socket,
                          timeout: float = 2.0) -> set[str]:
    """
    Le pregunta al servidor que nodos estan conectados en este momento.

    Como funciona:
      1. Manda /who al servidor
      2. El servidor responde con: "[SERVIDOR] Nodos conectados: n1,n2,n3"
      3. handle_incoming_message detecta esa respuesta y pone _who_event
      4. Esta funcion espera ese evento hasta 'timeout' segundos
      5. Parsea la lista y descarta al monitor (el no vota)

    Si no llega respuesta en el tiempo limite, devuelve conjunto vacio.
    """
    global _who_response, _who_event

    # reiniciar el mecanismo de sincronizacion
    _who_response = None
    _who_event    = threading.Event()

    try:
        client_socket.sendall(b"/who\n")
    except OSError:
        return set()   # si fallo el envio, retornar vacio

    # esperar a que receive_messages() senalice la respuesta
    _who_event.wait(timeout=timeout)

    with state_lock:
        resp = _who_response

    if resp is None:
        return set()   # timeout, no hubo respuesta

    # parsear "nodo1,nodo2,nodo3" → conjunto de nombres
    names = {n.strip() for n in resp.split(",") if n.strip()}
    names.discard(MONITOR_NAME)   # el monitor no es validador
    return names


# ─── blockchain / ledger ─────────────────────────────────────────────────────

def split_transactions_into_blocks(file_path:       str,
                                   block_line_count: int = BLOCK_LINE_COUNT
                                   ) -> list[str]:
    """
    Lee el archivo de transacciones y lo divide en bloques.
    Cada bloque tiene 'block_line_count' lineas. El ultimo puede tener menos
    si el total no es multiplo exacto.
    Devuelve una lista de strings, uno por bloque.
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
    Imprime en consola todos los bloques confirmados en el ledger.
    Muestra el hash, el hash anterior y cuantos votos si tuvo cada bloque.
    El encadenamiento de hashes es lo que hace inmutable la cadena.
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


# ─── gestion de bloques ───────────────────────────────────────────────────────

def schedule_block_timeout(client_socket: socket.socket,
                           block_id:      str) -> threading.Timer:
    """
    Pone un timer para detectar si un bloque no recibe todos los votos a tiempo.
    Si el timer se dispara antes de que el bloque se resuelva, se declara
    fork de tipo timeout.

    Si el bloque se resuelve antes, confirm_block o register_vote cancelan el timer.
    Devuelve el timer para guardarlo y poder cancelarlo despues.
    """
    def _timeout() -> None:
        # sacar el bloque de pending, puede que ya se haya resuelto antes
        with state_lock:
            info = pending_blocks.pop(block_id, None)
        if info is None:
            return   # ya fue resuelto, no hacer nada

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
    Maneja y anuncia que un bloque no se pudo confirmar (fork).

    Hay tres razones posibles:
      - votos_divididos: ya es matematicamente imposible llegar al quorum
                         aunque todos los que quedan voten YES
      - quorum_no_alcanzado: todos votaron pero los YES no alcanzan el quorum
      - timeout: algun validador no respondio en BLOCK_TIMEOUT_SECONDS

    En todos los casos el bloque se rechaza, se limpia de las colas
    y se avisa a toda la red con BIFURCACION_DETECTADA.
    """
    print(f"\n╔══ BIFURCACION_DETECTADA ══╗")
    print(f"║  Bloque    : {block_id}")
    print(f"║  Votos SI  : {yes_votes} / NO: {no_votes} / Total: {total_validators}")
    print(f"║  Quorum    : {quorum}  ->  NO alcanzado")
    print(f"║  Tipo      : {fork_reason}")
    print(f"║  Accion    : bloque RECHAZADO, no se inserta en el ledger.")
    print(f"╚════════════════════════════╝\n")

    # limpiar el bloque de las estructuras de confirmacion ordenada
    with state_lock:
        _confirm_queue.pop(block_id, None)
        if block_id in _confirm_order:
            _confirm_order.remove(block_id)

    # avisar a toda la red
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
    Cuando un bloque alcanza el quorum, lo mueve a la cola de confirmacion
    y trata de insertar todos los bloques que esten listos y en orden.

    El orden importa porque el previous_hash de cada bloque tiene que
    coincidir con el hash del bloque anterior en el ledger.
    Si block_002 llega antes que block_001, se guarda en _confirm_queue
    y espera hasta que block_001 se confirme primero.

    Cuando finalmente se inserta, se recalcula el hash con el previous_hash
    real del ledger (no el provisional que se uso al distribuir).
    """
    with state_lock:
        info = pending_blocks.pop(block_id, None)
        if info is None:
            return   # ya fue procesado por otro camino

        # cancelar el timer, el bloque ya se resolvio
        timer = info.get("timer")
        if timer:
            timer.cancel()

        # pasar a la cola de confirmacion ordenada
        _confirm_queue[block_id] = info

        # intentar confirmar todos los bloques consecutivos que esten listos
        while _confirm_order and _confirm_order[0] in _confirm_queue:
            next_id   = _confirm_order.pop(0)
            next_info = _confirm_queue.pop(next_id)

            # previous_hash real: el del ultimo bloque en el ledger (o genesis)
            previous_hash = (confirmed_chain[-1]["hash"]
                             if confirmed_chain else "0" * 64)

            # recalcular el hash con el previous_hash definitivo
            # (puede diferir del provisional si algun bloque anterior fue rechazado)
            block_hash = compute_block_hash(previous_hash, next_id, next_info["text"])

            # insertar en el ledger
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

            # avisar a toda la red que el bloque se confirmo
            try:
                client_socket.sendall(
                    f"/broadcast CONSENSO_ALCANZADO {next_id} | hash={block_hash[:12]}...\n"
                    .encode("utf-8")
                )
            except OSError:
                pass


# ─── votacion ────────────────────────────────────────────────────────────────

def register_vote(client_socket: socket.socket,
                  block_id:      str,
                  voter:         str,
                  decision:      bool) -> bool:
    """
    Registra el voto de un validador para un bloque.

    Casos posibles (en orden de evaluacion):
      1. Quorum alcanzado (yes_votes >= quorum) → confirmar el bloque ya
      2. Votos divididos (ya es imposible llegar al quorum) → declarar fork
      3. Todos votaron pero no hay quorum → declarar fork
      4. Todavia vienen votos → actualizar estado y esperar

    Ignora votos duplicados del mismo nodo por si acaso llegan dos veces.
    Devuelve True si el voto fue aceptado, False si fue ignorado.
    """
    with state_lock:
        info = pending_blocks.get(block_id)
        if info is None:
            return False   # bloque ya resuelto o desconocido
        if voter in info["voters"]:
            return False   # voto duplicado, ignorar

        # registrar el voto
        info["voters"].add(voter)
        if decision:
            info["yes_votes"] += 1
        else:
            info["no_votes"] = info.get("no_votes", 0) + 1

        # leer estado para evaluar afuera del lock
        yes_votes        = info["yes_votes"]
        no_votes         = info.get("no_votes", 0)
        quorum           = info["quorum"]
        total_voters     = len(info["voters"])
        total_validators = len(info["validators"])

    # caso 1: quorum alcanzado, confirmar de inmediato
    if yes_votes >= quorum:
        confirm_block(client_socket, block_id)
        return True

    # caso 2: fork temprano por votos divididos
    # si todos los que quedan votaran YES tampoco llegaria al quorum
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

    # caso 3: todos votaron y no hay quorum
    if total_voters >= total_validators:
        with state_lock:
            pending_blocks.pop(block_id, None)
            timer = info.get("timer")
        if timer:
            timer.cancel()
        detect_fork(client_socket, block_id, yes_votes, no_votes,
                    total_validators, quorum, "quorum_no_alcanzado")
        return True

    # caso 4: voto parcial, seguir esperando
    print(f"[VOTO REGISTRADO] {block_id}: {yes_votes}/{quorum} SI, "
          f"{no_votes} NO  ({total_voters}/{total_validators} respondieron)")
    return True


def parse_vote_message(message: str) -> tuple[str | None, bool | None]:
    """
    Extrae el block_id y la decision de un mensaje de voto.

    Acepta varios formatos para ser compatible con distintas versiones:
      VOTE|block_001|YES
      VOTE|block_001|NO
      VOTE block_001 YES
      BLOQUE_OK|block_001
      BLOQUE_INVALIDO|block_001

    Devuelve (None, None) si el mensaje no es un voto reconocible.
    """
    message = message.strip()

    # formato VOTE|bid|YES/NO o VOTE bid YES/NO
    m = re.search(
        r"VOTE[|\s]+(?P<block>block_\w+)[|\s]+(?P<decision>YES|NO|SI)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() in {"YES", "SI"}
        return m.group("block"), decision

    # formato BLOQUE_OK|bid o BLOQUE_INVALIDO|bid
    m = re.search(
        r"(?P<decision>BLOQUE_OK|BLOQUE_INVALIDO)[|\s]+(?P<block>block_\w+)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() == "BLOQUE_OK"
        return m.group("block"), decision

    return None, None   # no es un voto reconocible


def handle_incoming_message(client_socket: socket.socket,
                             message:      str) -> None:
    """
    Clasifica y procesa cada mensaje que llega del servidor.

    Tipos de mensaje:
      - [SERVIDOR] Nodos conectados: ...  → respuesta al /who, senalizar _who_event
      - PRIVATE_FROM_sender: payload      → mensaje privado (no solemos recibir bloques)
      - sender: payload                   → chat general, intentar parsear como voto
      - mensajes del propio monitor y del servidor → ignorar
    """
    global _who_response, _who_event

    message = message.strip()
    if not message:
        return

    print(message)   # log de todo lo que llega

    # respuesta al /who: desbloquear query_connected_nodes
    PREFIX_WHO = "[SERVIDOR] Nodos conectados:"
    if message.startswith(PREFIX_WHO):
        with state_lock:
            _who_response = message[len(PREFIX_WHO):].strip()
        _who_event.set()   # senalizar que ya tenemos la respuesta
        return

    sender:  str | None = None
    payload: str | None = None

    # mensaje privado: PRIVATE_FROM_sender: payload
    if message.startswith("PRIVATE_FROM_"):
        try:
            rest = message[len("PRIVATE_FROM_"):]
            sender, payload = rest.split(": ", 1)
        except ValueError:
            return

    # chat general: sender: payload
    else:
        try:
            sender, payload = message.split(": ", 1)
        except ValueError:
            return

    # ignorar mensajes propios y del servidor
    if not sender or sender == MONITOR_NAME or sender.startswith("[SERVIDOR]"):
        return

    # intentar interpretar como voto de validador
    block_id, decision = parse_vote_message(payload)
    if block_id is None:
        return   # no es un voto, ignorar

    register_vote(client_socket, block_id, sender, decision)


def receive_messages(client_socket: socket.socket) -> None:
    """
    Hilo daemon que escucha continuamente los mensajes del servidor.

    Usa buffer acumulado porque TCP puede partir los mensajes en varios recv().
    Solo procesa las lineas que tienen \\n al final (completas).
    El resto lo guarda para el siguiente recv().
    """
    buf = bytearray()   # buffer para acumular datos de TCP
    try:
        while True:
            chunk = client_socket.recv(65_536)
            if not chunk:
                print("[MONITOR] El servidor cerro la conexion.")
                break

            buf.extend(chunk)
            # separar las lineas completas del fragmento incompleto
            text  = buf.decode("utf-8", errors="replace")
            parts = text.split("\n")
            buf   = bytearray(parts[-1].encode("utf-8"))  # lo que queda sin \n

            # procesar solo las lineas completas
            for line in parts[:-1]:
                handle_incoming_message(client_socket, line)
    except OSError:
        pass


# ─── distribucion de bloques ─────────────────────────────────────────────────

def distribute_blocks(client_socket:   socket.socket,
                      file_path:        str,
                      validator_nodes:  list[str]) -> None:
    """
    Ejecuta una ronda completa de consenso distribuido.

    Pasos:
      1. Pide al servidor la lista de nodos activos y calcula el quorum real
      2. Divide el archivo en bloques
      3. Para cada bloque:
         a. Registrar en _confirm_order (garantia de orden)
         b. Calcular el hash propuesto encadenado con el tip provisional
         c. Minar el nonce de prueba de trabajo
         d. Empaquetar en JSON y enviar a todos los validadores activos
         e. Registrar en pending_blocks y arrancar el timer de timeout

    Los bloques se mandan todos a la vez para que los validadores los procesen
    en paralelo. La confirmacion en el ledger se hace en orden estricto.
    """
    blocks = split_transactions_into_blocks(file_path)
    if not blocks:
        print("[AVISO] El archivo no contiene transacciones validas.")
        return
    if not validator_nodes:
        print("[ERROR] Debes indicar al menos un nodo validador.")
        return

    # ── FASE 1: quorum dinamico REAL ─────────────────────────────────
    # preguntar al hub que nodos estan realmente conectados ahora
    connected = query_connected_nodes(client_socket)
    if not connected:
        print("[AVISO] El servidor no reporto nodos conectados. "
              "Se usaran los nombres indicados sin verificar.")
        active_validators = list(validator_nodes)
    else:
        # quedarse solo con los validadores indicados que esten en linea
        active_validators = [v for v in validator_nodes if v in connected]
        offline = [v for v in validator_nodes if v not in connected]
        if offline:
            print(f"[AVISO] Nodos NO conectados (excluidos del quorum): {', '.join(offline)}")

    if not active_validators:
        print("[ERROR] Ninguno de los validadores indicados esta conectado al hub.")
        return

    # quorum = mayoria simple
    quorum = math.floor(len(active_validators) / 2) + 1
    print(f"\n[CARGA] {len(blocks)} bloque(s) candidato(s) desde '{file_path}'.")
    print(f"[CARGA] Validadores activos: {', '.join(active_validators)}")
    print(f"[CARGA] Quorum dinamico real: {quorum}/{len(active_validators)}\n")

    # tip provisional para el encadenamiento mientras se distribuyen los bloques
    with state_lock:
        provisional_prev = (confirmed_chain[-1]["hash"]
                            if confirmed_chain else "0" * 64)

    total = len(blocks)
    for index, block_text in enumerate(blocks, start=1):
        block_id = f"block_{index:03d}"

        # registrar en la cola de confirmacion ANTES de enviar
        with state_lock:
            _confirm_order.append(block_id)

        # hash propuesto encadenado con el tip provisional
        proposed_hash = compute_block_hash(provisional_prev, block_id, block_text)

        # minar el nonce de prueba de trabajo
        print(f"[MINANDO] {block_id} — buscando nonce con prefijo '{NONCE_PREFIX}'...")
        nonce, puzzle_hash = mine_nonce(block_text)
        print(f"[NONCE]   {block_id} -> nonce={nonce}  puzzle_hash={puzzle_hash[:12]}...")

        # armar el JSON que recibiran los validadores
        block_msg = json.dumps({
            "type":          "BLOCK",       # tipo de mensaje
            "block_id":      block_id,      # identificador del bloque
            "sequence":      f"{index}/{total}",  # posicion en la tanda
            "previous_hash": provisional_prev,    # hash del bloque anterior
            "text":          block_text,    # transacciones del bloque
            "proposed_hash": proposed_hash, # hash SHA-256 del bloque
            "nonce":         nonce,         # nonce que satisface la PoW
            "puzzle_hash":   puzzle_hash,   # SHA-256(nonce:text) con prefijo
        }, ensure_ascii=False)

        # registrar en pending_blocks con estado inicial
        with state_lock:
            pending_blocks[block_id] = {
                "text":          block_text,
                "validators":    set(active_validators),  # los que deben votar
                "voters":        set(),                   # los que ya votaron
                "yes_votes":     0,
                "no_votes":      0,
                "quorum":        quorum,
                "proposed_hash": proposed_hash,
                "previous_hash": provisional_prev,
                "timer":         None,   # se asigna abajo
            }

        # arrancar el timer de timeout para este bloque
        timer = schedule_block_timeout(client_socket, block_id)
        with state_lock:
            if block_id in pending_blocks:
                pending_blocks[block_id]["timer"] = timer

        # enviar a todos los validadores activos
        for validator in active_validators:
            send_private_message(client_socket, validator, block_msg)
        print(f"[ENVIADO] {block_id} -> {', '.join(active_validators)}")

        # avanzar el tip provisional para el siguiente bloque
        provisional_prev = proposed_hash


# ─── interfaz de usuario ─────────────────────────────────────────────────────

def parse_load_command(command: str) -> tuple[str | None, list[str] | None]:
    """
    Parsea el comando del operador:
        cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)

    Devuelve (archivo, [nodos]) si el formato es correcto.
    Devuelve (None, None) si no reconoce el formato.
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
    Punto de entrada del monitor.

    Se conecta al hub, manda su nombre como primer mensaje y arranca el hilo
    que escucha los votos en segundo plano. Despues entra en el loop
    interactivo esperando comandos del operador.

    Comando principal:
      cargar_bloques(archivo.txt, v1, v2, v3)
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    # el nombre se manda con \n para que el servidor lo reconozca completo
    client_socket.sendall((MONITOR_NAME + "\n").encode("utf-8"))

    print(f"[CONECTADO] Monitor registrado como '{MONITOR_NAME}' en {HOST}:{PORT}.")
    print("Comandos disponibles:")
    print("  cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)")
    print("  salir")
    print(f"Timeout por bloque: {BLOCK_TIMEOUT_SECONDS}s  |  Prefijo PoW: '{NONCE_PREFIX}'\n")

    # hilo daemon para escuchar votos y notificaciones mientras el operador escribe
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

            # si no especificaron nodos en el comando, pedirlos interactivamente
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
