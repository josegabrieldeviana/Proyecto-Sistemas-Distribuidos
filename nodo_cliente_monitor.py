"""
NODO MONITOR — Orquestador / Validador Maestro
══════════════════════════════════════════════════════════════════
Responsabilidades:
  • Recibir instrucciones del usuario (cargar_bloques).
  • Segmentar el archivo de transacciones en bloques candidatos.
  • Calcular el quórum dinámicamente según los validadores disponibles.
  • Pre-computar la cadena provisional de hashes y minar nonces (PoW ligero).
  • Distribuir bloques a los Procesadores via mensajes privados (/w).
  • Escuchar el chat público y contabilizar votos VOTE|bid|YES/NO.
  • Detectar quórum alcanzado  →  confirmar bloque en el ledger.
  • Detectar bifurcaciones     →  anunciar BIFURCACION_DETECTADA.
  • Detectar nodos caídos      →  timeout por bloque con timer.
══════════════════════════════════════════════════════════════════
"""

import hashlib
import json
import math
import re
import socket
import threading
from pathlib import Path

# ── Configuración de red ──────────────────────────────────────────────
HOST:         str = "127.0.0.1"
PORT:         int = 5000
MONITOR_NAME: str = "monitor"

# ── Parámetros de bloque y consenso ──────────────────────────────────
BLOCK_LINE_COUNT:      int = 5     # Líneas de transacciones por bloque
BLOCK_TIMEOUT_SECONDS: int = 30    # Segundos hasta declarar timeout/bifurcación
NONCE_PREFIX:          str = "0"   # El hash del acertijo debe comenzar con esto (PoW ligero)

# ── Estado global (protegido por state_lock) ──────────────────────────
state_lock:      threading.Lock = threading.Lock()
pending_blocks:  dict           = {}   # bloques en vuelo esperando votos
confirmed_chain: list           = []   # ledger definitivo de bloques confirmados


# ══════════════════════ CRIPTOGRAFÍA ════════════════════════════════

def compute_block_hash(previous_hash: str, block_id: str, block_text: str) -> str:
    """
    Calcula el hash SHA-256 canónico del bloque.

    Usa serialización JSON con claves ordenadas para garantizar:
      • Reproducibilidad total: misma entrada → mismo hash siempre.
      • Resistencia a colisiones por concatenación:
            ("abc","def","ghi") ≠ ("abcdef","g","hi")
        porque JSON encapsula cada campo con comillas y separadores.
      • Codificación UTF-8 consistente entre todos los nodos.

    Entrada canónica ejemplo:
        {"block_id":"block_001","block_text":"TX…","previous_hash":"0000…"}
    """
    canonical = json.dumps(
        {
            "block_id":      block_id,
            "block_text":    block_text,
            "previous_hash": previous_hash,
        },
        sort_keys=True,        # orden determinístico de claves
        ensure_ascii=False,
        separators=(",", ":"), # formato compacto, sin espacios extra
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mine_nonce(block_text: str) -> tuple[int, str]:
    """
    Prueba de Trabajo (PoW) ligera:
    Encuentra el menor entero N ≥ 0 tal que
        SHA-256(str(N) + ":" + block_text)  empiece con NONCE_PREFIX.

    La ":" entre nonce y texto es un separador fijo; como N es siempre
    un entero sin ":", no hay ambigüedad ni colisión posible.

    Promedio de iteraciones para NONCE_PREFIX="0" → ~16 (trivial).
    Retorna (nonce, puzzle_hash).
    """
    nonce = 0
    while True:
        candidate  = f"{nonce}:{block_text}".encode("utf-8")
        puzzle_hash = hashlib.sha256(candidate).hexdigest()
        if puzzle_hash.startswith(NONCE_PREFIX):
            return nonce, puzzle_hash
        nonce += 1


# ══════════════════════ COMUNICACIÓN ════════════════════════════════

def send_private_message(client_socket: socket.socket,
                         target_node: str,
                         message: str) -> None:
    """Envía un mensaje privado al nodo destino a través del servidor hub."""
    client_socket.sendall(f"/w {target_node} {message}".encode("utf-8"))


# ══════════════════════ BLOCKCHAIN / LEDGER ═════════════════════════

def split_transactions_into_blocks(file_path: str,
                                   block_line_count: int = BLOCK_LINE_COUNT
                                   ) -> list[str]:
    """
    Lee el archivo de transacciones y lo segmenta en bloques de
    'block_line_count' líneas cada uno.
    Retorna lista de strings, uno por bloque.
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
    """Imprime el estado completo del ledger confirmado."""
    print("\n╔══ ESTADO GLOBAL DE LA BLOCKCHAIN ══╗")
    if not confirmed_chain:
        print("║  (sin bloques confirmados todavía)  ║")
        print("╚═════════════════════════════════════╝")
        return
    for i, block in enumerate(confirmed_chain, start=1):
        status = "OK"
        print(f"║  {i:02d}. {block['block_id']}")
        print(f"║      hash     : {block['hash'][:20]}…")
        print(f"║      prev_hash: {block['previous_hash'][:20]}…")
        print(f"║      quórum   : {block['yes_votes']}/{block['quorum']}  [{status}]")
    print("╚═════════════════════════════════════╝\n")


# ══════════════════════ GESTIÓN DE BLOQUES ══════════════════════════

def schedule_block_timeout(client_socket: socket.socket,
                           block_id: str) -> threading.Timer:
    """
    Programa un timer: si el bloque no se confirma/rechaza antes de
    BLOCK_TIMEOUT_SECONDS, se declara timeout y posible nodo caído.
    Retorna el timer para poder cancelarlo si el bloque se resuelve antes.
    """
    def _timeout() -> None:
        with state_lock:
            info = pending_blocks.pop(block_id, None)
        if info is None:
            return   # Ya fue procesado antes del timeout

        yes   = info["yes_votes"]
        total = len(info["voters"])
        quorum = info["quorum"]
        print(f"\n[TIMEOUT] {block_id} expiró tras {BLOCK_TIMEOUT_SECONDS}s.")
        print(f"[TIMEOUT] Votos SI: {yes} | Votantes: {total} | Quórum: {quorum}")
        print(f"[TIMEOUT] Posibles nodos caídos o sin respuesta.")
        print(f"[TIMEOUT] {block_id} descartado — posible BIFURCACION por inactividad.\n")

    timer = threading.Timer(BLOCK_TIMEOUT_SECONDS, _timeout)
    timer.daemon = True
    timer.start()
    return timer


def detect_fork(client_socket: socket.socket,
                block_id: str,
                yes_votes: int,
                total_validators: int,
                quorum: int) -> None:
    """
    Se invoca cuando TODOS los validadores emitieron su voto pero
    los votos afirmativos (YES) no alcanzan el quórum.
    Esto indica una bifurcación: la red no tiene consenso sobre este bloque.
    """
    print(f"\n╔══ BIFURCACION_DETECTADA ══╗")
    print(f"║  Bloque  : {block_id}")
    print(f"║  Votos SI: {yes_votes} / {total_validators}")
    print(f"║  Quórum  : {quorum}  →  NO alcanzado")
    print(f"║  Acción  : bloque RECHAZADO, no se inserta en el ledger.")
    print(f"╚════════════════════════════╝\n")

    # Anuncia la bifurcación a toda la red
    client_socket.sendall(
        f"/broadcast BIFURCACION_DETECTADA {block_id} votos_si={yes_votes}/{total_validators}\n".encode("utf-8")
    )


def confirm_block(client_socket: socket.socket, block_id: str) -> None:
    """
    Inserta el bloque en el ledger permanente, cancela su timer y
    difunde CONSENSO_ALCANZADO a toda la red.
    """
    with state_lock:
        info = pending_blocks.pop(block_id, None)
        if info is None:
            return

        # Cancelar el timer de timeout
        timer = info.get("timer")
        if timer:
            timer.cancel()

        # Encadenar usando el último hash confirmado (o génesis)
        previous_hash = (confirmed_chain[-1]["hash"]
                         if confirmed_chain else "0" * 64)
        block_hash = compute_block_hash(previous_hash, block_id, info["text"])

        confirmed_chain.append({
            "block_id":      block_id,
            "hash":          block_hash,
            "previous_hash": previous_hash,
            "text":          info["text"],
            "yes_votes":     info["yes_votes"],
            "quorum":        info["quorum"],
        })

    print(f"\n[QUORUM ALCANZADO] {block_id} aprobado e insertado en el ledger.")
    print_global_blockchain_state()

    # Difundir confirmación a toda la red (Fase 5 de la rúbrica)
    client_socket.sendall(
        f"/broadcast CONSENSO_ALCANZADO {block_id} | hash={block_hash[:12]}…\n".encode("utf-8")
    )


# ══════════════════════ VOTACIÓN ════════════════════════════════════

def register_vote(client_socket: socket.socket,
                  block_id: str,
                  voter: str,
                  decision: bool) -> bool:
    """
    Registra el voto de 'voter' para 'block_id'.
    - Ignora votos duplicados del mismo nodo.
    - Comprueba quórum tras cada voto afirmativo.
    - Detecta bifurcación cuando todos votaron pero el quórum no se alcanzó.
    Retorna True si el voto fue aceptado, False si fue ignorado.
    """
    with state_lock:
        info = pending_blocks.get(block_id)
        if info is None:
            return False
        if voter in info["voters"]:
            return False   # Voto duplicado

        info["voters"].add(voter)
        if decision:
            info["yes_votes"] += 1

        yes_votes        = info["yes_votes"]
        quorum           = info["quorum"]
        total_voters     = len(info["voters"])
        total_validators = len(info["validators"])

    # ── ¿Se alcanzó el quórum? ───────────────────────────────────────
    if yes_votes >= quorum:
        confirm_block(client_socket, block_id)
        return True

    # ── ¿Todos votaron sin alcanzar quórum? → bifurcación ───────────
    if total_voters >= total_validators:
        with state_lock:
            pending_blocks.pop(block_id, None)
            timer = info.get("timer")
        if timer:
            timer.cancel()
        detect_fork(client_socket, block_id, yes_votes, total_validators, quorum)
        return True

    # ── Voto registrado, esperando más ──────────────────────────────
    print(f"[VOTO REGISTRADO] {block_id}: {yes_votes}/{quorum} votos SI "
          f"({total_voters}/{total_validators} nodos respondieron)")
    return True


def parse_vote_message(message: str) -> tuple[str | None, bool | None]:
    """
    Extrae (block_id, decision) de un mensaje de voto.
    Formatos soportados:
      VOTE|block_001|YES         (formato primario de los Procesadores)
      VOTE|block_001|NO
      VOTE block_001 YES         (variante con espacios)
      BLOQUE_OK|block_001        (formato alternativo del spec)
      BLOQUE_INVALIDO|block_001
    """
    message = message.strip()

    # ── Formato VOTE|bid|YES/NO o VOTE bid YES/NO ───────────────────
    m = re.search(
        r"VOTE[|\s]+(?P<block>block_\w+)[|\s]+(?P<decision>YES|NO|SI)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() in {"YES", "SI"}
        return m.group("block"), decision

    # ── Formato BLOQUE_OK|bid  o  BLOQUE_INVALIDO|bid ───────────────
    m = re.search(
        r"(?P<decision>BLOQUE_OK|BLOQUE_INVALIDO)[|\s]+(?P<block>block_\w+)",
        message, re.IGNORECASE
    )
    if m:
        decision = m.group("decision").upper() == "BLOQUE_OK"
        return m.group("block"), decision

    return None, None


def handle_incoming_message(client_socket: socket.socket,
                            message: str) -> None:
    """
    Clasifica cada mensaje recibido del servidor:
      - Mensaje privado  →  PRIVATE_FROM_<sender>: <payload>
      - Chat general     →  <sender>: <payload>
    Extrae sender y payload, descarta mensajes propios y del servidor,
    intenta parsear como voto y lo registra si corresponde.
    """
    message = message.strip()
    if not message:
        return

    print(message)   # registro de auditoría en consola

    sender:  str | None = None
    payload: str | None = None

    # ── Mensaje privado ──────────────────────────────────────────────
    if message.startswith("PRIVATE_FROM_"):
        try:
            rest        = message[len("PRIVATE_FROM_"):]
            sender, payload = rest.split(": ", 1)
        except ValueError:
            return

    # ── Chat general ─────────────────────────────────────────────────
    else:
        try:
            sender, payload = message.split(": ", 1)
        except ValueError:
            return

    # Ignorar mensajes propios y del servidor
    if not sender or sender == MONITOR_NAME or sender.startswith("[SERVIDOR]"):
        return

    block_id, decision = parse_vote_message(payload)
    if block_id is None:
        return

    register_vote(client_socket, block_id, sender, decision)


def receive_messages(client_socket: socket.socket) -> None:
    """
    Hilo daemon: escucha el socket y procesa cada línea de mensaje
    que llega del servidor (votos, notificaciones de red, etc.).
    """
    try:
        while True:
            data = client_socket.recv(65_536)
            if not data:
                print("[MONITOR] El servidor cerró la conexión.")
                break
            # Un recv() puede traer varias líneas fusionadas por el SO
            for line in data.decode("utf-8", errors="replace").split("\n"):
                handle_incoming_message(client_socket, line)
    except OSError:
        pass


# ══════════════════════ DISTRIBUCIÓN DE BLOQUES ═════════════════════

def distribute_blocks(client_socket: socket.socket,
                      file_path: str,
                      validator_nodes: list[str]) -> None:
    """
    Flujo completo de distribución de una ronda de consenso:

    1. Segmenta el archivo en bloques candidatos.
    2. Calcula el quórum dinámico:  floor(N/2) + 1  donde N = # validadores.
    3. Para cada bloque:
         a. Computa proposed_hash (encadenando desde el tip actual del ledger).
         b. Mina un nonce  →  SHA-256(nonce:block_text) empieza con NONCE_PREFIX.
         c. Empaqueta todo en JSON y lo envía a cada validador via /w.
         d. Registra el bloque en pending_blocks.
         e. Programa un timer de timeout.
    """
    blocks = split_transactions_into_blocks(file_path)
    if not blocks:
        print("[AVISO] El archivo no contiene transacciones válidas.")
        return
    if not validator_nodes:
        print("[ERROR] Debes indicar al menos un nodo validador.")
        return

    # ── Quórum dinámico ──────────────────────────────────────────────
    quorum = math.floor(len(validator_nodes) / 2) + 1
    print(f"\n[CARGA] {len(blocks)} bloque(s) candidato(s) desde '{file_path}'.")
    print(f"[CARGA] Validadores: {', '.join(validator_nodes)}")
    print(f"[CARGA] Quórum dinámico requerido: {quorum}/{len(validator_nodes)}\n")

    # Punta provisional de la cadena para encadenamiento de hashes
    with state_lock:
        provisional_prev = (confirmed_chain[-1]["hash"]
                            if confirmed_chain else "0" * 64)

    total = len(blocks)
    for index, block_text in enumerate(blocks, start=1):
        block_id = f"block_{index:03d}"

        # ── Hash propuesto (verifica integridad del bloque) ──────────
        proposed_hash = compute_block_hash(provisional_prev, block_id, block_text)

        # ── Minado de nonce (acertijo PoW ligero) ────────────────────
        print(f"[MINANDO] {block_id} — buscando nonce con prefijo '{NONCE_PREFIX}'…")
        nonce, puzzle_hash = mine_nonce(block_text)
        print(f"[NONCE]   {block_id} → nonce={nonce}  puzzle_hash={puzzle_hash[:12]}…")

        # ── Mensaje JSON para los validadores ────────────────────────
        block_msg = json.dumps({
            "type":          "BLOCK",
            "block_id":      block_id,
            "sequence":      f"{index}/{total}",
            "previous_hash": provisional_prev,
            "text":          block_text,
            "proposed_hash": proposed_hash,
            "nonce":         nonce,
            "puzzle_hash":   puzzle_hash,
        }, ensure_ascii=False)

        # ── Registro del bloque pendiente ────────────────────────────
        with state_lock:
            pending_blocks[block_id] = {
                "text":          block_text,
                "validators":    set(validator_nodes),
                "voters":        set(),
                "yes_votes":     0,
                "quorum":        quorum,
                "proposed_hash": proposed_hash,
                "previous_hash": provisional_prev,
                "timer":         None,   # se asigna justo después
            }

        # ── Timer de timeout ─────────────────────────────────────────
        timer = schedule_block_timeout(client_socket, block_id)
        with state_lock:
            if block_id in pending_blocks:
                pending_blocks[block_id]["timer"] = timer

        # ── Envío a cada validador ───────────────────────────────────
        for validator in validator_nodes:
            send_private_message(client_socket, validator, block_msg)
        print(f"[ENVIADO] {block_id} → {', '.join(validator_nodes)}")

        # Avanzar la cadena provisional para el siguiente bloque
        provisional_prev = proposed_hash


# ══════════════════════ INTERFAZ DE USUARIO ═════════════════════════

def parse_load_command(command: str) -> tuple[str | None, list[str] | None]:
    """
    Parsea el comando: cargar_bloques(archivo.txt, nodo1, nodo2, …)
    Retorna (file_path, [nodos]) o (None, None) si el formato es incorrecto.
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
    """Punto de entrada del Monitor: conecta al hub y lanza el loop interactivo."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(MONITOR_NAME.encode("utf-8"))

    print(f"[CONECTADO] Monitor registrado como '{MONITOR_NAME}' en {HOST}:{PORT}.")
    print("Comandos disponibles:")
    print("  cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)")
    print("  salir")
    print(f"Timeout por bloque: {BLOCK_TIMEOUT_SECONDS}s  |  Prefijo PoW: '{NONCE_PREFIX}'\n")

    # Hilo daemon listener de mensajes entrantes (votos, notificaciones)
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
                print("  Uso: cargar_bloques(archivo.txt, nodo1, nodo2, …)")
                continue

            # Si el usuario escribió "nodos_validadores" como placeholder
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
        print("\n[SALIENDO] Cerrando monitor…")
    finally:
        try:
            client_socket.close()
        except OSError:
            pass


if __name__ == "__main__":
    start_monitor()
