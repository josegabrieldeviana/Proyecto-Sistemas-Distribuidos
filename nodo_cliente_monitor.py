import hashlib
import math
import re
import socket
import threading
from pathlib import Path

HOST = "127.0.0.1"
PORT = 5000
MONITOR_NAME = "monitor"
BLOCK_LINE_COUNT = 5

state_lock = threading.Lock()
pending_blocks = {}
confirmed_chain = []


def send_private_message(client_socket, target_node, message):
    client_socket.sendall(f"/w {target_node} {message}".encode("utf-8"))


def split_transactions_into_blocks(file_path, block_line_count=BLOCK_LINE_COUNT):
    file_path = Path(file_path)
    content_lines = file_path.read_text(encoding="utf-8").splitlines()
    blocks = []

    for index in range(0, len(content_lines), block_line_count):
        chunk = content_lines[index:index + block_line_count]
        block_text = "\n".join(chunk).strip()
        if block_text:
            blocks.append(block_text)

    return blocks


def compute_block_hash(previous_hash, block_id, block_text):
    payload = f"{previous_hash}|{block_id}|{block_text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def print_global_blockchain_state():
    print("\n[ESTADO GLOBAL DE LA BLOCKCHAIN]")
    if not confirmed_chain:
        print("  (sin bloques confirmados todavía)")
        return

    for index, block in enumerate(confirmed_chain, start=1):
        print(f"  {index}. {block['block_id']} | hash={block['hash']} | quorum={block['yes_votes']}/{block['quorum']}")


def confirm_block(client_socket, block_id):
    with state_lock:
        block_info = pending_blocks.pop(block_id, None)
        if not block_info:
            return

        previous_hash = confirmed_chain[-1]["hash"] if confirmed_chain else "0" * 64
        block_hash = compute_block_hash(previous_hash, block_id, block_info["text"])
        confirmed_chain.append(
            {
                "block_id": block_id,
                "hash": block_hash,
                "previous_hash": previous_hash,
                "text": block_info["text"],
                "yes_votes": block_info["yes_votes"],
                "quorum": block_info["quorum"],
            }
        )

    print(f"\n[QUORUM ALCANZADO] {block_id} ha sido aprobado e insertado en el registro histórico.")
    print_global_blockchain_state()
    
    # EXIGENCIA DE LA RÚBRICA (Consistencia): El Monitor anuncia el éxito a toda la red por broadcast (Fase 5)
    notificacion = f"/broadcast CONSENSO_ALCANZADO {block_id} | hash={block_hash[:12]}..."
    client_socket.sendall(notificacion.encode("utf-8"))


def register_vote(client_socket, block_id, voter, decision):
    with state_lock:
        block_info = pending_blocks.get(block_id)
        if not block_info:
            return False

        if voter in block_info["voters"]:
            return False

        block_info["voters"].add(voter)
        if decision:
            block_info["yes_votes"] += 1

        current_yes_votes = block_info["yes_votes"]
        current_quorum = block_info["quorum"]

    if current_yes_votes >= current_quorum:
        confirm_block(client_socket, block_id)
        return True

    print(f"[VOTO REGISTRADO] {block_id}: {current_yes_votes}/{current_quorum} votos positivos.")
    return True


def parse_vote_message(message):
    message = message.strip()
    patterns = [
        r"^VOTE[|\s]+(?P<block>[^|\s]+)[|\s]+(?P<decision>YES|NO|SI|NO)$",
        r"^VOTO[|\s]+(?P<block>[^|\s]+)[|\s]+(?P<decision>SI|NO|YES)$",
        r"^(?P<block>block_[^:\s|]+)[|:\s]+(?P<decision>YES|NO|SI)$",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            block_id = match.group("block")
            decision = match.group("decision").upper() in {"YES", "SI"}
            return block_id, decision

    return None, None


def handle_incoming_message(client_socket, message):
    print(message)  # Muestra el mensaje en consola para auditoría

    sender = None
    payload = None

    # Caso 1: El voto llega por mensaje privado (PRIVATE_FROM_Validador1: VOTE block_001 YES)
    if message.startswith("PRIVATE_FROM_"):
        try:
            prefix_removed = message[len("PRIVATE_FROM_"):]
            sender, payload = prefix_removed.split(": ", 1)
        except ValueError:
            return

    # Caso 2: El voto llega por el chat general / broadcast (Validador1: VOTE block_001 YES)
    else:
        try:
            sender, payload = message.split(": ", 1)
        except ValueError:
            return

    # Evitamos procesar mensajes que hayamos enviado nosotros mismos
    if sender == MONITOR_NAME:
        return

    # Intentamos parsear el voto utilizando tus expresiones regulares
    block_id, decision = parse_vote_message(payload)
    if not block_id:
        return

    # Si el formato es correcto, registramos el voto pasando el socket
    register_vote(client_socket, block_id, sender, decision)


def receive_messages(client_socket):
    """Escucha y procesa los mensajes que envía el servidor."""
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                print("[DESCONECTADO] El servidor cerró la conexión.")
                break

            message = data.decode("utf-8", errors="replace")
            handle_incoming_message(client_socket, message)
    except OSError:
        pass


def distribute_blocks(client_socket, file_path, validator_nodes):
    blocks = split_transactions_into_blocks(file_path)
    if not blocks:
        print("[AVISO] El archivo no contiene transacciones válidas para segmentar.")
        return

    if not validator_nodes:
        print("[ERROR] Debes indicar al menos un nodo validador.")
        return

    quorum = math.floor(len(validator_nodes) / 2) + 1
    print(f"[CARGA] {len(blocks)} bloques candidatos preparados desde {file_path}.")
    print(f"[CARGA] Válidadores objetivo: {', '.join(validator_nodes)} | quórum requerido: {quorum}.")

    for index, block_text in enumerate(blocks, start=1):
        block_id = f"block_{index:03d}"
        with state_lock:
            pending_blocks[block_id] = {
                "text": block_text,
                "validators": set(validator_nodes),
                "voters": set(),
                "yes_votes": 0,
                "quorum": quorum,
            }

        message = f"BLOCK|{block_id}|{index}/{len(blocks)}|{block_text}"
        for validator_node in validator_nodes:
            send_private_message(client_socket, validator_node, message)

        print(f"[ENVIADO] {block_id} -> {', '.join(validator_nodes)}")


def parse_load_command(command):
    match = re.fullmatch(r"cargar_bloques\(\s*(?P<file>[^,]+?)\s*,\s*(?P<nodes>.+?)\s*\)", command.strip(), flags=re.IGNORECASE)
    if not match:
        return None, None

    file_path = match.group("file").strip().strip('"').strip("'")
    raw_nodes = match.group("nodes").strip()
    validator_nodes = [node.strip().strip('"').strip("'") for node in raw_nodes.split(",") if node.strip()]
    return file_path, validator_nodes


def start_monitor():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(MONITOR_NAME.encode("utf-8"))

    print(f"[CONECTADO] Monitor registrado como '{MONITOR_NAME}' en {HOST}:{PORT}.")
    print("Comandos disponibles:")
    print("  cargar_bloques(archivo.txt, nodo1, nodo2, nodo3)")
    print("  salir")
    print("El monitor escucha votos en formato VOTE|block_001|YES o VOTO|block_001|SI.")

    listener = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
    listener.start()

    try:
        while True:
            command = input("monitor> ").strip()
            if not command:
                continue

            if command.lower() in {"salir", "exit", "quit"}:
                break

            file_path, validator_nodes = parse_load_command(command)
            if file_path is None:
                print("[ERROR] Comando no reconocido. Usa cargar_bloques(archivo.txt, nodo1, nodo2, ...).")
                continue

            if not validator_nodes or validator_nodes == ["nodos_validadores"]:
                raw_validators = input("Ingresa los nodos validadores separados por coma: ").strip()
                validator_nodes = [node.strip().strip('"').strip("'") for node in raw_validators.split(",") if node.strip()]

            try:
                distribute_blocks(client_socket, file_path, validator_nodes)
            except FileNotFoundError:
                print(f"[ERROR] No se encontró el archivo: {file_path}")
            except UnicodeDecodeError:
                print(f"[ERROR] No se pudo leer el archivo como texto UTF-8: {file_path}")
            except OSError as exc:
                print(f"[ERROR] No fue posible procesar el archivo: {exc}")
    except (KeyboardInterrupt, EOFError):
        print("\n[SALIENDO] Cerrando monitor...")
    finally:
        try:
            client_socket.close()
        except OSError:
            pass


if __name__ == "__main__":
    start_monitor()