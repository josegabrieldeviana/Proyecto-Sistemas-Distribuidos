#parte de josé

import socket
import threading

# Configuración del servidor
HOST = '127.0.0.1'
PORT = 5000

# Diccionario para rastrear clientes: {nombre_nodo: socket_objeto}
clients = {}

def broadcast(message, sender_socket):
    """Envía un mensaje a todos los clientes excepto al remitente."""
    for client_name, client_socket in clients.items():
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except:
                continue

def handle_client(client_socket, address):
    """Maneja la comunicación individual con cada nodo."""
    print(f"[NUEVA CONEXIÓN] {address} conectado.")
    
    # El primer mensaje del cliente debe ser su nombre para registrarlo
    try:
        client_name = client_socket.recv(1024).decode('utf-8').strip()
        clients[client_name] = client_socket
        print(f"[REGISTRO] Cliente '{client_name}' registrado.")
        
        while True:
            # Recibir mensaje del cliente
            raw_data = client_socket.recv(4096).decode('utf-8')
            if not raw_data:
                break
            
            print(f"[MENSAJE DE {client_name}]: {raw_data}")

            # Lógica de Mensajería Privada (/w <nodo> <mensaje>)
            if raw_data.startswith("/w "):
                try:
                    parts = raw_data.split(" ", 2)
                    target_node = parts[1]
                    message_content = parts[2]
                    
                    if target_node in clients:
                        # Formato: Enviamos el mensaje tal cual al destinatario
                        # El PDF dice que el servidor permite comunicación indirecta
                        clients[target_node].send(f"PRIVATE_FROM_{client_name}: {message_content}".encode('utf-8'))
                    else:
                        client_socket.send(f"ERROR: Nodo {target_node} no encontrado.".encode('utf-8'))
                except IndexError:
                    client_socket.send("ERROR: Formato incorrecto. Use /w <nodo> <mensaje>".encode('utf-8'))
            
            # Lógica de Broadcast (Votaciones y logs generales)
            elif raw_data.startswith("/broadcast "):
                message_content = raw_data.replace("/broadcast ", "")
                broadcast(f"{client_name}: {message_content}", client_socket)
            
            else:
                # Cualquier otro mensaje se puede tratar como broadcast por defecto
                broadcast(f"{client_name}: {raw_data}", client_socket)

    except Exception as e:
        print(f"[ERROR] Con {address}: {e}")
    finally:
        # Limpieza al desconectar
        if 'client_name' in locals():
            print(f"[DESCONEXIÓN] {client_name} se ha ido.")
            del clients[client_name]
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[INICIADO] Servidor escuchando en {HOST}:{PORT}...")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()