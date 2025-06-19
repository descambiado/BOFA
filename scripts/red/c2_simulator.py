
#!/usr/bin/env python3
"""
C2 Simulator - BOFA Red Team Module
Simula servidor y cliente C2 para entrenamiento
"""

import socket
import threading
import json
import base64
import time
import argparse
import os
from datetime import datetime
import random
import string

class C2Server:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.clients = {}
        self.commands_log = []
        self.server_socket = None
        self.running = False
        self.output_dir = "output/c2_simulation"
        
    def create_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_client_id(self):
        """Genera ID único para cliente"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    
    def start_server(self):
        """Inicia el servidor C2"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[+] C2 Server iniciado en {self.host}:{self.port}")
            print("[+] Esperando conexiones...")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_id = self.generate_client_id()
                    
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'connected_at': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    print(f"[+] Nueva conexión: {client_id} desde {address}")
                    
                    # Iniciar hilo para manejar cliente
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_id, client_socket)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[!] Error aceptando conexión: {e}")
                        
        except Exception as e:
            print(f"[!] Error iniciando servidor: {e}")
    
    def handle_client(self, client_id, client_socket):
        """Maneja comunicación con cliente específico"""
        try:
            while self.running:
                # Recibir beacon del cliente
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode())
                    self.process_client_message(client_id, message)
                    
                    # Enviar respuesta (comando simulado)
                    response = self.generate_command_response(client_id)
                    client_socket.send(json.dumps(response).encode())
                    
                except json.JSONDecodeError:
                    print(f"[!] Datos inválidos de {client_id}")
                
                time.sleep(1)
                
        except Exception as e:
            print(f"[!] Error manejando cliente {client_id}: {e}")
        finally:
            self.disconnect_client(client_id)
    
    def process_client_message(self, client_id, message):
        """Procesa mensaje del cliente"""
        if client_id in self.clients:
            self.clients[client_id]['last_seen'] = datetime.now().isoformat()
        
        # Log del beacon
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'client_id': client_id,
            'type': 'beacon',
            'data': message
        }
        self.commands_log.append(log_entry)
        
        print(f"[>] Beacon de {client_id}: {message.get('status', 'unknown')}")
    
    def generate_command_response(self, client_id):
        """Genera respuesta de comando simulado"""
        commands = [
            {'cmd': 'sysinfo', 'args': []},
            {'cmd': 'sleep', 'args': ['30']},
            {'cmd': 'download', 'args': ['/etc/passwd']},
            {'cmd': 'screenshot', 'args': []},
            {'cmd': 'keylog', 'args': ['start']},
            {'cmd': 'persist', 'args': []},
            {'cmd': 'noop', 'args': []}  # No operation
        ]
        
        # Seleccionar comando aleatorio
        command = random.choice(commands)
        
        response = {
            'id': random.randint(1000, 9999),
            'command': command['cmd'],
            'args': command['args'],
            'timestamp': datetime.now().isoformat()
        }
        
        # Log del comando enviado
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'client_id': client_id,
            'type': 'command',
            'data': response
        }
        self.commands_log.append(log_entry)
        
        return response
    
    def disconnect_client(self, client_id):
        """Desconecta cliente"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            del self.clients[client_id]
            print(f"[-] Cliente {client_id} desconectado")
    
    def show_status(self):
        """Muestra estado del servidor"""
        print("\n" + "="*50)
        print("C2 SERVER STATUS")
        print("="*50)
        print(f"Clientes activos: {len(self.clients)}")
        print(f"Comandos enviados: {len([log for log in self.commands_log if log['type'] == 'command'])}")
        print(f"Beacons recibidos: {len([log for log in self.commands_log if log['type'] == 'beacon'])}")
        
        for client_id, info in self.clients.items():
            print(f"- {client_id}: {info['address']} (last seen: {info['last_seen']})")
    
    def save_logs(self):
        """Guarda logs de la sesión"""
        log_file = os.path.join(self.output_dir, f"c2_session_{int(time.time())}.json")
        
        session_data = {
            'server_info': {
                'host': self.host,
                'port': self.port,
                'started_at': datetime.now().isoformat()
            },
            'clients': self.clients,
            'commands_log': self.commands_log,
            'statistics': {
                'total_clients': len(self.clients),
                'total_commands': len([log for log in self.commands_log if log['type'] == 'command']),
                'total_beacons': len([log for log in self.commands_log if log['type'] == 'beacon'])
            }
        }
        
        with open(log_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        print(f"[+] Logs guardados en: {log_file}")
        return log_file
    
    def stop_server(self):
        """Detiene el servidor"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[+] Servidor C2 detenido")

class C2Client:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
    def connect(self):
        """Conecta al servidor C2"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.running = True
            print(f"[+] Conectado a C2 server {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[!] Error conectando: {e}")
            return False
    
    def generate_beacon(self):
        """Genera beacon simulado"""
        beacon = {
            'timestamp': datetime.now().isoformat(),
            'hostname': 'victim-pc',
            'username': 'user',
            'os': 'Windows 10',
            'ip': '192.168.1.100',
            'status': 'alive',
            'processes': random.randint(50, 200),
            'uptime': random.randint(3600, 86400)
        }
        return beacon
    
    def simulate_command_execution(self, command):
        """Simula ejecución de comando"""
        print(f"[>] Ejecutando comando simulado: {command['command']}")
        
        # Simular diferentes respuestas según comando
        if command['command'] == 'sysinfo':
            return "Windows 10 Pro - Intel i7 - 16GB RAM"
        elif command['command'] == 'screenshot':
            return "Screenshot captured: screenshot_123.png"
        elif command['command'] == 'download':
            return f"File downloaded: {command['args'][0]}"
        elif command['command'] == 'keylog':
            return "Keylogger started"
        elif command['command'] == 'persist':
            return "Persistence mechanism installed"
        else:
            return "Command executed successfully"
    
    def start_beacon_loop(self):
        """Inicia loop de beacons"""
        try:
            while self.running:
                # Enviar beacon
                beacon = self.generate_beacon()
                self.socket.send(json.dumps(beacon).encode())
                
                # Recibir comando
                response = self.socket.recv(4096)
                if response:
                    try:
                        command = json.loads(response.decode())
                        result = self.simulate_command_execution(command)
                        print(f"[<] Resultado: {result}")
                    except json.JSONDecodeError:
                        print("[!] Respuesta inválida del servidor")
                
                # Esperar antes del siguiente beacon
                time.sleep(random.randint(5, 15))
                
        except Exception as e:
            print(f"[!] Error en beacon loop: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Desconecta del servidor"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[+] Desconectado del servidor C2")

def main():
    parser = argparse.ArgumentParser(description="C2 Simulator (Educational)")
    parser.add_argument("mode", choices=["server", "client"], help="Modo de operación")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Host del servidor")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Puerto del servidor")
    parser.add_argument("-o", "--output", help="Directorio de salida")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔴 BOFA C2 Simulator")
    print("⚠️  SOLO FINES EDUCATIVOS Y SIMULACIÓN")
    print("=" * 60)
    
    if args.mode == "server":
        server = C2Server(args.host, args.port)
        
        if args.output:
            server.output_dir = args.output
        server.create_output_dir()
        
        try:
            # Iniciar servidor en hilo separado
            server_thread = threading.Thread(target=server.start_server)
            server_thread.daemon = True
            server_thread.start()
            
            # Menu interactivo
            while True:
                print("\n[C2 SERVER MENU]")
                print("1. Mostrar estado")
                print("2. Guardar logs")
                print("3. Salir")
                
                choice = input("Selecciona opción: ").strip()
                
                if choice == "1":
                    server.show_status()
                elif choice == "2":
                    server.save_logs()
                elif choice == "3":
                    server.stop_server()
                    break
                    
        except KeyboardInterrupt:
            server.stop_server()
    
    elif args.mode == "client":
        client = C2Client(args.host, args.port)
        
        if client.connect():
            try:
                client.start_beacon_loop()
            except KeyboardInterrupt:
                client.disconnect()

if __name__ == "__main__":
    main()
