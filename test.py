import socket
import threading
import time
import random
from zlib import crc32
import sys

# Classe que representa um nó na rede em anel
class RingNode:
    def __init__(self, config_file):
        # Lê as configurações do arquivo de texto
        with open(config_file) as f:
            lines = [line.strip() for line in f.readlines()]
            self.dest_ip, self.dest_port = lines[0].split(":")
            self.dest_port = int(self.dest_port)
            self.nickname = lines[1]
            self.token_hold_time = int(lines[2])
            self.is_token_creator = lines[3].lower() == "true"

        self.listen_port = int(lines[4])  # Porta de escuta
        self.has_token = self.is_token_creator
        self.token_start_time = time.time() if self.has_token else None
        self.token_timeout = 10  # Tempo máximo para token retornar
        self.token_min_interval = 1  # Tempo mínimo entre tokens
        self.message_queue = []
        self.retry_queue = {}  # Mensagens aguardando retransmissão

        # Cria socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.listen_port))

        self.lock = threading.Lock()

        # Inicia as threads principais
        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.token_monitor, daemon=True).start()
        threading.Thread(target=self.user_interface, daemon=True).start()

        print(f"[{self.nickname}] Pronto. Enviando para {self.dest_ip}:{self.dest_port}.")

        if self.is_token_creator:
            time.sleep(1)
            self.send_token()

    # Loop que escuta mensagens UDP recebidas
    def listen_loop(self):
        while True:
            data, _ = self.sock.recvfrom(2048)
            message = data.decode('utf-8')

            if message == "9000":
                self.receive_token()
            elif message.startswith("7777:"):
                self.handle_data(message)

    # Gera e envia um novo token
    def send_token(self):
        self.token_start_time = time.time()
        self.has_token = False
        self.sock.sendto(b"9000", (self.dest_ip, self.dest_port))
        print(f"[{self.nickname}] Token enviado.")

    # Processa o recebimento do token
    def receive_token(self):
        now = time.time()

        if self.is_token_creator:
            elapsed = now - self.token_start_time
            if elapsed < self.token_min_interval:
                print(f"[{self.nickname}] Token chegou cedo. Descartado.")
                return
            elif elapsed > self.token_timeout:
                print(f"[{self.nickname}] Token perdido. Gerando novo.")
                self.send_token()
                return

        self.token_start_time = now
        self.has_token = True
        print(f"[{self.nickname}] Recebeu o token.")

        with self.lock:
            if self.message_queue:
                msg = self.message_queue.pop(0)
                self.send_message(msg)
            else:
                print(f"[{self.nickname}] Aguardando {self.token_hold_time}s antes de repassar o token.")
                time.sleep(self.token_hold_time)  # <- correção: segurar token mesmo se não tiver mensagem
                self.send_token()


    # Envia uma mensagem com possibilidade de corrompê-la propositalmente
    def send_message(self, msg):
        if random.random() < 0.1:  # 10% de chance de corromper
            msg = self.corrupt_message(msg)  # <-correção: função para corromper propositalmente
            print(f"[{self.nickname}] Mensagem corrompida propositalmente.")

        self.sock.sendto(msg.encode('utf-8'), (self.dest_ip, self.dest_port))
        self.has_token = False

    # Inverte string para simular corrupção <-correção
    def corrupt_message(self, msg):
        return msg[::-1]

    # Trata mensagens de dados recebidas
    def handle_data(self, raw):
        try:
            _, payload = raw.split(":", 1)
            status, origin, dest, crc_str, content = payload.split(";", 4)
            crc_recv = int(crc_str)

            if dest == self.nickname or dest == "TODOS":
                valid = crc32(content.encode()) == crc_recv
                ack_type = "ACK" if valid else "NACK"

                print(f"[{self.nickname}] Recebeu de {origin}: {content} | CRC {'OK' if valid else 'FALHOU'}")
                resp = f"7777:{ack_type};{origin};{self.nickname};{crc_recv};{content}"
                self.sock.sendto(resp.encode('utf-8'), (self.dest_ip, self.dest_port))

            elif origin == self.nickname:
                if status == "ACK":
                    print(f"[{self.nickname}] {dest} recebeu corretamente.")
                elif status == "NACK":
                    print(f"[{self.nickname}] {dest} respondeu com erro. Vai retransmitir uma vez.")
                    self.retry_queue[(dest, content)] = raw.replace("NACK", "naoexiste")
                elif status == "naoexiste":
                    print(f"[{self.nickname}] Destino {dest} não existe.")

                self.send_token()
            else:
                # Encaminha mensagem adiante
                self.sock.sendto(raw.encode('utf-8'), (self.dest_ip, self.dest_port))
        except Exception as e:
            print(f"[{self.nickname}] Erro ao processar: {e}")

    # Interface do usuário no terminal
    def user_interface(self):
        while True:
            print("\n1. Enviar mensagem")
            print("2. Enviar para TODOS")
            print("3. Ver fila")
            print("4. Sair")
            op = input("Escolha: ")

            if op == '1':
                dest = input("Destino: ")
                msg = input("Mensagem: ")
                self.queue_message(dest, msg)
            elif op == '2':
                msg = input("Mensagem para todos: ")
                self.queue_message("TODOS", msg)
            elif op == '3':
                print(f"Fila: {self.message_queue}")
            elif op == '4':
                print("Encerrando...")
                break

    # Enfileira uma nova mensagem para envio
    def queue_message(self, dest, msg):
        with self.lock:
            if len(self.message_queue) >= 10:
                print("Fila cheia. Mensagem descartada.")
                return
            crc_val = crc32(msg.encode())
            full_msg = f"7777:naoexiste;{self.nickname};{dest};{crc_val};{msg}"
            self.message_queue.append(full_msg)
            print(f"Mensagem para {dest} enfileirada.")

    # Monitora token e trata retransmissões
    def token_monitor(self):
        while True:
            if self.has_token and self.retry_queue:
                for key, msg in list(self.retry_queue.items()):
                    print(f"[{self.nickname}] Retransmitindo para {key[0]}.")
                    self.message_queue.insert(0, msg)
                    del self.retry_queue[key]
            time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python NodeRing.py <arquivo_config>")
        sys.exit(1)

    RingNode(sys.argv[1])
    while True:
        time.sleep(1)  # Mantém processo vivo
