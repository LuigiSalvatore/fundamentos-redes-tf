import socket
import threading
import random
from time import time, sleep
from zlib import crc32
import sys

class Node:
    def __init__(self, filename):
        with open(filename) as file:
            dest, self.name, token_time, token_flag = [line.strip() for line in file.readlines()[:4]]

        self.dest_ip, self.dest_port = dest.split(':')
        self.dest_port = int(self.dest_port)
        self.has_token = token_flag.lower() == 'true'
        self.token_lifetime = int(token_time)
        self.listen_port = 11000 if self.has_token else int(self.dest_port) + 1

        self.msgs = []
        self.msg_lock = threading.Lock()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', self.listen_port))

        self.is_token_manager = self.has_token
        self.token_time = time() if self.has_token else None
        self.last_token_time = time() if self.has_token else None
        self.token_timeout = 10
        self.token_timemin = 1

        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.token_handler, daemon=True).start()
        threading.Thread(target=self.cli_loop, daemon=True).start()

        print(f"Node {self.name} initialized on port {self.listen_port}, sending to {self.dest_ip}:{self.dest_port}")
        if self.has_token:
            print(f"{self.name} is the token manager. Sending token.")
            sleep(1)
            self.pass_token()

    def listen_loop(self):
        while True:
            try:
                data, _ = self.socket.recvfrom(2048)
                raw_msg = data.decode('utf-8')
                if raw_msg == "9000":
                    self.handle_token()
                else:
                    self.handle_message(raw_msg)
            except Exception as e:
                print(f"Erro na recepção: {e}")

    def handle_message(self, raw_msg):
        try:
            msg_type, data = raw_msg.split(':', 1)
            control, origin, dest, crc, msg_content = data.split(';', 4)

            if msg_type == "7777":
                if dest == self.name or dest == "TODOS":
                    self.process_message(control, origin, crc, msg_content)
                elif origin == self.name:
                    if control == "NACK":
                        if not hasattr(self, "retry_attempted"):
                            print("NACK recebido. Mensagem será reenviada.")
                            self.retry_attempted = True
                            original_msg = f"7777:naoexiste;{origin};{dest};{crc};{msg_content}"
                            with self.msg_lock:
                                self.msgs.insert(0, original_msg)
                        else:
                            print("NACK ignorado, mensagem já reenviada.")
                    else:
                        print(f"{control} recebido de {dest}.")
                        if hasattr(self, "retry_attempted"):
                            del self.retry_attempted
                else:
                    self.pass_message(raw_msg)
        except ValueError as e:
            print(f"Erro ao processar mensagem: {e} - {raw_msg}")

    def process_message(self, control, origin, crc, msg_content):
        print(f"Mensagem de {origin}: {msg_content}")
        if crc32(msg_content.encode('utf-8')) != int(crc):
            print("Erro de CRC, enviando NACK")
            control = "NACK"
        else:
            print("Mensagem OK, enviando ACK")
            control = "ACK"
        self.send(f"7777:{control};{origin};{self.name};{crc};{msg_content}")

    def handle_token(self):
        curr_time = time()
        if self.is_token_manager:
            diff = curr_time - self.token_time
            if diff < self.token_timemin:
                print("Token chegou cedo demais, será descartado.")
                return
            elif diff > self.token_timeout:
                print("Token perdido, será regenerado.")
                self.pass_token()
                return

        self.last_token_time = curr_time
        self.has_token = True
        self.token_time = curr_time

        print("--- TOKEN RECEBIDO ---")

        with self.msg_lock:
            if self.msgs:
                raw_msg = self.msgs.pop(0)
                self.pass_message(raw_msg)
            else:
                self.pass_token()

    def pass_message(self, raw_msg):
        if random.random() < 0.1:
            print("Erro injetado na mensagem")
            raw_msg = self.corrupt_message(raw_msg)
        self.socket.sendto(raw_msg.encode('utf-8'), (self.dest_ip, self.dest_port))

    def corrupt_message(self, msg):
        return msg[::-1]  # Simples inversão de string como "corrupção"

    def pass_token(self):
        self.socket.sendto(b"9000", (self.dest_ip, self.dest_port))
        self.has_token = False

    def send(self, msg):
        self.socket.sendto(msg.encode('utf-8'), (self.dest_ip, self.dest_port))
        self.pass_token()

    def token_handler(self):
        while True:
            if self.has_token and (time() - self.token_time > self.token_lifetime):
                print("Token expirado, passando adiante.")
                self.pass_token()
            sleep(1)

    def queue_msg(self, dest, msg, err):
        with self.msg_lock:
            if len(self.msgs) >= 10:
                print("Fila cheia. Mensagem descartada.")
                return
            crc = crc32(msg.encode('utf-8'))
            raw_msg = f"7777:naoexiste;{self.name};{dest};{crc};{msg};{err}"	
            self.msgs.append(raw_msg)
        print(f"Mensagem para {dest} enfileirada.")

    def cli_loop(self):
        while True:
            print("\nMENU:")
            print("1. Enviar mensagem (unicast)")
            print("2. Enviar mensagem para TODOS (broadcast)")
            print("3. Ver fila de mensagens")
            print("4. Sair")
            op = input("Opção: ")
            if op == '1':
                dest = input("Destino: ")
                msg = input("Mensagem: ")
                while True:
                    try:
                        err = int(input("Error %: "))
                        if 0 <= err <= 100:
                            break
                        else:
                            print("Digite um valor inteiro entre 0 e 100.")
                    except ValueError:
                        print("Digite um valor inteiro válido.")
                self.queue_msg(dest, msg, err)
            elif op == '2':
                msg = input("Mensagem: ")
                while True:
                    try:
                        err = int(input("Error %: "))
                        if 0 <= err <= 100:
                            break
                        else:
                            print("Digite um valor inteiro entre 0 e 100.")
                    except ValueError:
                        print("Digite um valor inteiro válido.")
                self.queue_msg("TODOS", msg, err)
            elif op == '3':
                with self.msg_lock:
                    for i, m in enumerate(self.msgs):
                        print(f"{i+1}: {m}")
            elif op == '4':
                print("Encerrando...")
                break
            else:
                print("Opção inválida.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python tf-redes.py <arquivo_config>")
        sys.exit(1)

    Node(sys.argv[1])

    while True:
        sleep(1)  # Mantém a thread principal viva
