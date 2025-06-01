import socket
import threading
import time
import random
from zlib import crc32
import sys
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import queue

# Classe que representa um nó na rede em anel
class RingNode:
    def __init__(self, config_file, log_queue, override_token_hold_time=None):
        with open(config_file) as f:
            lines = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip() != '']
            self.dest_ip, self.dest_port = lines[0].split(":")
            self.dest_port = int(self.dest_port)
            self.nickname = lines[1]
            self.token_hold_time = int(lines[2])
            self.is_token_creator = lines[3].lower() == "true"

        if override_token_hold_time is not None:
            self.token_hold_time = override_token_hold_time
        else:
            self.token_hold_time = 1  # valor padrão

        self.listen_port = int(lines[4])
        self.has_token = self.is_token_creator
        self.token_start_time = time.time() if self.has_token else None
        self.token_timeout = 10
        self.token_min_interval = 1
        self.message_queue = []
        self.retry_queue = {}

        self.corrupt_next_message = False
        self.corrupt_field = ""

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.listen_port))

        self.lock = threading.Lock()
        self.log_queue = log_queue

        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.token_monitor, daemon=True).start()
        threading.Thread(target=self.user_interface, daemon=True).start()

        self.log(f"Pronto. Enviando para {self.dest_ip}:{self.dest_port}.", "info")

        if self.is_token_creator:
            time.sleep(1)
            self.send_token()

    def log(self, message, tag="info"):
        timestamp = time.strftime("[%H:%M:%S]")
        self.log_queue.put((f"{timestamp} {self.nickname}: {message}", tag))

    def listen_loop(self):
        while True:
            data, _ = self.sock.recvfrom(2048)
            message = data.decode('utf-8')
            if message == "9000":
                self.receive_token()
            elif message.startswith("7777:"):
                self.handle_data(message)

    def send_token(self):
        self.token_start_time = time.time()
        self.has_token = False
        self.sock.sendto(b"9000", (self.dest_ip, self.dest_port))
        self.log("Token enviado.", "token")

    def receive_token(self):
        now = time.time()

        if self.is_token_creator:
            elapsed = now - self.token_start_time
            if elapsed < self.token_min_interval:
                self.log("Token chegou cedo. Descartado.", "token")
                return
            elif elapsed > self.token_timeout:
                self.log("Token perdido. Gerando novo.", "token")
                self.send_token()
                return

        self.token_start_time = now
        self.has_token = True
        self.log("Recebeu o token.", "token")

        with self.lock:
            if self.message_queue:
                msg = self.message_queue.pop(0)
                self.send_message(msg)
            else:
                self.log(f"Aguardando {self.token_hold_time}s antes de repassar o token.", "token")
                time.sleep(self.token_hold_time)
                self.send_token()

    def send_message(self, msg):
        if self.corrupt_next_message:
            msg = self.apply_corruption(msg)
            self.log(f"Mensagem corrompida propositalmente no campo: {self.corrupt_field}.", "warn")
            self.corrupt_next_message = False

        self.sock.sendto(msg.encode('utf-8'), (self.dest_ip, self.dest_port))
        self.has_token = False

    def apply_corruption(self, msg):
        prefix, payload = msg.split(":", 1)
        status, origin, dest, crc_str, content = payload.split(";", 4)
        if self.corrupt_field == "status":
            status = "XXXX"
        elif self.corrupt_field == "origin":
            origin = "????"
        elif self.corrupt_field == "dest":
            dest = "****"
        elif self.corrupt_field == "crc":
            crc_str = "0000"
        elif self.corrupt_field == "content":
            content = content[::-1]
        return f"{prefix}:{status};{origin};{dest};{crc_str};{content}"

    def handle_data(self, raw):
        try:
            _, payload = raw.split(":", 1)
            status, origin, dest, crc_str, content = payload.split(";", 4)
            crc_recv = int(crc_str)

            if dest == self.nickname or dest == "TODOS":
                valid = crc32(content.encode()) == crc_recv
                ack_type = "ACK" if valid else "NACK"

                msg_recebida = f"Recebeu de {origin}: {content} | CRC {'OK' if valid else 'FALHOU'}"
                print(msg_recebida)
                tag = "broadcast" if dest == "TODOS" else "recv"
                self.log(msg_recebida, tag)

                resp = f"7777:{ack_type};{origin};{self.nickname};{crc_recv};{content}"
                self.sock.sendto(resp.encode('utf-8'), (self.dest_ip, self.dest_port))

            elif origin == self.nickname:
                if status == "ACK":
                    self.log(f"{dest} recebeu corretamente.", "ack")
                elif status == "NACK":
                    self.log(f"{dest} respondeu com erro. Vai retransmitir uma vez.", "nack")
                    self.retry_queue[(dest, content)] = raw.replace("NACK", "naoexiste")
                elif status == "naoexiste":
                    self.log(f"Destino {dest} não existe.", "warn")
                self.send_token()
            else:
                self.sock.sendto(raw.encode('utf-8'), (self.dest_ip, self.dest_port))
        except Exception as e:
            self.log(f"Erro ao processar: {e}", "error")

    def user_interface(self):
        while True:
            print("\n1. Enviar mensagem")
            print("2. Enviar para TODOS")
            print("3. Ver fila")
            print("4. Corromper próxima mensagem")
            print("5. Sair")
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
                self.corrupt_next_message = True
                campo = input("Campo a corromper (status, origin, dest, crc, content): ").strip().lower()
                if campo in ["status", "origin", "dest", "crc", "content"]:
                    self.corrupt_field = campo
                    print(f"A próxima mensagem será corrompida no campo: {campo}")
                else:
                    print("Campo inválido. Nenhuma corrupção aplicada.")
                    self.corrupt_next_message = False
            elif op == '5':
                print("Encerrando...")
                break

    def queue_message(self, dest, msg):
        with self.lock:
            if len(self.message_queue) >= 10:
                print("Fila cheia. Mensagem descartada.")
                return
            crc_val = crc32(msg.encode())
            full_msg = f"7777:naoexiste;{self.nickname};{dest};{crc_val};{msg}"
            self.message_queue.append(full_msg)
            print(f"Mensagem para {dest} enfileirada.")

    def token_monitor(self):
        while True:
            if self.has_token and self.retry_queue:
                for key, msg in list(self.retry_queue.items()):
                    self.log(f"Retransmitindo para {key[0]}", "nack")
                    self.message_queue.insert(0, msg)
                    del self.retry_queue[key]
            time.sleep(1)

# GUI principal na thread principal
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python NodeRing.py <arquivo_config> [tempo_token]")
        sys.exit(1)

    config_file = sys.argv[1]
    token_override = int(sys.argv[2]) if len(sys.argv) > 2 else None

    log_queue = queue.Queue()

    def gui_loop():
        root = tk.Tk()
        root.title("Logs")
        text_area = ScrolledText(root, height=20, width=80)
        text_area.pack()

        text_area.tag_config("token", foreground="blue")
        text_area.tag_config("recv", foreground="black")
        text_area.tag_config("broadcast", foreground="purple")
        text_area.tag_config("ack", foreground="green")
        text_area.tag_config("nack", foreground="red")
        text_area.tag_config("warn", foreground="orange")
        text_area.tag_config("error", foreground="darkred")

        def update_logs():
            while not log_queue.empty():
                msg, tag = log_queue.get_nowait()
                text_area.insert(tk.END, msg + "\n", tag)
                text_area.see(tk.END)
            root.after(100, update_logs)

        update_logs()
        root.mainloop()

    threading.Thread(target=RingNode, args=(config_file, log_queue, token_override), daemon=True).start()
    gui_loop()
