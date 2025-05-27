import socket
import threading
from time import time
import base64
import os
import hashlib
import argparse
from zlib import crc32

class Node:
    def __init__(self, filename, listen_port=11000):
        with open(filename) as file:
            line = file.readline().strip()
            split = None
            for i in range(len(line)):
                if line[i] == ':':
                    split = i
                    break
            if split == None:
                raise Exception("Malformed file, aborting...")
            self.dest_ip = line[0:split-1]
            self.dest_port = int(line[split+1:-1])
            self.name = file.readline().strip()
            self.token_lifetime = int(file.readline().strip())
            self.token_held = 0
            self.token = True if file.readline().strip() == "true" else False
            self.msgs = {}
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', listen_port))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.lock = threading.Lock()
            self.has_token = False
            self.pass_msg = None # Mensagems a serem repassadas
            self.received_msg = None # Mensagems para a própria máquina
            self.returned_msg = None # Mensagems que voltaram para própria máquina

            if self.token_lifetime <= 0: 
                raise Exception("Token lifetime set to 0 or less, aborting...")
            
        print("Setup complete.")

    def write_message(self):
        if len(self.msgs) < 10:
            self.msgs.append(input())
        else:
            print("Message limit (10) reached, please wait until a message is sent.")
    
    async def send(self):
        # Se houver msg pra ser repassada, repassa
        if self.pass_msg is not None:
            self.socket.sendto(self.pass_msg.encode('utf-8'), (self.dest_ip, self.dest_port))
            self.pass_msg = None
        # Senao, se houver msgs pra enviar, e tiver o token, envia
        elif len(self.msgs) > 0 and self.has_token == True:
            self.socket.sendto(self.msgs[-1].encode('utf-8'), (self.dest_ip, self.dest_port))
            # Enquanto n receber a mensagem de volta, não pode enviar outras msgs
            while True:
                if self.received_msg is not None:
                    if self.received_msg[0] == "ACK":
                        print(f'Message received by {self.received_msg[2]} with an ACK!')
                        self.msgs.pop()
                        self.received_msg = None
                        self.send_token()
                        break
                    elif self.received_msg[0] == "NACK":
                        print(f'Message received by {self.received_msg[2]} with a NACK!')
                        self.received_msg = None
                        self.send_token()
                        break
                    elif self.received_msg[0] == "naoexiste":
                        print(f'Não existe um caminho para {self.received_msg[0]}.')
                        self.msgs.pop()
                        self.received_msg = None
                        self.send_token()
                        break
                    else:
                        raise Exception("Como? [mensagem com erro fatal]")
                    
    async def receive(self):
        while True:
            ret_msg = "7776:"
            if self.received_msg is not None:
                #calcula o erro
                err = crc32(self.received_msg[-1])
                if err != self.received_msg[3]:
                    ret_msg += "NACK" + self.received_msg[1:-1]
                else:
                    ret_msg += "ACK" + self.received_msg[1:-1]
                print(f'Received Message: {self.received_msg[-1]}')
                print(f'Origin: {self.received_msg[1]}')
                self.pass_msg = ret_msg
                self.received_msg = None

    async def message_looped(self):
        while True:
            if self.returned_msg is not None:
                err = crc32(self.returned_msg[-1])

    def send_token(self):
        self.socket.sendto("9000".encode('utf-8'), (self.dest_ip, self.dest_port))
    
    async def listen_loop(self):
        while True:
            data, addr = self.socket.recvfrom(self.listen_port)
            message = data.decode('utf-8')
            sender_ip, sender_port = addr
            self.handle_message(message)

    def handle_message(message, self):
        aux = message.split(':')
        data_type = aux[0]
        
        if data_type == "9000":
            if self.has_token and self.token:
                pass
                # INSERIR FUNÇÃO QUE HANDLE CONTROLE DE TOKEN
            else:
                self.has_token = True
                self.token_held = time()

        elif data_type == "7777":
            data = aux[1]
            data = data.split(';') # Isso deve split a mensagem em controle de erro, nome de origem, nome de destino, crc, e mensagem, nesta ordem

            # se uma msg que a maquina mandou voltou pra ela mesma, guarda
            if data[1] == self.name:
                self.returned_msg = data
            # caso contrario se nao for pra ela, manda adiante
            elif data[2] != self.name:
                self.pass_msg = message
                self.send()
            # senao é pra ela, entao guarda
            else:
                self.received_msg = data

    def token_timer(self):
        while (True):
            if self.has_token and time() - self.token_held >= self.token_lifetime:
                self.has_token = False
                self.send_token()
            else:
                time.sleep(1)
                
