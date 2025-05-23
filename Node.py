import socket
import threading
import time
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
            self.token = True if file.readline().strip() == "true" else False
            self.msgs = {}
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', listen_port))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.lock = threading.Lock()
            self.has_token = False
            self.pass_msg = None # Mensagems a serem repassadas
            self.received_msg = None # Mensagems para a própria máquina

            if self.token_lifetime <= 0: 
                raise Exception("Token lifetime set to 0 or less, aborting...")
            
        print("Setup complete.")

    def write_message(self):
        if len(self.msgs) < 10:
            self.msgs.append(input())
        else:
            print("Message limit (10) reached, please wait until a message is sent.")
    
    def send(self):
        # Se houver msg pra ser repassada, repassa
        if self.pass_msg is not None:
            self.socket.sendto(self.pass_msg.encode('utf-8'), (self.dest_ip, self.dest_port))
            self.pass_msg = None
        # Senao, se houver msgs pra enviar, e tiver o token, envia
        elif len(self.msgs) > 0 and self.has_token == True:
            self.socket.sendto(self.msgs[-1].encode('utf-8'), (self.dest_ip, self.dest_port))
    
    def listen_loop(self):
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

        elif data_type == "7777":
            data = aux[1]
            data = data.split(';') # Isso deve split a mensagem em controle de erro, nome de origem, nome de destino, crc, e mensagem, nesta ordem

            #checar erro
            err = crc32(data[4]) # usa o crc32 na mensagem

            if err == int(data[0]):
                if data[2] != self.name:
                    self.pass_msg = message
                    send()
                else:
                    self.received_msg = data
                    
