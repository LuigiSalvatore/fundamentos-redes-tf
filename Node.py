import socket
import threading
from time import time, sleep
from zlib import crc32

class Node:
    def __init__(self, filename, listen_port=11000, token_timeout=10, token_timemin=5):
        with open(filename) as file:
            # Read configuration from file up to the first three lines
            dest, self.name, self.token_lifetime = [x.strip() for x in file.readlines()[:3]]
            # Read last line for token status
            self.has_token = file.readline().strip().lower() == 'true'
            # Listen port for incoming messages
            self.listen_port = listen_port
        
        # Split destination into IP and port
        self.dest_ip, self.dest_port = dest.split(':')
        self.dest_port = int(self.dest_port)
        
        # Message handling
        self.msgs = []  # Messages to send
        self.msg_lock = threading.Lock()  # Lock for message handling
        
        # Socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', listen_port))
        
        # Start threads
        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.token_handler, daemon=True).start() 
        
        # Token management
        self.is_token_manager = self.has_token
        self.token_time = time()  if self.has_token else None
        self.last_token_time = time() if self.has_token else None
        self.token_lifetime = int(self.token_lifetime)
        self.token_timeout = token_timeout # Token timeout in seconds
        self.token_timemin = token_timemin # Token must take at least this long to be passed
        
        print(f"Node {self.name} initialized with destination {self.dest_ip}:{self.dest_port} and token lifetime {self.token_lifetime} seconds.")
        if self.has_token:
            print(f"Node {self.name} is the token manager. Sending token now.")
            self.send_token()
            
    def listen_loop(self):
        # Reminder:
        # Token: "9000" (nothing else)
        # Regular: "7777:control;origin;dest;crc;message_content" ie "7777:naoexiste;Juca;Juquinha;1388532993;Hello World"
        while True:
            try:
                # Split incoming messages into components
                data, _ = self.socket.recvfrom(self.listen_port)
                raw_msg = data.decode('utf-8')
                
                # If the message is a token, handle it separately, else handle it as a regular message
                if raw_msg == "9000":
                    self.handle_token()
                else:
                    self.handle_message(raw_msg)
            except Exception as e:
                print(f"Error receiving message: {e}")
    
    def handle_message(self, raw_msg):
        try:
            # Split the raw message into components
            msg_type, data = raw_msg.split(':', 1)
            control, origin, dest, crc, msg_content = data.split(';', 4)
            
            # Normal message handling
            if msg_type == "7777":
                # Base case: Message is for this node
                if dest == self.name: # Message for this node
                    self.process_message(control, origin, crc, msg_content)
            
                # Loopback case: Message is from this node
                elif origin == self.name:
                    # NACK handling
                    if control == "NACK":
                        # Check if we have already attempted to resend this message, if not, resend it
                        if not hasattr(self, "retry_attempted"):
                            print("Received NACK - resending message at earliest opportunity.")
                            self.retry_attempted = True
                            original_msg = f"7777:naoexiste;{origin};{dest};{crc};{msg_content}"
                            with self.msg_lock:
                                self.msgs.insert(0, original_msg)  # Resend at the front of the queue
                        else:
                            print(f"We already resent this message, ignoring NACK from {dest}.")
                    # ACK and naoexiste handling
                    else:
                        if control == "ACK":
                            print(f"Received ACK for our message from {dest}.")
                        elif control == "naoexiste":
                            print(f"Received naoexiste from {dest}, maybe there's no path to it?")
                        if hasattr(self, "retry_attempted"):
                            del self.retry_attempted # Clear retry flag
                
                # Forwarding case: Message is not for this node and not from this node
                else:
                    print(f"Forwarding message from {origin} to {dest}.")
                    self.pass_message(raw_msg)
        except ValueError as e:
            print(f"Error processing message: {e} - Raw message: {raw_msg}")
            
    def process_message(self, control, origin, crc, msg_content):
        print(f"Processing message from {origin}: {msg_content}")
        # check crc
        if crc32(msg_content.encode('utf-8')) != int(crc):
            print(f"CRC mismatch for message from {origin}. Sending NACK.")
            control = "NACK"
        else:
            print(f"CRC match for message from {origin}. Sending ACK.")
            control = "ACK"
        self.send(f"7777:{control};{origin};{self.name};{crc};{msg_content}")
    
    def handle_token(self):
        curr_time = time()
        if self.is_token_manager:
            time_dif = curr_time - self.token_time
            
            # Token Gonzales: token arrived too soon, delete it
            if time_dif < self.token_timemin:
                print(f"Token arrived too soon ({time_dif:.2f}s), deleting it.")
                return
            
            # Token Turtle: token expired, make a new one
            elif time_dif > self.token_timeout:
                print(f"Token expired after {time_dif:.2f}s, creating a new token.")
        
        self.last_token_time = curr_time # Update token time
        
        # Normal token handling
        with self.msg_lock:
            self.has_token = True
            self.token_time = curr_time
            print("  ####################  ")
            print("########################")
            print("#### RECEIVED TOKEN ####")
            print("########################")
            print("  ####################  ")
            
            if self.msgs:
                print("Messages in queue, sending first message.")
                raw_msg = self.msgs.pop(0)
                self.pass_message(raw_msg)
            else:
                print("No messages in queue, passing token.")
                self.pass_token()
            
            
    def pass_message(self, raw_msg):
        self.socket.sendto(raw_msg.encode('utf-8'), (self.dest_ip, self.dest_port))
    
    def pass_token(self):
        self.socket.sendto(b"9000", (self.dest_ip, self.dest_port))
        self.has_token = False
        
    def send(self, msg):
        self.socket.sendto(msg.encode('utf-8'), (self.dest_ip, self.dest_port))
        self.pass_token()
    
    def token_handler(self):
        while True:
            if self.has_token and (time() - self.token_time > int(self.token_lifetime)):
                print("!!!!!! Token expired, passing token !!!!!!")
                self.pass_token()
            sleep(self.token_lifetime)  # Sleep for the token lifetime to check for expiration
    
    def queue_msg(self, dest, msg):
        crc = crc32(msg.encode('utf-8'))
        raw_msg = f"7777:naoexiste;{self.name};{dest};{crc};{msg}"
        
        with self.msg_lock:
            self.msgs.append(raw_msg)
            
        print(f"Message queued for {dest}: {msg}")
        
    def inject_error(self):
        with self.msg_lock:
            if self.msgs:
                print("Injecting error into the first message in the queue.")
                raw_msg = self.msgs[0]
                _, data = raw_msg.split(':', 1)
                control, origin, dest, crc, msg_content = data.split(';', 4)
                print("Choose corruption type:")
                print("1. Corrupt control field (ACK/NACK/naoexiste)")
                print("2. Corrupt origin field (sender's name)")
                print("3. Corrupt destination field (receiver's name)")
                print("4. Corrupt CRC field")
                print("5. Corrupt message content")
                choice = input("Enter your choice (1-5): ")
                if choice == '1':
                    control = "))(#@JKmm!D)"
                elif choice == '2':
                    origin = "i#@(jjN!klalAA)"
                elif choice == '3':
                    dest = "iiWI(@(9jDN!))"
                elif choice == '4':
                    crc = crc * 2
                elif choice == '5':
                    msg_content = "88d1jds9a1--axjvm!"
                else:
                    print("Invalid choice, no corruption applied.")
                    return
                corrupted_msg = f"7777:{control};{origin};{dest};{crc};{msg_content}"
                self.msgs[0] = corrupted_msg
            else:
                print("Can't inject error - message queue is empty. Try writing a message first.")
                
                
