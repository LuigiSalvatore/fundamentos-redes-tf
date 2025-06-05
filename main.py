import socket
import threading
from time import time, sleep, strftime
from zlib import crc32
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import queue

class Node:
    def __init__(self, filename, listen_port=11000, token_timeout=10, token_timemin=-1):
        # Original file1 initialization (unchanged)
        with open(filename) as file:
            lines = [line.strip() for line in file.readlines() if line.strip()] # Read non-empty lines
            if len(lines) < 4:
                raise ValueError("Configuration file must contain at least 4 lines.")
            
            # Get node configuration
            dest, self.name, self.token_lifetime = [x.strip() for x in lines[:3]]
            # Read last line for token status
            token_status = lines[3].lower()
            if token_status not in ['true', 'false']:
                raise ValueError("Token status must be 'true' or 'false'.")
            self.has_token = token_status == 'true'
        
        # Parameters
        self.destroy_next_token = False
        self.awaiting_ack = False
        self.ack_received = False
        self.nack_count = 0
        self.waiting_ack_event = None


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
        
        # Token management
        self.is_token_manager = self.has_token
        self.token_time = time() if self.has_token else None
        self.last_token_time = time() if self.has_token else None
        self.token_lifetime = int(self.token_lifetime)
        self.token_timeout = token_timeout # Token timeout in seconds

        self.destroy_next_token = False
        self.ack_received = False
        self.nack_count = 0
        self.waiting_ack_event = threading.Event()
        self.token_timemin = token_timemin # Token must take at least this long to be passed
        
        # Error injection from file2 (new optional feature)
        self.corrupt_next_message = False
        self.corrupt_field = ""
        
        # GUI additions from file2 (new)
        self.log_queue = queue.Queue()
        self.gui_thread = threading.Thread(target=self.start_gui, daemon=True)
        self.gui_thread.start()
        
        # Start threads
        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.token_handler, daemon=True).start() 
        
        self.log(f"Node {self.name} initialized with destination {self.dest_ip}:{self.dest_port} and token lifetime {self.token_lifetime} seconds.")
        if self.has_token:
            self.log(f"Node {self.name} is the token manager. Sending token now.")
            self.pass_token()
            
    # GUI methods from file2 (new additions)
    def log(self, message, tag="info"):
        """Log message to GUI (from file2)"""
        timestamp = strftime("[%H:%M:%S]")
        self.log_queue.put((f"{timestamp} {self.name}: {message}", tag))
    
    def start_gui(self):
        """Initialize GUI components (from file2)"""
        root = tk.Tk()
        root.title(f"Node {self.name} - Logs")
        text_area = ScrolledText(root, height=20, width=80)
        text_area.pack()

        # Configure tags for different message types (from file2)
        text_area.tag_config("token", foreground="blue")
        text_area.tag_config("info", foreground="black")
        text_area.tag_config("debug", foreground="gray")
        text_area.tag_config("error", foreground="red")
        text_area.tag_config("warn", foreground="orange")
        text_area.tag_config("ack", foreground="green")
        text_area.tag_config("nack", foreground="darkred")

        def update_logs():
            """Update GUI with new log messages (from file2)"""
            while not self.log_queue.empty():
                msg, tag = self.log_queue.get_nowait()
                text_area.insert(tk.END, msg + "\n", tag)
                text_area.see(tk.END)
            root.after(100, update_logs)

        # Create menu for user actions (from file2)
        menubar = tk.Menu(root)
        actionmenu = tk.Menu(menubar, tearoff=0)
        actionmenu.add_command(label="Send Message", command=self.send_message_dialog)
        actionmenu.add_command(label="Send Messages", command=self.multi_message_dialog)
        actionmenu.add_command(label="Broadcast", command=self.broadcast_dialog)
        actionmenu.add_command(label="Inject Error", command=self.inject_error_dialog)
        actionmenu.add_command(label="Check Status", command=self.status_dialog)
        actionmenu.add_command(label="Destroy Next Token", command=self.set_destroy_token)
        actionmenu.add_command(label="Message Queue", command=self.show_queue_dialog) 
        actionmenu.add_command(label="Generate New Token", command=self.gerar_token_dialog)
        actionmenu.add_separator()
        actionmenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="Actions", menu=actionmenu)
        root.config(menu=menubar)

        update_logs()
        root.mainloop()

    def set_destroy_token(self):
        self.destroy_next_token = True
        self.log("Next Token will be destroyed.", "warn")

    def show_queue_dialog(self):
        """Show the current message queue in a dialog"""
        dialog = tk.Toplevel()
        dialog.title("Fila de Mensagens")

        with self.msg_lock:
            if not self.msgs:
                tk.Label(dialog, text="A fila de mensagens está vazia.").pack(padx=10, pady=10)
            else:
                for idx, msg in enumerate(self.msgs, 1):
                    tk.Label(dialog, text=f"{idx}: {msg}").pack(anchor='w', padx=10)

        tk.Button(dialog, text="Fechar", command=dialog.destroy).pack(pady=10)   
    def status_dialog(self):
        """Dialog to show node status (from file2)"""
        dialog = tk.Toplevel()
        dialog.title("Node Status")
        
        tk.Label(dialog, text=f"Node Name: {self.name}").pack()
        tk.Label(dialog, text=f"Destination: {self.dest_ip}:{self.dest_port}").pack()
        tk.Label(dialog, text=f"Token Manager: {'Yes' if self.is_token_manager else 'No'}").pack()
        tk.Label(dialog, text=f"Token Lifetime: {self.token_lifetime} seconds").pack()
        tk.Label(dialog, text=f"Has Token: {'Yes' if self.has_token else 'No'}").pack()
        
        tk.Button(dialog, text="Close", command=dialog.destroy).pack()
        
    def send_message_dialog(self):
        """Dialog for sending messages (from file2)"""
        dialog = tk.Toplevel()
        dialog.title("Send Message")
        
        tk.Label(dialog, text="Destination:").grid(row=0, column=0)
        dest_entry = tk.Entry(dialog)
        dest_entry.grid(row=0, column=1)
        
        tk.Label(dialog, text="Message:").grid(row=1, column=0)
        msg_entry = tk.Entry(dialog)
        msg_entry.grid(row=1, column=1)
        
        def send():
            dest = dest_entry.get()
            msg = msg_entry.get()
            if dest and msg:
                self.queue_msg(dest, msg)
                dialog.destroy()
        
        send_button = tk.Button(dialog, text="Send", command=send)
        send_button.grid(row=2, columnspan=2)
        dialog.bind("<Return>", lambda event: send())

    
    def broadcast_dialog(self):
        """Dialog for broadcast messages (from file2)"""
        dialog = tk.Toplevel()
        dialog.title("Broadcast Message")
        
        tk.Label(dialog, text="Message for all nodes:").grid(row=0, column=0)
        msg_entry = tk.Entry(dialog)
        msg_entry.grid(row=0, column=1)
        
        def send():
            msg = msg_entry.get()
            if msg:
                self.queue_msg("TODOS", msg)
                dialog.destroy()
        
        send_button = tk.Button(dialog, text="Broadcast", command=send)
        send_button.grid(row=1, columnspan=2)
        dialog.bind("<Return>", lambda event: send())
    
    def inject_error_dialog(self):
        """Dialog for error injection (from file2)"""
        dialog = tk.Toplevel()
        dialog.title("Inject Error")
        
        tk.Label(dialog, text="Select field to corrupt:").pack()
        
        options = [
            ("Control Field", "1"),
            ("Origin Field", "2"),
            ("Destination Field", "3"),
            ("CRC Field", "4"),
            ("Message Content", "5")
        ]
        
        selected = tk.StringVar(value="1")
        
        for text, value in options:
            tk.Radiobutton(dialog, text=text, variable=selected, value=value).pack(anchor=tk.W)
        
        def inject():
            self.inject_error(selected.get())
            dialog.destroy()
        
        tk.Button(dialog, text="Inject Error", command=inject).pack()

    # Original file1 methods (unchanged except for print->log conversion)
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
                self.log(f"Error receiving message: {e}", "error")
    
    def handle_message(self, raw_msg):
        try:
            # Split the raw message into components
            msg_type, data = raw_msg.split(':', 1)
            control, origin, dest, crc, msg_content = data.split(';', 4)
            
            # Normal message handling
            if msg_type == "7777":
                # Base case: Message is for this node
                if dest == self.name or dest == "TODOS": # Added "TODOS" from file2
                    self.process_message(control, origin, crc, msg_content)
            
                # Loopback case: Message is from this node
                elif origin == self.name:
                    # NACK handling
                    if control == "NACK":
                        if self.awaiting_ack:
                            self.nack_count += 1
                        # Check if we have already attempted to resend this message, if not, resend it
                        if not hasattr(self, "retry_attempted"):
                            self.log("Received NACK - resending message at earliest opportunity.", "nack")
                            self.retry_attempted = True
                            original_msg = f"7777:naoexiste;{origin};{dest};{crc};{msg_content}"
                            with self.msg_lock:
                                self.msgs.insert(0, original_msg)  # Resend at the front of the queue
                        else:
                            self.log(f"We already resent this message, ignoring NACK from {dest}.", "warn")
                    # ACK and naoexiste handling
                    else:
                        if control == "ACK":
                            if self.awaiting_ack:
                                self.ack_received = True
                            self.log(f"Received ACK for our message from {dest}.", "ack")
                        elif control == "naoexiste":
                            self.log(f"Received naoexiste from {dest}, maybe there's no path to it?", "warn")
                        if hasattr(self, "retry_attempted"):
                            del self.retry_attempted # Clear retry flag
                
                # Forwarding case: Message is not for this node and not from this node
                else:
                    self.log(f"Forwarding message from {origin} to {dest}.", "debug")
                    self.pass_message(raw_msg)
        except ValueError as e:
            self.log(f"Error processing message: {e} - Raw message: {raw_msg}", "error")
            
    def process_message(self, control, origin, crc, msg_content):
        self.log(f"Processing message from {origin}: {msg_content}", "debug")
        # check crc
        if crc32(msg_content.encode('utf-8')) != int(crc):
            self.log(f"CRC mismatch for message from {origin}. Sending NACK.", "nack")
            control = "NACK"
        else:
            self.log(f"CRC match for message from {origin}. Sending ACK.", "ack")
            control = "ACK"
        self.send(f"7777:{control};{origin};{self.name};{crc};{msg_content}")
    
    
    def handle_token(self):
        curr_time = time()

        if self.destroy_next_token:
            self.log("Token destroyed as requested.", "warn")
            self.destroy_next_token = False
            return

        if self.is_token_manager:
            time_dif = curr_time - self.token_time if self.token_time else float('inf')
            if time_dif < self.token_timemin:
                self.log(f"Token arrived too soon ({time_dif:.2f}s), ignoring.", "token")
                return

        with self.msg_lock:
            self.has_token = True
            self.token_time = curr_time
            self.log("RECEIVED TOKEN", "token")

            if self.msgs:
                msg = self.msgs.pop(0)
                self.waiting_ack_event.clear()
                self.ack_received = False
                self.nack_count = 0

                if self.corrupt_next_message:
                    msg = self.apply_corruption(msg)
                    self.log(f"Message corrupted in field {self.corrupt_field}", "warn")
                    self.corrupt_next_message = False

                self.pass_message(msg)
                self.log(f"Sent message: {msg}", "debug")

        # Wait outside the lock
        start_wait = time()
        while time() - start_wait < 3:
            if self.ack_received or self.nack_count >= 2:
                break
            sleep(0.1)

        self.log("Passing token to next node", "token")
        self.pass_token()


    def gerar_token_dialog(self):
        dialog = tk.Toplevel()
        dialog.title("Gerar Novo Token")
        msg = "Deseja realmente gerar um novo token?\n(Só é permitido se você é o token manager.)"
        tk.Label(dialog, text=msg).pack(padx=10, pady=10)

        def gerar():
            if self.is_token_manager:
                self.log("Gerando novo token manualmente.", "token")
                self.pass_token()
            else:
                self.log("Não é possível gerar novo token: este nó não é token manager.", "error")
            dialog.destroy()

        tk.Button(dialog, text="Gerar Token", command=gerar).pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(dialog, text="Cancelar", command=dialog.destroy).pack(side=tk.RIGHT, padx=10, pady=10)
    
    def apply_corruption(self, msg):
        """Apply corruption to message (from file2)"""
        _, data = msg.split(':', 1)
        control, origin, dest, crc, msg_content = data.split(';', 4)
        if self.corrupt_field == "1":
            control = "))(#@JKmm!D)"
        elif self.corrupt_field == "2":
            origin = "i#@(jjN!klalAA)"
        elif self.corrupt_field == "3":
            dest = "iiWI(@(9jDN!))"
        elif self.corrupt_field == "4":
            crc = str(int(crc) * 2)
        elif self.corrupt_field == "5":
            msg_content = "88d1jds9a1--axjvm!"
        return f"7777:{control};{origin};{dest};{crc};{msg_content}"
            
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
            if self.is_token_manager:
                # Only manager handles token regeneration
                if not self.has_token and (self.token_time is None or (time() - self.token_time) > self.token_timeout):
                    self.log("Manager creating new token", "token")
                    self.has_token = True
                    self.token_time = time()
                    self.pass_token()
            sleep(1)
    
    
    def queue_msg(self, dest, msg):
        with self.msg_lock:
            if len(self.msgs) >= 10:
                self.log("Limite de 10 mensagens na fila atingido. Não é possível adicionar mais mensagens.", "warn")
                return
            crc = crc32(msg.encode('utf-8'))
            raw_msg = f"7777:naoexiste;{self.name};{dest};{crc};{msg}"
            self.msgs.append(raw_msg)
        self.log(f"Message queued for {dest}: {msg}", "debug")
        
    def inject_error(self, choice):
        """Inject error into next message (from file2)"""
        with self.msg_lock:
            if self.msgs:
                self.log("Injecting error into the first message in the queue.", "warn")
                self.corrupt_next_message = True
                self.corrupt_field = choice
            else:
                self.log("Can't inject error - message queue is empty. Try writing a message first.", "warn")
                
    def multi_message_dialog(self):
        """Dialog for queuing multiple messages at once (new feature)"""
        dialog = tk.Toplevel()
        dialog.title("Queue Multiple Messages")

        # Destination entry
        tk.Label(dialog, text="Destination:").grid(row=0, column=0, sticky='w')
        dest_entry = tk.Entry(dialog)
        dest_entry.grid(row=0, column=1, padx=5, pady=5)

        # Message list box with scrollbar
        tk.Label(dialog, text="Messages (one per line):").grid(row=1, column=0, sticky='w', columnspan=2)
        msg_frame = tk.Frame(dialog)
        msg_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        scrollbar = tk.Scrollbar(msg_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        msg_list = tk.Text(msg_frame, height=10, width=40, yscrollcommand=scrollbar.set)
        msg_list.pack(side=tk.LEFT, fill=tk.BOTH)
        scrollbar.config(command=msg_list.yview)

        # Button frame
        button_frame = tk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=5)

        def queue_messages():
            dest = dest_entry.get().strip()
            messages = msg_list.get("1.0", tk.END).splitlines()

            if not dest:
                self.log("Error: Destination cannot be empty", "error")
                return

            # Only non-empty messages
            non_empty_msgs = [msg for msg in messages if msg.strip()]
            with self.msg_lock:
                available_slots = 10 - len(self.msgs)
                if available_slots <= 0:
                    self.log("Limite de 10 mensagens na fila atingido. Não é possível adicionar mais mensagens.", "warn")
                    dialog.destroy()
                    return
                msgs_to_add = non_empty_msgs[:available_slots]
                for msg in msgs_to_add:
                    crc = crc32(msg.encode('utf-8'))
                    raw_msg = f"7777:naoexiste;{self.name};{dest};{crc};{msg}"
                    self.msgs.append(raw_msg)
            self.log(f"Queued {len(msgs_to_add)} messages for {dest}", "info")
            if len(non_empty_msgs) > available_slots:
                self.log(f"Apenas {available_slots} mensagens foram adicionadas devido ao limite de 10 mensagens na fila.", "warn")
            dialog.destroy()

        tk.Button(button_frame, text="Queue Messages", command=queue_messages).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python node.py <config_file> <listen_port>")
        sys.exit(1)
    
    node = Node(sys.argv[1], int(sys.argv[2]))
    # The GUI runs in its own thread, so we need to keep the main thread alive
    while True:
        sleep(1)