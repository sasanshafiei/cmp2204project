import tkinter as tk
import os
import base64
import socket
import json
import time
import pyDes
from threading import Thread, Event
import threading
from json.decoder import JSONDecodeError
import random
import queue
import datetime
import LocalIp

username_queue = queue.Queue()
stop_event = Event()
threads = []


class P2PChatApplicationClient:
    def __init__(self, username, app):
        self.LOCAL_IP_ADDRESS = LocalIp.getLocalIp()  # get local ip address by connecting Google DNS server
        self.SERVER_PORT = 6000  # port used to connect peers
        self.filename = "chat_log.json"  # file where recent messages kept
        self.input_timeout = False  # bool value to determine whether a peer is offline or not
        self.input_timeout_duration = 5
        self.users_dict = {}  # dictionary of the users as map
        self.username = username
        self.app = app

        if not os.path.exists(self.filename):  # if the file does not exist, create with permission =222
            with open(self.filename, 'w') as file:
                pass

    def service_announcer(self):
        announced = False  # UDP broadcasting
        try:
            while not stop_event.is_set():  # while stop_event is not set
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                # create the socket for broadcasting
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # 1 = true so it means broadcast is true
                broadcast_address = self.get_broadcast_ip(self.LOCAL_IP_ADDRESS)
                # use subnet mask and calculate broadcst ip
                announcement = json.dumps({"username": self.username, "IP_ADDRESS": self.LOCAL_IP_ADDRESS})
                # send json message to broadcasting address so it is gona be sent everyone in same subnet (not LAN)
                client_socket.sendto(announcement.encode(), (broadcast_address, self.SERVER_PORT))
                # using brodcast adres and port, do broadcasting to everyone
                if not announced:
                    self.app.display_event(f"{announcement} has been announced! \n")
                    announced = True

                client_socket.close()
                # dont forget to close the socket you created, so port is gone be free
                time.sleep(8)  # Announce every 8 seconds

        except KeyboardInterrupt:
            self.app.display_event("Client shutdown requested. Exiting...")
            client_socket.close()  # /////even if there is a keyboard interruption, port is gona be able to reused
        except Exception as e:
            self.app.display_event(f"An error occurred: {e}")
            client_socket.close()  # /////

    def peer_discovery(self):
        self.app.display_event("Listening for broadcast messages...\n")
        try:
            serverPort = 6000
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # simple UDP socket
            client_socket.bind((self.LOCAL_IP_ADDRESS,
                                serverPort))  # socket is binded to a spesific port so it is gona listen this port
            self.app.display_event("The server is ready to receive\n")

            while not stop_event.is_set():
                try:
                    data, addr = client_socket.recvfrom(2048)
                    # recvfrom receives data from UDP socket (2048 is maxbuffer size(bytes))
                    # recvfrom returns (data,addr) pair where data is data and addr is a pair (ipv4,port) of sender
                    if addr[
                        0] == LocalIp.getLocalIp():  # /////if it is coming from our device (echo), we'll not display it
                        continue

                    try:
                        message = json.loads(data.decode())  # data.decode() converts bytes to a string
                        # json.loads() parses string to a python dictionary
                        if "username" in message:
                            username = message.get("username")
                            sender_ip = addr[0]
                            timestamp = time.time()

                            # Read existing data
                            existing_data = []
                            try:
                                with open(self.filename, 'r') as file:
                                    for line in file:
                                        if line.strip():
                                            try:
                                                existing_data.append(json.loads(line))
                                            except json.JSONDecodeError:
                                                continue
                            except FileNotFoundError:
                                pass

                            # Update or add user entry
                            updated = False
                            new_data = []
                            for entry in existing_data:
                                if isinstance(entry, dict):
                                    for key, value in entry.items():
                                        if isinstance(value, dict) and value.get("sender_ip") == sender_ip:
                                            # Update existing entry
                                            entry[key]["timestamp"] = timestamp
                                            updated = True
                                new_data.append(entry)

                            if not updated:
                                # Add new entry
                                new_data.append({username: {"sender_ip": sender_ip, "timestamp": timestamp}})

                            # Write back to file
                            with open(self.filename, 'w') as file:
                                for entry in new_data:
                                    json.dump(entry, file)
                                    file.write('\n')

                            self.users_dict[sender_ip] = username
                            self.app.display_event(f"\nUpdated user: {username}")

                    except JSONDecodeError as e:
                        self.app.display_event(f"Error decoding JSON: {e}")

                except Exception as e:
                    self.app.display_event(f"Error in peer discovery: {e}")

        finally:
            client_socket.close()

    def chat_initiator(self, mode, target_username, message):
        if not stop_event.is_set():
            if mode.lower() == "secured_chat":
                self.initiate_chat("yes", target_username, message)
            elif mode.lower() == "unsecured_chat":
                self.initiate_chat("no", target_username, message)
            elif mode.lower() == "history":
                self.show_users()
            else:
                self.app.display_event("Invalid option.")

    def initiate_chat(self, secured, target_username, message_1):
        try:
            with open('chat_log.json', 'r') as file:
                chat_log = file.read()

            target_info = None
            for line in chat_log.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if target_username in data:
                            target_info = data[target_username]
                            break
                    except json.JSONDecodeError:
                        continue

            if not target_info:
                self.app.display_event(f"User {target_username} not found")
                return

            target_ip = target_info.get('sender_ip')
            if not target_ip:
                self.app.display_event(f"No IP address for {target_username}")
                return

            if secured == "yes":
                self.initiate_secure_chat(target_ip, target_username, message_1)
            else:
                self.initiate_unsecure_chat(target_ip, target_username, message_1)

        except Exception as e:
            self.app.display_event(f"Error initiating chat: {e}")

    def initiate_secure_chat(self, target_ip, target_username, message):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, 6001))

            # Diffie-Hellman key exchange
            p = 23
            g = 5
            a = random.randint(1, 9999999)
            A = pow(g, a, p)

            # Send our public key
            client_socket.sendall(json.dumps({'key': A}).encode())

            # Receive their public key
            data = client_socket.recv(2048)
            if not data:
                raise Exception("No response from peer")

            response = json.loads(data.decode())
            B = response['key']

            # Calculate shared secret
            S = pow(int(B), a, p)

            # Encrypt and send message
            encrypted_message = self.encrypt_message(message, str(S))
            client_socket.sendall(json.dumps({'encrypted_message': encrypted_message}).encode())

            self.app.display_tx(f"Sent encrypted message to {target_username}")

        except Exception as e:
            self.app.display_event(f"Secure chat error: {e}")
        finally:
            client_socket.close()

    def initiate_unsecure_chat(self, target_ip, target_username, message):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, 6001))
            client_socket.sendall(json.dumps({'unencrypted_message': message}).encode())
            self.app.display_tx(f"Sent unencrypted message to {target_username}")
        except Exception as e:
            self.app.display_event(f"Unsecure chat error: {e}")
        finally:
            client_socket.close()

    def encrypt_message(self, message, key):
        des = pyDes.triple_des(key.ljust(24))
        encoded_message = message.encode()
        encrypted_message = des.encrypt(encoded_message, padmode=2)
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
        return encrypted_message_base64

    def decrypt_message(self, encrypted_message, key):
        try:
            decrypted_message_base64 = base64.b64decode(encrypted_message)
            des = pyDes.triple_des(key.ljust(24))
            decrypted_message = des.decrypt(decrypted_message_base64, padmode=2)
            return decrypted_message.decode()
        except Exception as e:
            self.app.display_event(f"Error decrypting message: {e}")
            return None

    def save_message(self, message, filename):
        fifteen_minutes = 15 * 60
        current_time = time.time()
        with open(filename, 'r') as file:
            lines = file.readlines()
            filtered_lines = []
            for line in lines:
                try:
                    data = json.loads(line)
                    first_value = next(iter(data.values()))
                    if "timestamp" in first_value:
                        timestamp = first_value["timestamp"]

                        if int(timestamp) >= current_time - fifteen_minutes:
                            filtered_lines.append(json.dumps(data) + "\n")
                except json.JSONDecodeError:
                    self.app.display_event(f"Error decoding JSON: {line}")

        filtered_lines.append(json.dumps(message, ensure_ascii=False) + "\n")

        with open(filename, 'w') as file:
            file.writelines(filtered_lines)

    def calculate_broadcast_address(self, LOCAL_IP_ADDRESS, subnet_mask):
        ip_parts = [int(part) for part in LOCAL_IP_ADDRESS.split('.')]
        mask_parts = [int(part) for part in subnet_mask.split('.')]

        broadcast_parts = [(ip | (255 - mask)) for ip, mask in zip(ip_parts, mask_parts)]
        return '.'.join(map(str, broadcast_parts))

    def get_broadcast_ip(self, local_LOCAL_IP_ADDRESS):
        subnet_mask = LocalIp.get_subnet_mask()
        return self.calculate_broadcast_address(local_LOCAL_IP_ADDRESS, subnet_mask)

    def Responder(self):
        serverPort = 6001
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind(("", serverPort))
        client_socket.listen(5)  # Allow multiple connections
        self.app.display_event('The server is ready to respond \n')

        while not stop_event.is_set():
            try:
                connectionSocket, addr = client_socket.accept()
                Thread(target=self.handle_connection, args=(connectionSocket, addr)).start()
            except Exception as e:
                self.app.display_event(f"Error accepting connection: {e}")

        client_socket.close()
        self.app.display_event("Responder socket closed\n")

    def handle_connection(self, connectionSocket, addr):
        try:
            S = None  # Shared secret

            # First message should contain the key exchange or message
            received_data = connectionSocket.recv(2048)
            if not received_data:
                return

            data = json.loads(received_data.decode())

            if "key" in data:
                # Key exchange process
                B = data['key']
                p = 23
                g = 5
                a = random.randint(1, 999999)
                A = pow(g, a, p)

                # Send our part of the key
                connectionSocket.sendall(json.dumps({'key': A}).encode())

                # Calculate shared secret
                S = pow(int(B), a, p)
                self.app.display_event(f"Established shared secret: {S}")

                # Expect encrypted message next
                received_data = connectionSocket.recv(2048)
                if not received_data:
                    return
                data = json.loads(received_data.decode())

            if 'encrypted_message' in data and S is not None:
                encrypted_message = data['encrypted_message']
                decrypted_message = self.decrypt_message(encrypted_message, str(S))
                sender_username = self.users_dict.get(addr[0], "Unknown")
                self.display_received_message(sender_username, decrypted_message, encrypted=True)

            elif 'unencrypted_message' in data:
                unencrypted_message = data['unencrypted_message']
                sender_username = self.users_dict.get(addr[0], "Unknown")
                self.display_received_message(sender_username, unencrypted_message, encrypted=False)

        except Exception as e:
            self.app.display_event(f"Connection error: {e}")
        finally:
            connectionSocket.close()

    def display_received_message(self, sender, message, encrypted):
        timestamp = time.time()
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        status = "ENCRYPTED" if encrypted else "UNENCRYPTED"

        display_text = f"Received {status.lower()} message from {sender} at {time_str}: {message}\n"
        self.app.display_tx(display_text)

        log_entry = {
            'timestamp': timestamp,
            'sender_username': sender,
            'message': message,
            'status': status
        }
        self.log_message(log_entry)

    def log_message(self, log_entry):
        with open(self.filename, 'a') as file:
            json.dump(log_entry, file)
            file.write('\n')

    def show_users(self):
        users_status = self.check_user_status(self.filename)
        self.app.display_event("Current users:")
        for user, status in users_status.items():
            self.app.display_event(f"{user}: {status}")

    def check_user_status(self, log_file, threshold=10):
        current_time = time.time()
        users_status = {}

        try:
            with open(log_file, 'r') as file:
                for line in file:
                    try:
                        if line.strip():
                            data = json.loads(line)
                            if isinstance(data, dict) and len(data) == 1:
                                username = list(data.keys())[0]
                                user_info = data[username]
                                if isinstance(user_info, dict) and 'sender_ip' in user_info:
                                    timestamp = user_info.get('timestamp', 0)
                                    if username not in users_status or timestamp > users_status[username].get(
                                            'timestamp', 0):
                                        users_status[username] = {
                                            'timestamp': timestamp,
                                            'ip': user_info['sender_ip']
                                        }
                    except json.JSONDecodeError:
                        continue

            result = {}
            for user, info in users_status.items():
                last_announcement = info["timestamp"]
                if current_time - last_announcement <= threshold:
                    result[user] = "Online"
                elif current_time - last_announcement <= threshold * 6:
                    result[user] = "Away"
                else:
                    result[user] = "Offline"
            return result
        except FileNotFoundError:
            return {}


# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class GUI_P2PChatApplicationClient:
    def __init__(self, master):
        self.master = master
        master.title("P2P Chat Application")
        master.geometry("800x600")
        self.message = None

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(side="top", pady=10)

        self.username_info_label = tk.Label(self.button_frame, text="Not logged in", bg="lightgray")
        self.username_info_label.pack(side="left", anchor="w", padx=(10, 8), fill="both")

        self.username_button = tk.Button(self.button_frame, text="Enter Username", command=self.enter_username)
        self.username_button.pack(side="left", padx=10)

        self.users_button = tk.Button(self.button_frame, text="Display Users", command=self.show_users)
        self.users_button.pack(side="left", padx=10)

        self.chat_button = tk.Button(self.button_frame, text="Chat", command=self.show_chat)
        self.chat_button.pack(side="left", padx=10)

        self.history_button = tk.Button(self.button_frame, text="History", command=self.show_history)
        self.history_button.pack(side="left", padx=10)

        self.exit = tk.Button(self.button_frame, text="Exit", command=self.quit_programme)
        self.exit.pack(side="left", padx=10)

        self.events_frame = tk.Frame(master)
        self.events_frame.pack(side="left", padx=10, pady=10, fill="both")

        self.event_label = tk.Label(self.events_frame, text="Events", font=("Helvetica", 14, "bold"))
        self.event_label.pack(anchor="w", padx=10, pady=5)

        self.event_text = tk.Text(self.events_frame, wrap="word", width=100, height=20)
        self.event_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.message_frame = tk.Frame(master)
        self.message_frame.pack(side="left", padx=10, pady=10, fill="both")

        self.message_label = tk.Label(self.events_frame, text="Received/Sent Messages", font=("Helvetica", 14, "bold"))
        self.message_label.pack(anchor="w", padx=10, pady=5)

        self.message_text = tk.Text(self.events_frame, wrap="word", width=100, height=10)
        self.message_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.main_frame = tk.Frame(master)
        self.main_frame.pack(side="left", anchor="center", padx=10, pady=10, expand=True)

        self.update_users = True
        self.display_text()
        self.current_frame = None

    def quit_programme(self):
        stop_event.set()
        threads.clear()
        stop_event.clear()
        os._exit(1)
        quit()

    def display_text(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.main_frame.pack(side="left", anchor="center", padx=10, pady=10, expand=True)

        self.title_label = tk.Label(self.main_frame,
                                    text="To start, first enter your username.\n Then push one of the buttons: Display Users, Chat, History",
                                    font=("Helvetica", 14, "bold"))
        self.title_label.pack(side="top", anchor="center", padx=10, pady=5, fill="both", expand=True)

    def display_event(self, event):
        self.event_text.insert(tk.END, f"{event} \n")
        self.event_text.see(tk.END)

    def display_tx(self, event):
        self.message_text.insert(tk.END, f"{event} \n")
        self.message_text.see(tk.END)

    def show_users(self):
        self.display_event("Displaying users.\n")
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.user_label = tk.Label(self.main_frame, text="Users", font=("Helvetica", 14, "bold"))
        self.user_label.pack(anchor="w", padx=10, pady=5)

        self.user_text = tk.Text(self.main_frame, wrap="word", width=50, height=30)
        self.user_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.close_button = tk.Button(self.main_frame, text="Close", command=self.close_chat)
        self.close_button.pack(side="left", anchor="center", expand=True, fill="x")

        def update_user_status():
            if not self.update_users:
                return

            users_status = client.check_user_status("chat_log.json")
            self.user_text.delete('1.0', tk.END)
            self.user_text.insert(tk.END, "Users Status:\n")
            self.user_text.insert(tk.END, "-" * 40 + "\n")

            if not users_status:
                self.user_text.insert(tk.END, "No users found\n")
            else:
                for user, status in users_status.items():
                    self.user_text.insert(tk.END, f"{user}: {status}\n")

            self.main_frame.after(5000, update_user_status)

        self.update_users = True
        update_user_status()

    def show_chat(self):
        self.display_event("Displaying chat\n")
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.main_frame.pack(side="left", anchor="center", padx=10, pady=10, expand=True)

        self.secure_button = tk.Button(self.main_frame, text="Secure Chat", command=self.secure_chat)
        self.secure_button.pack(side="top", anchor="center", padx=10, pady=10, fill="both", expand=True)

        self.unsecure_button = tk.Button(self.main_frame, text="Unsecure Chat", command=self.unsecure_chat)
        self.unsecure_button.pack(side="top", anchor="center", padx=10, pady=10, fill="both", expand=True)

    def secure_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.target_username_label = tk.Label(self.main_frame, text="Enter Target Username:")
        self.target_username_label.pack(side="top", anchor="center", padx=10, pady=10)

        self.target_username_entry = tk.Entry(self.main_frame)
        self.target_username_entry.pack(side="top", fill="both", expand=True)

        self.submit_button = tk.Button(self.main_frame, text="Submit",
                                       command=lambda: self.initiate_chat("secured_chat"))
        self.submit_button.pack(side="top", anchor="center", padx=10, pady=10)

        self.display_event(f"Pressed secure chat button")

    def initiate_chat(self, mode):
        self.display_event(f"Mode is {mode}")
        target_username = self.target_username_entry.get()
        self.display_event(f"Target username is {target_username}")

        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.create_chat_input_frame(mode, target_username)

    def create_chat_input_frame(self, mode, target_username):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.chat_label = tk.Label(self.main_frame, text="Chat", font=("Helvetica", 14, "bold"))
        self.chat_label.pack(anchor="w", padx=10, pady=5)

        self.message_entry = tk.Entry(self.main_frame)
        self.message_entry.pack(side="top", fill="both", expand=True)

        self.send_button = tk.Button(self.main_frame, text="Send",
                                     command=lambda: self.send_message(mode, target_username))
        self.send_button.pack(side="left", anchor="center", expand=True, fill="x")

        self.close_button = tk.Button(self.main_frame, text="Close Chat", command=self.close_chat)
        self.close_button.pack(side="left", anchor="center", expand=True, fill="x")

    def close_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.display_text()

    def send_message(self, mode, target_username):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.message = self.message_entry.get()
        if self.message:
            if client and target_username and self.message:
                client.chat_initiator(mode, target_username, self.message)
            self.display_tx(f"Sent: '{self.message}'. To: {target_username}")

    def unsecure_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.main_frame.pack(side="left", anchor="center", padx=10, pady=10, expand=True)

        self.target_username_label = tk.Label(self.main_frame, text="Enter Target Username:")
        self.target_username_label.pack(side="top", anchor="center", padx=10, pady=10)

        self.target_username_entry = tk.Entry(self.main_frame)
        self.target_username_entry.pack(side="top", fill="both", expand=True)

        self.submit_button = tk.Button(self.main_frame, text="Submit",
                                       command=lambda: self.initiate_chat("unsecured_chat"))
        self.submit_button.pack(side="top", anchor="center", padx=10, pady=10)

        self.display_event(f"Pressed unsecure chat button")

    def display_hist(self):
        try:
            with open(client.filename, "r") as f:
                chat_history = f.read()
                self.history_text.insert(tk.END, chat_history)
        except FileNotFoundError:
            self.history_text.insert(tk.END, "No chat history found.")

        self.history_text.config(state="disabled")

    def show_history(self):
        self.display_event("Displaying History\n")
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.history_label = tk.Label(self.main_frame, text="History", font=("Helvetica", 14, "bold"))
        self.history_label.pack(side="top", anchor="center", padx=10, pady=5)

        self.history_text = tk.Text(self.main_frame)
        self.history_text.pack(side="top", fill="both", expand=True)

        self.close_button = tk.Button(self.main_frame, text="Close History", command=self.display_text)
        self.close_button.pack(side="top", anchor="center", expand=True, fill="x")

        self.display_hist()

    def enter_username(self):
        self.username_window = tk.Toplevel(self.master)
        self.username_window.title("Enter Username")

        window_width = 300
        window_height = 100
        screen_width = self.username_window.winfo_screenwidth()
        screen_height = self.username_window.winfo_screenheight()
        x_coordinate = (screen_width - window_width) // 2
        y_coordinate = (screen_height - window_height) // 2
        self.username_window.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

        label_username = tk.Label(self.username_window, text="Enter your username:")
        label_username.pack()

        entry_username = tk.Entry(self.username_window)
        entry_username.pack()

        enter_button_username = tk.Button(self.username_window, text="Enter",
                                          command=lambda: self.process_username(entry_username.get()))
        enter_button_username.pack()

    def process_username(self, username):
        global username_queue
        self.display_event(f"Entered username: {username} ")
        self.username_window.destroy()
        username_queue.put(username)
        self.username_info_label.config(text="Logged in as " + username, bg="lightgreen")


def run_gui():
    root = tk.Tk()
    global app
    app = GUI_P2PChatApplicationClient(root)
    root.mainloop()


def run_p2p_chat():
    global username_queue
    username = username_queue.get()
    global client
    client = P2PChatApplicationClient(username, app)

    announcer_thread = Thread(target=client.service_announcer)
    discovery_thread = Thread(target=client.peer_discovery)
    responder = Thread(target=client.Responder)

    threads.extend([announcer_thread, discovery_thread, responder])
    announcer_thread.start()
    discovery_thread.start()
    responder.start()

    announcer_thread.join()
    discovery_thread.join()
    responder.join()


if __name__ == "__main__":
    gui_thread = threading.Thread(target=run_gui)
    p2p_thread = threading.Thread(target=run_p2p_chat)

    gui_thread.start()
    p2p_thread.start()

    gui_thread.join()
    p2p_thread.join()