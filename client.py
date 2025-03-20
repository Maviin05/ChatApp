import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, Frame, Label
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db

# Initialize Firebase
cred = credentials.Certificate("chatapp-411a7-firebase-adminsdk-fbsvc-7c90e5d836.json")  
firebase_admin.initialize_app(cred, {'databaseURL': 'https://chatapp-411a7-default-rtdb.firebaseio.com/'})  

# Caesar Cipher functions
def caesar_cipher(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift if char.islower() else shift % 26
            new_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift_amount) % 26) + ord('a' if char.islower() else 'A'))
            result += new_char
        else:
            result += char
    return result

def caesar_decipher(text, shift=3):
    return caesar_cipher(text, -shift)  # Decrypt by shifting backward

class ChatClient:
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

    
        self.username = simpledialog.askstring("Username", "Enter your username:")
        if not self.username:
            self.username = "Guest"
        self.client_socket.send(self.username.encode('utf-8'))

    
        self.displayed_messages = set()

    
        self.update_user_status(online=True)

        
        self.root = tk.Tk()
        self.root.title(f"Chat - {self.username}")
        self.root.geometry("400x600")
        self.root.configure(bg="#F6F6F6")

        self.header = tk.Label(self.root, text="ChatApp", font=("Arial", 14, "bold"), bg="#5D9CEC", fg="white")
        self.header.pack(fill="x", pady=5)

        self.text_area = scrolledtext.ScrolledText(self.root, state='disabled', wrap='word', width=50, height=25, bg="#F6F6F6", borderwidth=0)
        self.text_area.pack(padx=10, pady=10)

        self.message_frame = tk.Frame(self.root, bg="#F6F6F6")
        self.message_frame.pack(fill="x", padx=10, pady=5)

        self.entry = tk.Entry(self.message_frame, width=30, font=("Arial", 12), bd=0, bg="#FFFFFF")
        self.entry.pack(side="left", padx=10, pady=5, ipady=5)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.message_frame, text="➤", font=("Arial", 14), fg="white", bg="#5D9CEC", bd=0, command=self.send_message)
        self.send_button.pack(side="right", padx=5)

        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

        self.listen_to_firebase()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def receive_messages(self):
        """Handles receiving messages from the server and decrypts them."""
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    if "|right" in message:
                        encrypted_text = message.replace("|right", "").strip()
                        decrypted_text = caesar_decipher(encrypted_text)
                        self.display_message(decrypted_text, "right")
                    elif "|left" in message:
                        encrypted_text = message.replace("|left", "").strip()
                        decrypted_text = caesar_decipher(encrypted_text)
                        self.display_message(decrypted_text, "left")
            except:
                break

    def display_message(self, message, align="left"):
        """Properly aligns and displays messages in the chat."""
        self.text_area.configure(state='normal')

        timestamp = datetime.now().strftime("%I:%M %p")
        msg_frame = Frame(self.text_area, bg="#F6F6F6")

        bubble_color = "#5D9CEC" if align == "right" else "#FFFFFF"
        text_color = "white" if align == "right" else "black"
        anchor = "e" if align == "right" else "w"
        padding = (50, 5) if align == "right" else (5, 50)

        timestamp_label = Label(msg_frame, text=timestamp, font=("Arial", 8), fg="gray", bg="#F6F6F6")
        timestamp_label.pack(anchor=anchor, padx=padding)

        msg_label = Label(
            msg_frame, text=message, font=("Arial", 12), fg=text_color, bg=bubble_color,
            padx=10, pady=5, wraplength=250
        )
        msg_label.pack(anchor=anchor, padx=padding)

        self.text_area.window_create(tk.END, window=msg_frame)
        self.text_area.insert(tk.END, "\n")

        self.text_area.configure(state='disabled')
        self.text_area.see(tk.END)

    def send_message(self, event=None):
        """Encrypts and sends messages."""
        message = self.entry.get().strip()
        if not message:
            return

        self.entry.delete(0, tk.END)

        encrypted_message = caesar_cipher(message)
        formatted_msg = f"{self.username}: {encrypted_message}|right"
        
        self.display_message(f"You: {message}", "right")  
        self.client_socket.send(formatted_msg.encode('utf-8'))

    def update_user_status(self, online):
        """Updates Firebase user status."""
        users_ref = db.reference("users").child(self.username)
        users_ref.update({
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "online" if online else "offline"
        })

    def on_closing(self):
        """Handles disconnection."""
        self.update_user_status(online=False)
        self.client_socket.send('exit'.encode('utf-8'))
        self.client_socket.close()
        self.root.quit()

if __name__ == "__main__":
    host = input("Enter the server IP address: ")
    port = 5002
    ChatClient(host, port)
