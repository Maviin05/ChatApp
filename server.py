import socket
import threading
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime

# Initialize Firebase
cred = credentials.Certificate("chatapp-411a7-firebase-adminsdk-fbsvc-7c90e5d836.json")  
firebase_admin.initialize_app(cred, {'databaseURL': 'https://chatapp-411a7-default-rtdb.firebaseio.com/'}) 

# Caesar Cipher functions
def caesar_decipher(text, shift=3):
    return caesar_cipher(text, -shift)

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

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5002):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.clients = {}

        print(f"✅ Server started on {host}:{port}")
        threading.Thread(target=self.accept_clients).start()

    def accept_clients(self):
        while True:
            client_socket, address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, address)).start()

    def handle_client(self, client_socket, address):
        username = client_socket.recv(1024).decode('utf-8').strip()
        self.clients[client_socket] = username  

        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8').strip()
                decrypted_message = caesar_decipher(message[len(username) + 2:])
                self.broadcast(message, client_socket)
            except:
                del self.clients[client_socket]
                client_socket.close()
                break

if __name__ == "__main__":
    ChatServer()
