import socket
import threading
import logging

class ChatServer:
    
    clients_list = []
    last_received_message = ""

    def xor_cypher(self, input_string, key='K'):
        return ''.join(chr(ord(c) ^ ord(key)) for c in input_string)

    def __init__(self):
        self.server_socket = None
        self.create_listening_server()

    def create_listening_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_ip = '127.0.0.1'
        local_port = 10319
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((local_ip, local_port))
        logging.info("Listening for incoming messages..")
        self.server_socket.listen(5)
        self.receive_messages_in_a_new_thread()

    def receive_messages(self, so):
        while True:
            incoming_buffer = so.recv(256)
            if not incoming_buffer:
                break
            encrypted_message = incoming_buffer.decode('utf-8')
            self.last_received_message = self.xor_cypher(encrypted_message)  # Decrypting
            self.broadcast_to_all_clients(so)
        so.close()

    def broadcast_to_all_clients(self, senders_socket):
        encrypted_message = self.xor_cypher(self.last_received_message)  # Encrypting
        for client in self.clients_list:
            socket, (ip, port) = client
            if socket is not senders_socket:
                socket.sendall(encrypted_message.encode('utf-8'))
        logging.info("Message broadcasted to all clients: {}".format(self.last_received_message))

    def receive_messages_in_a_new_thread(self):
        while True:
            client = so, (ip, port) = self.server_socket.accept()
            self.add_to_clients_list(client)
            logging.info('Connected to {}:{}'.format(ip, port))
            t = threading.Thread(target=self.receive_messages, args=(so,))
            t.start()

    def add_to_clients_list(self, client):
        if client not in self.clients_list:
            self.clients_list.append(client)
            logging.info('New client added: {}'.format(client[1]))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ChatServer()
