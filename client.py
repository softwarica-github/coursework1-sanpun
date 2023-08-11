from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, messagebox, Menu, font
import socket
import threading
import os
import tkinter as tk
import sqlite3

def xor_cypher(input_string, key):
    if len(key) < len(input_string):
        key = key * (len(input_string) // len(key)) + key[:len(input_string) % len(key)]
    
    input_bytes = input_string.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    encrypted_bytes = bytearray([byte ^ key_byte for byte, key_byte in zip(input_bytes, key_bytes)])
    
    return encrypted_bytes


conn = sqlite3.connect("user_database.db")
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users (
                username text,
                password text,
                email text
            )""")

class GUI:
    client_socket = None
    last_received_message = None
    
    def __init__(self, master, username):
        self.root = master
        self.chat_transcript_area = None
        self.name_widget = None
        self.enter_text_widget = None
        self.send_button = None
        self.join_button = None
        self.file_menu = None
        self.username = username 
        self.initialize_socket()
        self.initialize_gui()
        self.listen_for_incoming_messages_in_a_thread()

    def initialize_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_ip = '127.0.0.1'
        remote_port = 10319
        self.client_socket.connect((remote_ip, remote_port))

    def initialize_gui(self):
        self.root.title("Secure Chat System by Sandipa Pun")
        self.root.geometry("800x600")  

        self.display_menu()
        self.display_chat_box()
        self.display_chat_entry_box()

    def display_menu(self):
        menu_bar = Menu(self.root)
        
        self.file_menu = Menu(menu_bar, tearoff=0)
        self.file_menu.add_command(label="Clear Chat", command=self.clear_chat)
        self.file_menu.add_command(label="Exit", command=self.on_close_window)
        menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.root.config(menu=menu_bar)

    def listen_for_incoming_messages_in_a_thread(self):
        thread = threading.Thread(target=self.receive_message_from_server, args=(self.client_socket,))
        thread.start()
        

    def receive_message_from_server(self, so):
        while True:
            buffer = so.recv(256)
            if not buffer:
                break
            decrypted_message = xor_cypher(buffer.decode('utf-8'), 'your_key_here').decode('utf-8')
            
            if "joined" in decrypted_message:
                user = decrypted_message.split(":")[1]
                message = user + " has joined"
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)
            else:
                self.chat_transcript_area.insert('end', decrypted_message + '\n')
                self.chat_transcript_area.yview(END)

    def display_chat_box(self):
        frame = Frame()
        Label(frame, text='Chat Box:', font=("Serif", 16)).pack(side='top', anchor='w')
        self.chat_transcript_area = Text(frame, width=70, height=20, font=("Serif", 12)) 
        scrollbar = Scrollbar(frame, command=self.chat_transcript_area.yview, orient=VERTICAL)
        self.chat_transcript_area.config(yscrollcommand=scrollbar.set)
        self.chat_transcript_area.bind('<KeyPress>', lambda e: 'break')
        self.chat_transcript_area.pack(side='left', padx=5)
        scrollbar.pack(side='right', fill='y')
        frame.pack(side='top', pady=10)

    def display_chat_entry_box(self):
            frame = Frame()
            Label(frame, text='Enter message:', font=("Serif", 16)).pack(side='left', anchor='w')
            self.enter_text_widget = Text(frame, width=40, height=5, font=("Serif", 12)) 
            self.enter_text_widget.pack(side='left', padx=5)
            self.enter_text_widget.bind('<Return>', self.on_enter_key_pressed)
            frame.pack(side='top')

            self.send_button = Button(frame, text="Send", font=("Serif", 14), command=self.send_chat, height=2, width=10) 
            self.send_button.pack(side='left', padx=5, pady=5)

    def on_enter_key_pressed(self, event):
        self.send_chat()
        self.clear_text()

    def clear_text(self):
        self.enter_text_widget.delete(1.0, 'end')

    def send_chat(self):
        senders_name = self.username + ": "
        data = self.enter_text_widget.get(1.0, 'end').strip()
        encrypted_data = xor_cypher(senders_name + data, 'your_key_here')  
        self.client_socket.send(encrypted_data)
        self.chat_transcript_area.insert('end', senders_name + data + '\n')
        self.chat_transcript_area.yview(END)
        self.enter_text_widget.delete(1.0, 'end')
        return 'break'


    def on_close_window(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            self.client_socket.close()
            exit(0)

    def clear_chat(self):
        self.chat_transcript_area.delete(1.0, END)


root = tk.Tk()
main_frame = tk.Frame(root)
main_frame.pack(expand=True)
root.title("Secure Chat System by Sandipa Pun")
root.geometry("800x600")  


welcome_label = tk.Label(main_frame, text="Welcome to Secure Chat System", font=("Helvetica", 24, 'bold'))
welcome_label.pack(expand=True)

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)


def sign_up():
    sign_up_window = tk.Toplevel(root)
    sign_up_window.title("Sign Up")
    sign_up_window.geometry("500x350")  
    username_label = tk.Label(sign_up_window, text="Username:", font=("Serif", 16))
    username_label.pack()
    username_entry = tk.Entry(sign_up_window, font=("Serif", 14))
    username_entry.pack()

    password_label = tk.Label(sign_up_window, text="Password:", font=("Serif", 16))
    password_label.pack()
    password_entry = tk.Entry(sign_up_window, show="*", font=("Serif", 14))
    password_entry.pack()

    confirm_password_label = tk.Label(sign_up_window, text="Confirm Password:", font=("Serif", 16))
    confirm_password_label.pack()
    confirm_password_entry = tk.Entry(sign_up_window, show="*", font=("Serif", 14))
    confirm_password_entry.pack()

    email_label = tk.Label(sign_up_window, text="Email:", font=("Serif", 16))
    email_label.pack()
    email_entry = tk.Entry(sign_up_window, font=("Serif", 14))
    email_entry.pack()

    def register():
        username = username_entry.get()
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()
        email = email_entry.get()

        if not username or not password or not confirm_password or not email:
            messagebox.showerror("Error", "All fields must be filled!")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone() is not None:
            messagebox.showerror("Error", "Username already exists!")
            return

        c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, email))
        conn.commit()

        messagebox.showinfo("Success", "Account created successfully!")

        sign_up_window.destroy()


    sign_up_button = tk.Button(sign_up_window, text="Sign Up", font=("Serif", 18), command=register)
    sign_up_button.pack(pady=20)


def sign_in():
    sign_in_window = tk.Toplevel(root)
    sign_in_window.title("Sign In")
    sign_in_window.geometry("300x200")  

    username_label = tk.Label(sign_in_window, text="Username:", font=("Serif", 16))
    username_label.pack()
    username_entry = tk.Entry(sign_in_window, font=("Serif", 14))
    username_entry.pack()

    password_label = tk.Label(sign_in_window, text="Password:", font=("Serif", 16))
    password_label.pack()
    password_entry = tk.Entry(sign_in_window, show="*", font=("Serif", 14))
    password_entry.pack()

    def validate():
        username = username_entry.get()
        password = password_entry.get()


        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        if c.fetchone() is not None:
            messagebox.showinfo("Success", "Logged in successfully!")
            main_frame.pack_forget()
            sign_in_window.destroy()

            gui = GUI(root, username)

        else:
            messagebox.showerror("Error", "Invalid username or password!")

    sign_in_button = tk.Button(sign_in_window, text="Sign In", font=("Serif", 14), command=validate)
    sign_in_button.pack(pady=20)


image_path = r"/home/san/securechat/logo.png"  
image = tk.PhotoImage(file=image_path)

image_label = tk.Label(main_frame, image=image)
image_label.pack(expand=True)

button_frame = tk.Frame(main_frame)
button_frame.pack(expand=True)

sign_up_button = tk.Button(button_frame, text="Sign Up", font=("Serif", 14), command=sign_up)
sign_up_button.grid(row=0, column=0, padx=10)

sign_in_button = tk.Button(button_frame, text="Sign In", font=("Serif", 14), command=sign_in)
sign_in_button.grid(row=0, column=1, padx=10)

root.mainloop()
conn.close()







