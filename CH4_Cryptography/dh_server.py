import tkinter as tk
import socket
import threading

selectect_confirm_number = 10
clients = []
port = 8080

# GUI setup
root = tk.Tk()
root.title("Diffie-Hellman Server")
root.geometry("500x600")
tk.Label(root, text="Diffie-Hellman Server", font=("Arial", 16)).pack(pady=20)

info = tk.Text(root, width=60, height=20)
info.pack(pady=10)

def log(msg):
    info.insert(tk.END, str(msg) + "\n")
    info.see(tk.END)

def validate_number(num):
    try:
        num = int(num)
        return (1 <= num <= 100), num
    except ValueError:
        return False, None

def confirm_selection():
    global selectect_confirm_number
    number = entry.get()
    valid, number = validate_number(number)
    if not valid:
        log("Invalid number. Enter between 1 and 100.")
        return
    selectect_confirm_number = number
    label_text.set(f"Select a number (1-100):  {selectect_confirm_number}")
    log(f"Server private key set to: {selectect_confirm_number}")

label_text = tk.StringVar()
label_text.set(f"Select a number (1-100):  {selectect_confirm_number}")
tk.Label(root, textvariable=label_text).pack()

entry = tk.Entry(root)
entry.pack(pady=5)

tk.Button(root, text="Confirm Your Key", command=confirm_selection).pack(pady=10)

def diffie_hellman_key_exchange(a, b):
        # Simple Diffie-Hellman key exchange simulation
    log(f"Received client's private key {a} Server's private key {b}")
    p = 23  # A prime number
    log(f"A prime number (p) : {p}")
    g = 5   # A primitive root modulo 
    log(f"A primitive root modulo {p} : (g)= {g}")

    # Alice's private key
    a_private = a
    log(f"a_private = : {a}")
    # Bob's private key
    b_private = b
    log(f"b_private = : {b}")
    
    # Alice computes her public key
    a_public = (g ** a_private) % p
    log("a_public = (g ** a_private) % p")
    log(f"a_public = : {a_public}")
    # Bob computes his public key
    b_public = (g ** b_private) % p
    log("b_public = (g ** b_private) % p")
    log(f"b_public = : {b_public}")


    # They exchange public keys and compute the shared secret
    shared_secret_a = (b_public ** a_private) % p
    log("shared_secret_a = (b_public ** a_private) % p")
    log(f"shared_secret_a = {shared_secret_a}")

    shared_secret_b = (a_public ** b_private) % p
    log("shared_secret_b = (a_public ** b_private) % p")
    log(f"shared_secret_b = {shared_secret_b}")

    log(f"✔️ Shared Symmetric key confirmed shared_secret_a=shared_secret_b ={shared_secret_a}")

    return shared_secret_a, shared_secret_b

def handle_client(client_socket):
    try:
        while True:
            msg = client_socket.recv(1024).decode('utf-8')
            if not msg:
                break
            print(f"Received key from client: {msg}")
            shared_secret_a, shared_secret_b = diffie_hellman_key_exchange(int(msg), selectect_confirm_number)
    except Exception as e:
        print(f"Error with client: {e}")
    finally:
        client_socket.close()


def accept_clients():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

# Start accepting connections in the background
threading.Thread(target=accept_clients, daemon=True).start()

root.mainloop()
