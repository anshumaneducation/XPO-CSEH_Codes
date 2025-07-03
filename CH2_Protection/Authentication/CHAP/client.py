import socket
import hashlib
import tkinter as tk
from tkinter import messagebox
import os

# File path
file_path = "/etc/encrypted_file.enc"

# Check if the encrypted file exists before opening the app
if not os.path.exists(file_path):
    exit()

# Shared secret password (same as server)
shared_secret = "mypassword"

# Function to compute the hash (using MD5)
def compute_hash(challenge, password):
    return hashlib.md5((password + challenge).encode()).hexdigest()

# Function to connect to the server and authenticate
def authenticate():
    username = entry_username.get()
    password = entry_password.get()
    write_to_textbox(f"Attempting to authenticate with username: {username}")
    write_to_textbox(f"Using password: {password}")

    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return
    
    ip= entry_ip.get()
    # Connect to the server
    server_host = ip
    server_port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_host, server_port))
        
        # Receive challenge from server
        challenge = client_socket.recv(1024).decode()
        write_to_textbox(f"Received challenge: {challenge}")
        print(f"Received challenge: {challenge}")
        
        # Update the client GUI with the received challenge
        label_challenge.config(text=f"Challenge: {challenge}")

        # Compute response
        write_to_textbox("Computing response using MD5 hash.")
        response = compute_hash(challenge, password)
        write_to_textbox(f"Computed response: {response}")

        # Send username and response to server
        client_socket.send(f"{username},{response}".encode())
        write_to_textbox(f"Sent username and response to server: {username}, {response}")

        # Receive authentication result
        result = client_socket.recv(1024).decode()
        write_to_textbox(f"Authentication result: {result}")
        messagebox.showinfo("Authentication", result)

    except Exception as e:
        messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
    finally:
        client_socket.close()

def write_to_textbox(text):
    textbox_flow.insert(tk.END, text + "\n")
    textbox_flow.see(tk.END)

# Create the GUI window for the client
window = tk.Tk()
window.geometry("600x700")
window.title("CHAP Authentication Client")

# IP address label and input
label_ip_addr = tk.Label(window, text="IP Address: ")
label_ip_addr.pack(pady=5)
entry_ip = tk.Entry(window)
entry_ip.pack(pady=5)

# Username and password labels and inputs
label_username = tk.Label(window, text="Username:")
label_username.pack(pady=5)
entry_username = tk.Entry(window)
entry_username.pack(pady=5)

label_password = tk.Label(window, text="Password:")
label_password.pack(pady=5)
entry_password = tk.Entry(window, show="*")
entry_password.pack(pady=5)

label_flow_client = tk.Label(window, text="Client Flow: Authenticate with the server using CHAP.")
label_flow_client.pack(pady=10)

textbox_flow = tk.Text(window, height=10, width=50)
textbox_flow.pack(pady=5)

# Label for showing the challenge
label_challenge = tk.Label(window, text="Challenge will appear here.")
label_challenge.pack(pady=5)

# Authentication button
auth_button = tk.Button(window, text="Authenticate", command=authenticate)
auth_button.pack(pady=20)


# Create a label for the steps of CHAP with server client interaction here
label_steps = tk.Label(window, text="Steps of CHAP Authentication:\n1. Client sends username and password.\n2. Server generates a challenge.\n3. Client computes response using MD5 hash.\n4. Client sends response to server.\n5. Server validates response and sends result back.")
label_steps.pack(pady=10)

# Run the GUI loop
window.mainloop()
