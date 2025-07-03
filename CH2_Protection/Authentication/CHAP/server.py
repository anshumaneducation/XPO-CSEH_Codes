import socket
import hashlib
import random
import string
import threading
import tkinter as tk
import os

# File path
file_path = "/etc/encrypted_file.enc"

# Check if the encrypted file exists before opening the app
if not os.path.exists(file_path):
    exit()

shared_secret_set="mypassword"


# Function to generate a random challenge string
def generate_challenge():
    write_to_textbox("Generating challenge...")
    write_to_textbox("Challenge generated.")
    # Generate a random string of 8 alphanumeric characters
    write_to_textbox("Generating random alphanumeric string for challenge.")
    write_to_textbox("Random alphanumeric string generated.")
    write_to_textbox(''.join(random.choices(string.ascii_letters + string.digits, k=8)))
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))


# Function to hash challenge + password using MD5
def compute_hash(challenge, password):
    write_to_textbox("Computing MD5 hash of challenge and password.")
    write_to_textbox(f"Challenge: {challenge}, Password: {password}")
    write_to_textbox("MD5 hash computed.")
    return hashlib.md5((password + challenge).encode()).hexdigest()

# Set password from GUI input
def set_password():
    global shared_secret_set
    if entry_password.get() != "":
        shared_secret.set(entry_password.get())  # Update shared secret with new password
        shared_secret_set=entry_password.get()

# This function handles each client connection in a separate thread
def handle_client(client_socket, client_address):
    print(f"Connection established with {client_address}")

    # Generate challenge and send it to the client
    challenge = generate_challenge()
    client_socket.send(challenge.encode())
    write_to_textbox(f"Sent challenge: {challenge}")
    print(f"Sent challenge: {challenge}")

    # Update the server GUI with the challenge
    label_challenge.config(text=f"Challenge: {challenge}")

    # Receive the username and response from the client
    client_data = client_socket.recv(1024).decode().split(',')
    received_username = client_data[0]
    received_response = client_data[1]

    # Update the server GUI with received username and response
    label_username.config(text=f"Received Username: {received_username}")
    write_to_textbox(f"Received Username: {received_username}")
    label_response.config(text=f"Received Response: {received_response}")
    write_to_textbox(f"Received Response: {received_response}")

    # Validate the response
    expected_response = compute_hash(challenge, shared_secret.get())
    write_to_textbox(f"Expected Response: {expected_response}")

    # Authenticate and send result back to client
    if received_response == expected_response:
        result = "Authentication successful!"
        print(result)
        client_socket.send(result.encode())
        write_to_textbox(result)
    else:
        result = "Authentication failed!"
        print(result)
        client_socket.send(result.encode())
        write_to_textbox(result)

    client_socket.close()

# Setup server
server_host = '0.0.0.0'
server_port = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_host, server_port))
server_socket.listen(5)  # Allow up to 5 simultaneous connections
print(f"Server listening on {server_host}:{server_port}...")

# Create the GUI window for the server
server_window = tk.Tk()
server_window.geometry("600x600")
server_window.title("CHAP Authenticator Server")
# Shared secret password (as a StringVar)
shared_secret = tk.StringVar()
shared_secret.set(shared_secret_set)  # Set initial password

# Labels to show received challenge and credentials
label_current_password = tk.Label(server_window, textvariable=shared_secret)
label_current_password.pack(pady=5)

entry_password = tk.Entry(server_window)
entry_password.pack(pady=5)

btn_set = tk.Button(server_window, text="Set Password", command=set_password)
btn_set.pack(pady=5)

# Labels to show received challenge and credentials
label_challenge = tk.Label(server_window, text="Challenge:")
label_challenge.pack(pady=5)

label_username = tk.Label(server_window, text="Received Username:")
label_username.pack(pady=5)

label_response = tk.Label(server_window, text="Received Response:")
label_response.pack(pady=5)

label_text_flow = tk.Label(server_window, text="Flow of Events in server below")
label_text_flow.pack(pady=5)

# Textbox to show flow of events
textbox_flow = tk.Text(server_window, height=15, width=50)
textbox_flow.pack(pady=5)
# Function to write text to the textbox
def write_to_textbox(text):
    textbox_flow.insert(tk.END, text + "\n")
    textbox_flow.see(tk.END)


# Function to accept client connections and spawn threads
def accept_connections():
    while True:
        client_socket, client_address = server_socket.accept()
        # Handle each client in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.daemon = True  # Allows the thread to exit when the main program exits
        client_thread.start()

# Run the accept_connections function in a separate thread so the GUI remains responsive
accept_thread = threading.Thread(target=accept_connections)
accept_thread.daemon = True
accept_thread.start()

# Start the GUI
server_window.mainloop()

# Close the server socket after GUI is closed
server_socket.close()
