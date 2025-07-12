import tkinter as tk
import socket
import random

key_client = 10
client_socket = None
connected = False

def validate_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def connect_to_server():
    global client_socket, connected
    try:
        ip = entry_ip.get()
        if not validate_ip(ip):
            label_status.config(text="Invalid IP address format.")
            return
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, 8080))
        connected = True
        button_connect.config(text="Connected", state="disabled")
        label_status.config(text="Connected to server.")
    except Exception as e:
        label_status.config(text=f"Connection error: {e}")
        connected = False

def send_number():
    global key_client, connected
    if not connected:
        label_status.config(text="Not connected to server.")
        return
    try:
        number = int(entry_number.get())
        if 1 <= number <= 100:
            key_client = number
            label_text.set(f"Select a number (1-100):  {key_client}")
            client_socket.sendall(str(key_client).encode('utf-8'))
            label_status.config(text="Number sent successfully!")
            # button_send.config(state="disabled")  # Disable after sending
        else:
            label_status.config(text="Enter a number between 1 and 100.")
    except BrokenPipeError:
        label_status.config(text="Connection broken. Restart client.")
        connected = False
    except ValueError:
        label_status.config(text="Invalid input.")
    except Exception as e:
        label_status.config(text=f"Error: {e}")

# GUI
root = tk.Tk()
root.title("Diffie-Hellman Client")
root.geometry("500x400")

tk.Label(root, text="Diffie-Hellman Client", font=("Arial", 16)).pack(pady=20)

tk.Label(root, text="Enter Server IP Address:").pack()
entry_ip = tk.Entry(root)
entry_ip.pack(pady=5)

button_connect = tk.Button(root, text="Connect to Server", command=connect_to_server)
button_connect.pack(pady=10)

label_text = tk.StringVar()
label_text.set(f"Select a number (1-100):  {key_client}")
tk.Label(root, textvariable=label_text).pack(pady=10)

entry_number = tk.Entry(root)
entry_number.pack(pady=5)

button_send = tk.Button(root, text="Send Number", command=send_number)
button_send.pack(pady=10)

label_status = tk.Label(root, text="")
label_status.pack(pady=10)

root.mainloop()
