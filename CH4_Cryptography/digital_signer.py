import tkinter as tk
from tkinter import filedialog, messagebox,ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import traceback
import hashlib
import time

public_key_path="public_key.pem"
# digital encryptor generator

def encrypt_file():
        global public_key_path
        file_path=file_path_var.get()
        process_messages_write("🔒 Starting Encryption Process...\n")
        if not file_path:
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return

        try:
            # Generate a random AES key
            process_messages_write("🔑 Generating AES Key...\n")
            aes_key = os.urandom(32)
            process_messages_write("  AES Key Generated.\n")
            process_messages_write("  AES Key Length: 256 bits\n")
            process_messages_write("  AES Key (hex): " + aes_key.hex() + "\n")
            iv = os.urandom(16)
            process_messages_write("  IV Generated.\n")
            process_messages_write("  IV Length: 128 bits\n")
            process_messages_write("  IV (hex): " + iv.hex() + "\n")
            process_messages_write("🔐 Encrypting File...\n")

            # Encrypt the file using AES
            with open(file_path, "rb") as file:
                file_data = file.read()

            process_messages_write("  File Data Read Successfully.\n")
            process_messages_write(f"  File Size: {len(file_data)} bytes\n")
            if len(file_data) == 0:
                messagebox.showerror("Error", "Selected file is empty.")
                return
            process_messages_write("  Padding File Data...\n")
            padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

            padded_data = padder.update(file_data) + padder.finalize()
            process_messages_write("  File Data Padded Successfully.\n")
            process_messages_write(f"  Padded Data Size: {len(padded_data)} bytes\n")
            process_messages_write("  Encrypting File Data with AES...\n")

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            process_messages_write("  AES Cipher Created.\n")
            process_messages_write("  Encryptor Created.\n")
            process_messages_write("  Encrypting Data...\n")
            # Encrypt the padded data

            encryptor = cipher.encryptor()

            process_messages_write("  Encryptor Initialized.\n")
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            process_messages_write("  Data Encrypted Successfully.\n")
            process_messages_write(f"  Encrypted Data Size: {len(encrypted_data)} bytes\n")
            process_messages_write("🔐 Encrypting AES Key with RSA...\n")


            # Encrypt the AES key using RSA
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            process_messages_write("  Public Key Loaded Successfully.\n")
            process_messages_write("  Encrypting AES Key with RSA...\n")
            process_messages_write("  Encrypting AES Key...\n")
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            process_messages_write("  AES Key Encrypted Successfully.\n")
            process_messages_write(f"  Encrypted AES Key Size: {len(encrypted_key)} bytes\n")
            process_messages_write("🔒 Encryption Process Completed Successfully.\n")
            # Save the encrypted AES key and the encrypted file
            original_file_path=file_path
            print(original_file_path)
            encrypted_file_path = file_path + ".enc"
            process_messages_write(f"  Saving Encrypted File as: {encrypted_file_path}\n")
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(iv + encrypted_key + encrypted_data)
            process_messages_write("  Encrypted File Saved Successfully.\n")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file_path}")
            os.remove(original_file_path)

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            print(traceback.format_exc())


# Function to select a file
def select_file():
    global file_path_var
    file_path = filedialog.askopenfilename(initialdir="/", title="Select a File")
    if file_path:
        file_path_var.set(file_path)  # Update the label or entry with the selected file path
        # enter path in entry box
        file_path_entry.delete(0, tk.END)  # Clear the entry box
        file_path_entry.insert(0, file_path)  # Insert the selected file path into the entry box

def process_messages_write(plaintext):
        received_textarea_2.config(state=tk.NORMAL)
        received_textarea_2.insert(tk.END, f"{plaintext}\n")
        received_textarea_2.config(state=tk.DISABLED)
        received_textarea_2.yview(tk.END)
            
# Create the main window
root = tk.Tk()

screen_width = 780
screen_height = 780
root.geometry(f"{screen_width}x{screen_height}")
root.resizable(False, True)

# Set the title of the window
title_text = "Cyber Security Trainer"
node_text = "Node 1: Digital Signature Encryptor"


# Create the title string with calculated spaces
title = f"{title_text}{'      '}{node_text}"
root.title(node_text)

# Create a frame for layout purposes
frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))


# Create a label to show the selected file path
file_path_var = tk.StringVar()

## entrybox for file path selected
file_path_entry = ttk.Entry(frame, textvariable=file_path_var, width=50)
file_path_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

# Create a button that opens the file selector
file_button = tk.Button(frame, text="Select File", command=select_file)
file_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)


# Create a button that Signs the file selector
sign_btn = tk.Button(frame, text="Encrypt File", command=encrypt_file)
sign_btn.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)


# Scrollbar

text_frame_2 = ttk.Frame(root)
text_frame_2.grid(row=2, column=0, padx=20, pady=20)

scrollbar2 = ttk.Scrollbar(text_frame_2, orient=tk.VERTICAL)
scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea_2 = tk.Text(text_frame_2, height=20, width=70, yscrollcommand=scrollbar2.set)
received_textarea_2.pack(fill=tk.BOTH, expand=True)
received_textarea_2.config(state=tk.DISABLED)

# Configure the scrollbar to work with the TextArea
scrollbar2.config(command=received_textarea_2.yview)

# Run the main event loop
root.mainloop()