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

private_key_path="private_key.pem"
# digital encryptor generator

def decrypt_file():
        global private_key_path
        process_messages_write("🔓 Starting Decryption Process...\n")
        file_path=file_path_var.get()
        process_messages_write("  Selected File: " + file_path + "\n")
        if not file_path:
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return

        if not file_path.endswith(".enc"):
            messagebox.showerror("Error", "Selected file is not an encrypted file.")
            return

        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            process_messages_write("🔑 Private Key Loaded Successfully.\n")
            process_messages_write("  Private Key Path: " + private_key_path + "\n")
            process_messages_write("🔐 Decrypting File...\n")
            with open(file_path, "rb") as encrypted_file:
                iv = encrypted_file.read(16)
                encrypted_key = encrypted_file.read(256)
                encrypted_data = encrypted_file.read()
            process_messages_write("  Encrypted File Read Successfully.\n")
            process_messages_write(f"  IV Length: {len(iv)} bytes\n")
            process_messages_write(f"  Encrypted Key Length: {len(encrypted_key)} bytes\n")
            process_messages_write(f"  Encrypted Data Length: {len(encrypted_data)} bytes\n")
            process_messages_write("🔑 Decrypting AES Key...\n")

            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            process_messages_write("  AES Key Decrypted Successfully.\n")
            process_messages_write("  AES Key Length: " + str(len(aes_key) * 8) + " bits\n")
            process_messages_write("  AES Key (hex): " + aes_key.hex() + "\n")
            process_messages_write("🔐 Decrypting File Data with AES...\n")
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            process_messages_write("  AES Cipher Created.\n")
            process_messages_write("  Decryptor Created.\n")
            process_messages_write("  Decrypting Data...\n")
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            process_messages_write("  Data Decrypted Successfully.\n")
            process_messages_write(f"  Decrypted Padded Data Size: {len(decrypted_padded_data)} bytes\n")
            process_messages_write("  Unpadding Decrypted Data...\n")
            # Unpad the decrypted data
            process_messages_write("  Unpadder Created.\n")

            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            process_messages_write("  Data Unpadded Successfully.\n")
            process_messages_write(f"  Decrypted Data Size: {len(decrypted_data)} bytes\n")
            process_messages_write("🔓 Decryption Completed Successfully.\n")
            encrypted_file_path=file_path
            process_messages_write("  Encrypted File Path: " + encrypted_file_path + "\n")
            # Save the decrypted data to a new file
            process_messages_write("  Saving Decrypted File...\n")
            process_messages_write("  Decrypted File Path: " + encrypted_file_path.rstrip(".enc") + "\n")
            process_messages_write("  Decrypted File Name: " + os.path.basename(encrypted_file_path.rstrip(".enc")) + "\n")
            process_messages_write("  Decrypted File Extension: " + os.path.splitext(encrypted_file_path)[1] + "\n")
            process_messages_write("  Decrypted File Size: " + str(len(decrypted_data)) + " bytes\n")
            print(encrypted_file_path)
            decrypted_file_path = file_path.rstrip(".enc")
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)
            process_messages_write("  Decrypted File Saved Successfully.\n")
            process_messages_write(f"  Decrypted File Path: {decrypted_file_path}\n")
            process_messages_write("🔓 Decryption Process Completed Successfully.\n")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_file_path}")
            os.remove(encrypted_file_path)

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            print(traceback.format_exc())



# Function to select a file
def select_file():
    file_path = filedialog.askopenfilename(initialdir="/", title="Select a File")
    if file_path:
        file_path_var.set(file_path)  
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
node_text = "Node 1: Digital Signature Decryptor"


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
sign_btn = tk.Button(frame, text="Decrypt File", command=decrypt_file)
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