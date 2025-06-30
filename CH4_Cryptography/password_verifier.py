import tkinter as tk
from tkinter import ttk
import hashlib
import os
import importlib

# Path to the keys file (relative path)
path_to_keys = "DSAkeys.txt"

# Variables for hashed passwords
encryptor_pass = None
decryptor_pass = None

def custom_hash(input_string):
    process_messages_write("🔍 Starting Hashing Process...\n")
    
    process_messages_write("🔤 Original String:\n")

    process_messages_write(f"  {input_string}\n")


    process_messages_write("📦 Step 1: Convert to Bytes (UTF-8 Encoding):\n")

    byte_data = input_string.encode()

    process_messages_write(f"  {byte_data}\n")


    process_messages_write("  Converting byte data to bit stream:\n")

    bit_stream = ''.join(format(byte, '08b') for byte in byte_data)
    process_messages_write(f"  {bit_stream[:64]}... ({len(bit_stream)} bits)\n")


    process_messages_write("🧵 Step 3: Padding Applied (as per SHA-256 rules).\n")

    # Simulate padding (not exact implementation)
    padded_bit_length = len(bit_stream) + 1 + 64
    padding_needed = (512 - padded_bit_length % 512) % 512
    total_length = len(bit_stream) + 1 + padding_needed + 64

    process_messages_write(f"  Original Length: {len(bit_stream)} bits\n")


    process_messages_write(f"  Padding: 1 + {padding_needed} zeros + 64-bit length\n")

    process_messages_write(f"  Final Padded Length: {total_length} bits\n")


    process_messages_write("  🧩 Step 4: Split into 512-bit Chunks (only 1 for small input):\n")


    process_messages_write(f"  1 Chunk: {total_length // 512} block(s)\n")


    process_messages_write("🔁 Step 5: Process with SHA-256 Compression Function (Hidden Complexity)\n")


    process_messages_write("  ➤ 64 rounds using functions like Σ₀, Σ₁, Ch, Maj, etc.\n")


    process_messages_write("✅ Final Step: SHA-256 Hash Output\n")

    hash_object = hashlib.sha256(byte_data)
    process_messages_write("  Hashing complete.\n")

    process_messages_write("  🔐 SHA-256 Digest:\n")

    final_hash = hash_object.hexdigest()
    process_messages_write(f"  {final_hash}\n")

    process_messages_write("🔚 Hashing Process Completed.\n")


    return final_hash

# Function to load hashed keys from the file
def load_keys():
    global encryptor_pass, decryptor_pass
    try:
        with open(path_to_keys, "r") as file:
            lines = file.readlines()
            if len(lines) < 2:
                print("Error: Keys file must have at least two hashed keys.")
                process_messages_write("Error: Keys file must have at least two hashed keys.")
                return False
            # Extract hashed keys
            encryptor_pass = lines[0].split(":")[1].strip()
            decryptor_pass = lines[1].split(":")[1].strip()
        return True
    except FileNotFoundError:
        print(f"Error: Keys file '{path_to_keys}' not found.")
        process_messages_write("Error: Keys file")
        return False
    except Exception as e:
        print(f"Error loading keys: {e}")
        process_messages_write("Error loading keys")
        return False

# Function to check password and load the appropriate module
def check_password():
    if not load_keys():
        return
    
    password = textarea.get()
    process_messages_write(f"Convert Input Password to hash {password}")
    input_pass = custom_hash(password)
    
    if input_pass == encryptor_pass:
        try:
            process_messages_write("Input pasword matched with encryptor software password")
            import digital_signer
            print("Digital Signer module loaded successfully.")
        except ImportError:
            print("Error: Unable to load 'digital_signer' module.")
    elif input_pass == decryptor_pass:
        try:
            process_messages_write("Input pasword matched with decrytor software password")
            import digital_verifier
            print("Digital Verifier module loaded successfully.")

        except ImportError:
            print("Error: Unable to load 'digital_verifier' module.")
    else:
        print("Error: Invalid password.")

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
node_text = "Input Password to Enter"
root.title(node_text)

# Create a frame for layout purposes
frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Input field for the password
textarea = tk.Entry(frame, show="*")  # Hide password input
textarea.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

# Create a button that checks the password
pass_button = tk.Button(frame, text="Check", command=check_password)
pass_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

# Scrollbar

text_frame_2 = ttk.Frame(root)
text_frame_2.grid(row=1, column=0, padx=5, pady=5)

scrollbar2 = ttk.Scrollbar(text_frame_2, orient=tk.VERTICAL)
scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea_2 = tk.Text(text_frame_2, height=10, width=70, yscrollcommand=scrollbar2.set)
received_textarea_2.pack(fill=tk.BOTH, expand=True)
received_textarea_2.config(state=tk.DISABLED)

# Configure the scrollbar to work with the TextArea
scrollbar2.config(command=received_textarea_2.yview)

# Run the main event loop
root.mainloop()
