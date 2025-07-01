import tkinter as tk
from tkinter import ttk
import os
import hashlib
import binascii


# Path to store the keys (relative to script location)
path_to_keys =  "DSAkeys.txt"
# File path for validation
file_path = "/etc/encrypted_file.enc"

# # Check if the encrypted file exists before opening the app
if not os.path.exists(file_path):
    exit()

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

    print(f"  🔐 SHA-256 Digest: {final_hash}")

    return final_hash

def process_messages_write(plaintext):
        received_textarea_2.config(state=tk.NORMAL)
        received_textarea_2.insert(tk.END, f"{plaintext}\n")
        received_textarea_2.config(state=tk.DISABLED)
        received_textarea_2.yview(tk.END)

# Function to save the keys to a file
def save_keys():
    key1 = key1_entry.get()
    key2 = key2_entry.get()
    
    # Ensure both keys are provided
    if not key1 or not key2:
        status_label.config(text="Please enter both keys.", foreground="red")
        return
    
    # Hash the values of keys
    # key1_hash = hashlib.md5(key1.encode()).hexdigest()
    # key2_hash = hashlib.md5(key2.encode()).hexdigest()

    key1_hash = custom_hash(key1)
    key2_hash = custom_hash(key2)
    
    # Save the hashed keys to the file
    try:
        with open(path_to_keys, "w") as file:
            file.write(f"Key 1: {key1_hash}\n")
            file.write(f"Key 2: {key2_hash}\n")
        status_label.config(text="Keys saved successfully!", foreground="green")
    except Exception as e:
        status_label.config(text=f"Error saving keys: {e}", foreground="red")

# Create the main Tkinter window
root = tk.Tk()
root.title("Key Storage GUI")
root.geometry("720x600")

# Key 1 label and entry
key1_label = ttk.Label(root, text="Encryptor Software Key:")
key1_label.pack(pady=5)
key1_entry = ttk.Entry(root, width=30)
key1_entry.pack(pady=5)

# Key 2 label and entry
key2_label = ttk.Label(root, text="Decryptor Software Key:")
key2_label.pack(pady=5)
key2_entry = ttk.Entry(root, width=30)
key2_entry.pack(pady=5)

# Save button
save_button = ttk.Button(root, text="Save Keys", command=save_keys)
save_button.pack(pady=10)

# Status label
status_label = ttk.Label(root, text="", font=("Arial", 10))
status_label.pack(pady=5)

# Scrollbar

text_frame_2 = ttk.Frame(root)
text_frame_2.pack(pady=5)

scrollbar2 = ttk.Scrollbar(text_frame_2, orient=tk.VERTICAL)
scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea_2 = tk.Text(text_frame_2, height=10, width=70, yscrollcommand=scrollbar2.set)
received_textarea_2.pack(fill=tk.BOTH, expand=True)
received_textarea_2.config(state=tk.DISABLED)

# Configure the scrollbar to work with the TextArea
scrollbar2.config(command=received_textarea_2.yview)

# Run the Tkinter event loop
root.mainloop()
