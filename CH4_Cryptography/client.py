## Receiver Node for CSEH Trainer

import tkinter as tk
from tkinter import ttk, filedialog
import socket
import threading
import hashlib
import subprocess
import random
import re  # Added for regex
import random
import base64
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
from Crypto.Cipher import AES


def aes_encrypt(plaintext: str, key ) -> str:
    key=key.encode()
    iv = get_random_bytes(16)  # AES block size is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encoded_ciphertext: str, key) -> str:
    process_messages_write("Decrypting ciphertext: " + encoded_ciphertext)
    # Convert key to bytes if it is a string

    key=key.encode()
    process_messages_write("Key is a string, converting to bytes.")
    ciphertext = base64.b64decode(encoded_ciphertext)
    process_messages_write("Decoded ciphertext: " + str(ciphertext))
    iv = ciphertext[:16]
    process_messages_write("IV extracted: " + str(iv))
    actual_ciphertext = ciphertext[16:]
    process_messages_write("Actual ciphertext: " + str(actual_ciphertext))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    process_messages_write("Cipher object created with key: " + str(key))
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    process_messages_write("Padded text after decryption: " + str(padded_plaintext))
    plaintext = unpad(padded_plaintext, AES.block_size)
    process_messages_write("Unpadded plaintext: " + str(plaintext))
    # Return the plaintext as a string
    process_messages_write("Decrypted plaintext: " + plaintext.decode())
    return plaintext.decode()

def tdes_encrypt(plaintext, key):
    # Convert key to bytes if it is a string
    if isinstance(key, str):
        key = key.encode()

    # Ensure the key length is 24 bytes (192 bits) for 3DES
    if len(key) != 24:
        raise ValueError("Key must be 24 bytes long")

    # Generate a random IV (initialization vector)
    iv = get_random_bytes(8)

    # Create a Triple DES cipher object
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of the block size (8 bytes)
    padded_text = pad(plaintext.encode(), DES3.block_size)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(padded_text)

    # Return the IV and ciphertext, encoded as base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def tdes_decrypt(ciphertext, key):
    # Convert key to bytes if it is a string
    process_messages_write("Decrypting ciphertext: " + ciphertext)
    if isinstance(key, str):
        key = key.encode()
        process_messages_write("Key is a string, converting to bytes.")

    # Ensure the key length is 24 bytes (192 bits) for 3DES
    if len(key) != 24:
        raise ValueError("Key must be 24 bytes long")
    process_messages_write("Key length is valid: " + str(len(key)))

    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    process_messages_write("Decoded ciphertext: " + str(ciphertext))

    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:8]
    process_messages_write("IV extracted: " + str(iv))
    actual_ciphertext = ciphertext[8:]
    process_messages_write("Actual ciphertext: " + str(actual_ciphertext))

    # Create a Triple DES cipher object
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    process_messages_write("Cipher object created with key: " + str(key))

    # Decrypt the ciphertext
    padded_text = cipher.decrypt(actual_ciphertext)
    process_messages_write("Padded text after decryption: " + str(padded_text))

    # Unpad the plaintext
    plaintext = unpad(padded_text, DES3.block_size)
    process_messages_write("Unpadded plaintext: " + str(plaintext))
    # Return the plaintext as a string
    process_messages_write("Decrypted plaintext: " + plaintext.decode())

    return plaintext.decode()



P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # Permutation P10
P8 = [6, 3, 7, 4, 8, 5, 10, 9]        # Permutation P8
P4 = [2, 4, 3, 1]                      # Permutation P4

IP = [2, 6, 3, 1, 4, 8, 5, 7]          # Initial Permutation IP
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]      # Inverse Initial Permutation IP^(-1)

EP = [4, 1, 2, 3, 2, 3, 4, 1]          # Expansion Permutation EP

S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]                     # S-Box S0

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]                     # S-Box S1

def permutate(original, permutation):
    """Permute the bits according to the given permutation."""
    return [original[i - 1] for i in permutation]

def left_shift(bits, shifts):
    """Left shift the bits by the specified number of shifts."""
    return bits[shifts:] + bits[:shifts]

def xor(bits1, bits2):
    """Perform bitwise XOR between two bit lists."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def sbox_lookup(bits, sbox):
    """Lookup the value in the specified S-Box."""
    row = (bits[0] << 1) | bits[3]
    col = (bits[1] << 1) | bits[2]
    return [int(x) for x in format(sbox[row][col], '02b')]

def generate_keys(key):
    """Generate the two subkeys from the main key."""
    key = permutate(key, P10)
    left, right = key[:5], key[5:]
    
    left = left_shift(left, 1)
    right = left_shift(right, 1)
    k1 = permutate(left + right, P8)
    
    left = left_shift(left, 2)
    right = left_shift(right, 2)
    k2 = permutate(left + right, P8)
    
    return k1, k2

def fk(bits, key):
    """Feistel function used in the encryption and decryption."""
    left, right = bits[:4], bits[4:]
    temp = permutate(right, EP)
    temp = xor(temp, key)
    left_half = sbox_lookup(temp[:4], S0)
    right_half = sbox_lookup(temp[4:], S1)
    temp = permutate(left_half + right_half, P4)
    return xor(left, temp) + right

def sdes_encrypt_block(block, k1, k2):
    """Encrypt an 8-bit block using the two subkeys."""
    bits = permutate(block, IP)
    bits = fk(bits, k1)
    bits = bits[4:] + bits[:4]  # Switch the left and right halves
    bits = fk(bits, k2)
    ciphertext = permutate(bits, IP_INV)
    return ciphertext

def sdes_decrypt_block(block, k1, k2):
    """Decrypt an 8-bit block using the two subkeys."""
    process_messages_write("Decrypting block: " + str(block))

    bits = permutate(block, IP)
    process_messages_write("After Initial Permutation (IP): " + str(bits))

    bits = fk(bits, k2)
    process_messages_write("After first fk with k2: " + str(bits))

    bits = bits[4:] + bits[:4]  # Switch the left and right halves
    process_messages_write("After switching halves: " + str(bits))

    bits = fk(bits, k1)
    process_messages_write("After second fk with k1: " + str(bits))

    plaintext = permutate(bits, IP_INV)
    process_messages_write("After Inverse Initial Permutation (IP^-1): " + str(plaintext))

    return plaintext

def string_to_bits(s):
    """Convert a string to a list of bits."""
    return [int(bit) for char in s for bit in format(ord(char), '08b')]

def bits_to_string(bits):
    """Convert a list of bits to a string."""
    return ''.join(chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits), 8))

def sdes_encrypt(plaintext, key):
    """Encrypt a plaintext string using the given key."""
    key_bits = string_to_bits(key)
    plaintext_bits = string_to_bits(plaintext)
    k1, k2 = generate_keys(key_bits[:10])

    ciphertext_bits = []
    for i in range(0, len(plaintext_bits), 8):
        block = plaintext_bits[i:i+8]
        if len(block) < 8:
            block += [0] * (8 - len(block))
        ciphertext_bits.extend(sdes_encrypt_block(block, k1, k2))
    return bits_to_string(ciphertext_bits)

def sdes_decrypt(ciphertext, key):
    """Decrypt a ciphertext string using the given key."""
    key_bits = string_to_bits(key)
    ciphertext_bits = string_to_bits(ciphertext)
    k1, k2 = generate_keys(key_bits[:10])

    plaintext_bits = []
    for i in range(0, len(ciphertext_bits), 8):
        block = ciphertext_bits[i:i+8]
        plaintext_bits.extend(sdes_decrypt_block(block, k1, k2))
    return bits_to_string(plaintext_bits)




e = 8009
d = 10609
n = 14017

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_large_prime():
    while True:
        p = random.randrange(100, 500)
        if is_prime(p):
            return p

def generate_keypair():
    p = generate_large_prime()
    q = generate_large_prime()
    n = p * q
    phi_n = (p - 1) * (q - 1)

    while True:
        e = random.randrange(1, phi_n)
        if gcd(e, phi_n) == 1:
            break

    d = mod_inverse(e, phi_n)
    return ((e, n), (d, n))

def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    # Convert list of integers to a comma-separated string
    ciphertext_str = ','.join(map(str, ciphertext))
    return ciphertext_str

def rsa_decrypt(ciphertext, private_key):
    process_messages_write("Decrypting ciphertext: " + ciphertext)
    # Convert the private key to integers
    d, n = private_key
    process_messages_write("Private key: d=" + str(d) + ", n=" + str(n))
    # Convert the comma-separated string back to a list of integers
    ciphertext_list = list(map(int, ciphertext.split(',')))
    process_messages_write("Ciphertext list: " + str(ciphertext_list))
    plaintext = [chr(pow(char, d, n)) for char in ciphertext_list]
    process_messages_write("Decrypted characters: " + str(plaintext))
    # Join the characters to form the plaintext string
    process_messages_write("Decrypted plaintext: " + ''.join(plaintext))
    return ''.join(plaintext)

client_socket = None


def RC4(message, key):
    global string_out
    S = list(range(256))
    j = 0
    out = []
    # Key Scheduling Algorithm (KSA)
    process_messages_write("Starting Key Scheduling Algorithm (KSA)...")
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
        
    process_messages_write("Key Scheduling Algorithm (KSA) completed.")
    process_messages_write(f"Initial S: {S}")
    # Initialize i and j for the Pseudorandom Generation Algorithm (PRGA)
    process_messages_write("Starting Pseudorandom Generation Algorithm (PRGA)...")
    # Initialize i and j for the Pseudorandom Generation Algorithm (PRGA)

    # Pseudorandom Generation Algorithm (PRGA)
    i = j = 0
    for char in message:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(chr(ord(char) ^ K))

    process_messages_write("Pseudorandom Generation Algorithm (PRGA) completed.")
    process_messages_write(f"Final S: {S}")
    process_messages_write(f"Output: {''.join(out)}")
    return ''.join(out)


# Function to validate IP address
def is_valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern, ip)

def received_Messages(ciphertext):
    client_socket.sendall("RECV".encode('utf-8'))
    hash_and_message = ciphertext.split('|')
    process_messages_write("Received message: " + ciphertext)
    process_messages_write("Split message: " + str(hash_and_message))
    received_hash = hash_and_message[0]
    process_messages_write("Received Algorithm Hash Value: " + received_hash)
    
    
    received_key_hash = hash_and_message[1]
    process_messages_write("Received Key Hash Value: " + received_key_hash)
    
    encrypted_message = hash_and_message[2]
    process_messages_write("Encrypted Message to Decrypt: " + encrypted_message)


    # Calculate MD5 hashes for each algorithm
    hash_rc4 = hashlib.md5(b'RC4').hexdigest()
    hash_RSA = hashlib.md5(b'RSA').hexdigest()
    hash_sDES = hashlib.md5(b'sDES').hexdigest()
    hash_TDES = hashlib.md5(b'TDES').hexdigest()
    hash_AES = hashlib.md5(b'AES').hexdigest()

    # Compare received hash with computed hashes to identify the algorithm
    if received_hash == hash_rc4:
        identified_algorithm = 'RC4'
    elif received_hash == hash_RSA:
        identified_algorithm = 'RSA'
    elif received_hash == hash_sDES:
        identified_algorithm = 'sDES'
    elif received_hash == hash_TDES:
        identified_algorithm = 'TDES'
    elif received_hash == hash_AES:
        identified_algorithm = 'AES'
    else:
        identified_algorithm = 'Unknown'

    process_messages_write("Identified Algorithm: " + identified_algorithm)

    key = "123456789012345678901234"
    md5_key_hash = hashlib.md5(key.encode()).hexdigest()

    plaintext = ""

    if md5_key_hash == received_key_hash:
        key = "123456789012345678901234"
    private_key = (10609, 14017)
    process_messages_write("Identified Key Value: " + received_key_hash)

    if identified_algorithm == "RC4":
        process_messages_algorithm("Steps for RC4: ")
        process_messages_algorithm("1. Key Scheduling Algorithm (KSA)  : Key=  123456789012345678901234")
        process_messages_algorithm("Initializes the permutation in array S based on the key.")
        process_messages_algorithm("Fills S with values 0–255, then shuffles using the key.")
        process_messages_algorithm("2. Pseudorandom Generation Algorithm (PRGA)")
        process_messages_algorithm("Uses S to generate a keystream.")
        process_messages_algorithm("XORs keystream with ciphertext/plaintext to produce output.")

        process_messages_write("Performing RC4: ")
        plaintext = RC4(encrypted_message, key)


    if identified_algorithm == "sDES":
        process_messages_algorithm("Steps for SDES: ")
        process_messages_algorithm("Initial Permutation (IP)")
        process_messages_algorithm("Public 24 bit Key use: 123456789012345678901234")
        process_messages_algorithm("fk using k2")
        process_messages_algorithm("Swap (Switch halves)")
        process_messages_algorithm("fk using k1")
        process_messages_algorithm("Inverse IP (IP⁻¹)")

        process_messages_write("Performing sDES: ")
        plaintext = sdes_decrypt(encrypted_message, key)
        

    if identified_algorithm == "TDES":
        process_messages_algorithm("Steps for TDES: ")
        process_messages_algorithm("1. Base64 Input")
        process_messages_algorithm("This is typical for encrypted data that's been Base64-encoded.")
        process_messages_algorithm("2. Key Handling : 123456789012345678901234")
        process_messages_algorithm("Triple DES expects a 24-byte key (3 DES keys of 8 bytes each")
        process_messages_algorithm("3. Base64 Decode")
        process_messages_algorithm("TDES commonly uses CBC mode, which requires:First 8 bytes → IV:Remaining 8 bytes → Actual ciphertext")
        process_messages_algorithm("4. Decryption")
        process_messages_algorithm("Decrypted output:  (\x06 repeated), meaning 6 bytes of padding were added., After removing padding we get the original plaintext.")

        process_messages_write("Performing TDES: ")
        plaintext = tdes_decrypt(encrypted_message, key)


    if identified_algorithm == "RSA":
        process_messages_algorithm("Steps for RSA: ")
        process_messages_algorithm("1. Input: Ciphertext")
        process_messages_algorithm("2. Use private key: d = 10609, n = 14017")
        process_messages_algorithm("3. Decrypt each integer:	m = (c^d) mod n")
        process_messages_algorithm("4. Convert each decrypted integer to ASCII character")
        process_messages_algorithm("5. Result")

        process_messages_write("Performing RSA: ")
        plaintext = rsa_decrypt(encrypted_message, private_key)


    if identified_algorithm == "AES":
        process_messages_algorithm("Steps for AES: ")
        process_messages_algorithm("1. Base64 Decode")
        process_messages_algorithm("Operation: Decode it from Base64 to get raw bytes")
        process_messages_algorithm("2. Extract Initialization Vector (IV)")
        process_messages_algorithm("AES block size = 16 bytes, so first 16 bytes are the IV")
        process_messages_algorithm("3. Extract Ciphertext")
        process_messages_algorithm("The remaining bytes after the IV are the actual ciphertext")
        process_messages_algorithm("4. Prepare AES-192 key  : 123456789012345678901234")
        process_messages_algorithm("24-byte key (from string)")
        process_messages_algorithm("5. Create cipher")
        process_messages_algorithm("AES-192 in CBC mode with key + IV")
        process_messages_algorithm("6. Decrypt ciphertext")
        process_messages_algorithm("Produces padded plaintext")
        process_messages_algorithm("7. Remove PKCS#7 padding")
        process_messages_algorithm("Get the original plaintext")
        process_messages_algorithm("8. Convert to string")
        process_messages_algorithm("Final output")

        process_messages_write("Performing AES: ")
        plaintext = aes_decrypt(encrypted_message, key)


    process_messages_write("Decrypted Message: " + plaintext)

    client_socket.sendall("OK".encode('utf-8'))
    return plaintext


def receive_messages():
    while True:
        try:
            message_received = client_socket.recv(1024).decode('utf-8')
            
            plaintext = received_Messages(message_received)
            if plaintext:
                received_textarea.config(state=tk.NORMAL)
                received_textarea.insert(tk.END, f"{plaintext}\n")
                received_textarea.config(state=tk.DISABLED)
                received_textarea.yview(tk.END)
                client_socket.sendall("OK".encode('utf-8'))
            else:
                break
        except:
            break

def process_messages_write(plaintext):
        received_textarea_2.config(state=tk.NORMAL)
        received_textarea_2.insert(tk.END, f"{plaintext}\n")
        received_textarea_2.config(state=tk.DISABLED)
        received_textarea_2.yview(tk.END)
        time.sleep(1)

def process_messages_algorithm(plaintext):
        received_textarea_3.config(state=tk.NORMAL)
        received_textarea_3.insert(tk.END, f"{plaintext}\n")
        received_textarea_3.config(state=tk.DISABLED)
        received_textarea_3.yview(tk.END)
        


def on_button_click_connect():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = ip_address_server_entry.get()  # Get the server IP from the entry box

    if not is_valid_ip(server_ip):
        return

    port = 8080
    try:
        client_socket.connect((server_ip, port))
        threading.Thread(target=receive_messages, daemon=True).start()

        # Change button text to "Connected" and disable it
        button.config(text="Connected", state=tk.DISABLED)

    except Exception as e:
        print(f"Error: {e}")


# Create the main window
root = tk.Tk()
root.title(f"Cyber Security Receiver")
screen_width = 780
screen_height = 780
root.geometry(f"{screen_width}x{screen_height}")
root.resizable(False, True)

# Create a frame for layout purposes
frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

# Connect to server
connect_label = ttk.Label(frame, text="Connect to server: ")
connect_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

# Entry box for IP address
ip_address_server_entry = ttk.Entry(frame)
ip_address_server_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

# Button for starting connection
button = ttk.Button(frame, text="Connect", command=on_button_click_connect)
button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)


# Label for received messages
received_label_2 = ttk.Label(frame, text="Received messages Computation:")
received_label_2.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

# Create a frame for the TextArea and its scrollbar
text_frame_2 = ttk.Frame(frame)
text_frame_2.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky=(tk.W, tk.E))

# Scrollbar
scrollbar2 = ttk.Scrollbar(text_frame_2, orient=tk.VERTICAL)
scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea_2 = tk.Text(text_frame_2, height=15, width=80, yscrollcommand=scrollbar2.set)
received_textarea_2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
received_textarea_2.config(state=tk.DISABLED)

# Configure the scrollbar to work with the TextArea
scrollbar2.config(command=received_textarea_2.yview)

# Label for received messages
received_label_3 = ttk.Label(frame, text="Identified Algorithm Steps:")
received_label_3.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
# Create a frame for the TextArea and its scrollbar
text_frame_3 = ttk.Frame(frame)
text_frame_3.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky=(tk.W, tk.E))

# Scrollbar
scrollbar3 = ttk.Scrollbar(text_frame_3, orient=tk.VERTICAL)
scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea_3 = tk.Text(text_frame_3, height=10, width=80, yscrollcommand=scrollbar3.set)
received_textarea_3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
received_textarea_3.config(state=tk.DISABLED)

# Label for received messages
received_label = ttk.Label(frame, text="Received messages from server:")
received_label.grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)

# Create a frame for the TextArea and its scrollbar
text_frame = ttk.Frame(frame)
text_frame.grid(row=7, column=0, columnspan=3, padx=5, pady=5, sticky=(tk.W, tk.E))

# Scrollbar
scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# TextArea for received messages
received_textarea = tk.Text(text_frame, height=5, width=80, yscrollcommand=scrollbar.set)
received_textarea.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
received_textarea.config(state=tk.DISABLED)

# Configure the scrollbar to work with the TextArea
scrollbar.config(command=received_textarea.yview)

# Run the main event loop
root.mainloop()
