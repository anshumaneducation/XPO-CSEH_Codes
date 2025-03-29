import requests
import time
import os
import threading
import firebase_admin
from firebase_admin import credentials, db
import tkinter as tk
from tkinter import ttk, messagebox
import os
import smbus

def getvalue_adc():
	address = 0x4F
	bus = smbus.SMBus(1)
	try:	
		bus.write_byte(address,0x40)
		potentiometer_value = bus.read_byte(address)
		time.sleep(2)			
	except KeyboardInterrupt:
		print("exit")	
	return	potentiometer_value 
    
# File path
file_path = "/etc/encrypted_file.enc"

# Check if the encrypted file exists before opening the app
if not os.path.exists(file_path):
    exit()

user_id_get = "user1"
pass_w = "password"

## ADC Value i.e., values from PCF8591 get_values
get_values = 0
encryption_key = 42  # Choose a key (must be the same for encryption and decryption)

# Firebase initialization
script_directory = os.path.dirname(os.path.realpath(__file__))
services_json_path = os.path.join(script_directory, 'services.json')
cred = credentials.Certificate(services_json_path)
firebase_admin.initialize_app(cred, {'databaseURL': 'https://iot-cseh-default-rtdb.asia-southeast1.firebasedatabase.app/'})

# Locks and flags
internet_lock = threading.Lock()
stop_thread = threading.Event()  # Flag to signal threads to stop
is_internet_connected = False  # Initialize flag

def xor_encrypt(value, encryption_key):
    """Encrypts a string or integer using XOR and returns hex string."""
    text = str(value)  # Convert number to string if needed
    encrypted = ''.join(chr(ord(c) ^ encryption_key) for c in text)
    return encrypted.encode().hex()  # Convert to hexadecimal string

def xor_decrypt(encrypted_hex, encryption_key):
    """Decrypts a hex-encoded string using XOR."""
    encrypted_text = bytes.fromhex(encrypted_hex).decode()  # Convert hex back to text
    decrypted = ''.join(chr(ord(c) ^ encryption_key) for c in encrypted_text)
    return decrypted

# Function to check internet connectivity
def is_connected():
    global is_internet_connected
    url = 'http://www.google.com'
    timeout = 2
    try:
        response = requests.get(url, timeout=timeout)
        with internet_lock:
            is_internet_connected = True
        print("Internet Connected!")
        return True
    except (requests.ConnectionError, requests.Timeout):
        with internet_lock:
            is_internet_connected = False
        print("NO Internet Connection!")
        return False

# Thread to update Firebase values
def updating_db_values_thread():
    global is_internet_connected, get_values

    while not stop_thread.is_set():
        with internet_lock:
            if not is_internet_connected:
                break
        try:
            if is_internet_connected:
                
                encrypted_value = xor_encrypt(get_values, encryption_key)  # Encrypt the value
                user_node_ref.child('values').set(encrypted_value)

                decrypted_value = xor_decrypt(encrypted_value, encryption_key)
                decrypted_var.set(f"Data Received from ADC: {decrypted_value}")
                encrypted_var.set(f"Encrypted Data Uploaded: {encrypted_value}")
                # Simulate data change
                get_values = getvalue_adc()
        except Exception as e:
            print(f"Exception in thread: {e}")
        time.sleep(2)

# Initialize Firebase reference and start thread
def start_db_reference():
    global user_node_ref
    with internet_lock:
        if is_internet_connected:
            user_node_ref = db.reference(user_id_get)
            user_node_ref.child('cseh_password').set(pass_w)
            thread = threading.Thread(target=updating_db_values_thread, daemon=True)
            thread.start()
            return thread

# Delete Firebase node
def delete_db_node():
    global user_node_ref
    with internet_lock:
        if is_internet_connected:
            user_node_ref.delete()

# Tkinter GUI Setup
def start_uploading():
    global user_id_get, pass_w

    user_id_get = user_id_entry.get().strip()  # Remove leading/trailing spaces
    pass_w = password_entry.get().strip()

    if not user_id_get or not pass_w:  # Check if fields are empty
        messagebox.showerror("Error", "Username and Password cannot be empty")
        return

    # Disable User ID and Password entry boxes
    user_id_entry.config(state='disabled')
    password_entry.config(state='disabled')

    # Change Start Button text to indicate upload in progress
    start_button.config(text="Uploading to Cloud...", state='disabled')

    if not user_id_get or not pass_w:
        messagebox.showwarning("Input Error", "Please enter both User ID and Password.")

        # Re-enable entries and button if input is invalid
        user_id_entry.config(state='normal')
        password_entry.config(state='normal')
        start_button.config(text="Start Cloud Uploading", state='normal')
        return

    print(f"Starting cloud uploading procedure for User ID: {user_id_get}")
    is_connected()
    if is_internet_connected:
        start_db_reference()
        messagebox.showinfo("Success", "Cloud uploading started successfully.")
    else:
        messagebox.showerror("Internet Error", "No Internet connection. Please try again.")

        # Re-enable entries and button if internet check fails
        user_id_entry.config(state='normal')
        password_entry.config(state='normal')
        start_button.config(text="Start Cloud Uploading", state='normal')

def on_close():
    print("Exiting application...")
    stop_thread.set()

    if is_internet_connected:
        delete_db_node()

    print("Cleanup completed. Program exited successfully.")
    root.destroy()
    print("Application closed.")

root = tk.Tk()
root.title("IoT Cloud Security")
root.geometry("400x300")

# User ID label and entry
user_id_label = ttk.Label(root, text="User ID:")
user_id_label.pack(pady=5)
user_id_entry = ttk.Entry(root, width=30)
user_id_entry.pack(pady=5)

# Password label and entry
password_label = ttk.Label(root, text="Password:")
password_label.pack(pady=5)
password_entry = ttk.Entry(root, width=30, show="*")  # Hide password input
password_entry.pack(pady=5)

# Start Button
start_button = ttk.Button(root, text="Start Uploading", command=start_uploading)
start_button.pack(pady=20)

## Display original & encrypted values
# Create StringVar() for dynamic updates
decrypted_var = tk.StringVar()
encrypted_var = tk.StringVar()

# Create Labels with StringVar()
decrypted_show = ttk.Label(root, textvariable=decrypted_var)
decrypted_show.pack(pady=5)

encrypted_show = ttk.Label(root, textvariable=encrypted_var)
encrypted_show.pack(pady=5)
# Protocol for closing the window
root.protocol("WM_DELETE_WINDOW", on_close)

# Run the Tkinter event loop
root.mainloop()
                                                                                                              