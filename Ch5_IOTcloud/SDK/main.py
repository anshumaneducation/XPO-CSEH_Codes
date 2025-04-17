import requests
import time
import os
import threading
import firebase_admin
from firebase_admin import credentials, db
import tkinter as tk
from tkinter import ttk, messagebox
import smbus
import subprocess

# Encrypted file check
file_path = "/etc/encrypted_file.enc"
if not os.path.exists(file_path):
    exit()

user_id_get = "user1"
pass_w = "password"
get_values = 0
encryption_key = 42

# Firebase initialization
script_directory = os.path.dirname(os.path.realpath(__file__))
services_json_path = os.path.join(script_directory, 'services.json')
cred = credentials.Certificate(services_json_path)
firebase_admin.initialize_app(cred, {'databaseURL': 'https://iot-cseh-default-rtdb.asia-southeast1.firebasedatabase.app/'})

internet_lock = threading.Lock()
stop_thread = threading.Event()
is_internet_connected = False

# XOR encrypt/decrypt
def xor_encrypt(value, encryption_key):
    text = str(value)
    encrypted = ''.join(chr(ord(c) ^ encryption_key) for c in text)
    return encrypted.encode().hex()

def xor_decrypt(encrypted_hex, encryption_key):
    encrypted_text = bytes.fromhex(encrypted_hex).decode()
    decrypted = ''.join(chr(ord(c) ^ encryption_key) for c in encrypted_text)
    return decrypted

# Internet check
def is_connected():
    global is_internet_connected
    try:
        requests.get("http://www.google.com", timeout=2)
        with internet_lock:
            is_internet_connected = True
        return True
    except:
        with internet_lock:
            is_internet_connected = False
        return False

# Check if i2c module is loaded
def is_i2c_module_loaded():
    try:
        result = subprocess.run(['lsmod'], stdout=subprocess.PIPE, text=True)
        return 'i2c_bcm2835' in result.stdout or 'i2c_dev' in result.stdout
    except Exception:
        return False

# Read ADC value
def getvalue_adc(i2c_address):
    bus = smbus.SMBus(1)
    try:
        bus.write_byte(i2c_address, 0x40)
        value = bus.read_byte(i2c_address)
        return value
    except Exception as e:
        error_var.set(f"I2C read failed hardware connection: {e}")
        return None

# Firebase thread
def updating_db_values_thread():
    global get_values

    while not stop_thread.is_set():
        with internet_lock:
            if not is_internet_connected:
                break

        try:
            address_str = i2c_entry.get().strip()
            try:
                i2c_address = int(address_str, 16)
                if not (0x03 <= i2c_address <= 0x77):
                    error_var.set("Invalid I2C address (must be 0x03–0x77).")
                    continue
                error_var.set("")
            except ValueError:
                error_var.set("Invalid I2C address format.")
                continue

            adc_value = getvalue_adc(i2c_address)
            if adc_value is None:
                continue

            get_values = adc_value
            encrypted_value = xor_encrypt(get_values, encryption_key)
            user_node_ref.child('values').set(encrypted_value)

            decrypted_value = xor_decrypt(encrypted_value, encryption_key)
            decrypted_var.set(f"ADC: {decrypted_value}")
            encrypted_var.set(f"Encrypted: {encrypted_value}")
        except Exception as e:
            error_var.set(f"Unexpected error: {e}")
        time.sleep(2)

def start_db_reference():
    global user_node_ref
    with internet_lock:
        if is_internet_connected:
            user_node_ref = db.reference(user_id_get)
            user_node_ref.child('cseh_password').set(pass_w)
            thread = threading.Thread(target=updating_db_values_thread, daemon=True)
            thread.start()

def delete_db_node():
    global user_node_ref
    with internet_lock:
        if is_internet_connected:
            user_node_ref.delete()

# GUI action
def start_uploading():
    global user_id_get, pass_w

    user_id_get = user_id_entry.get().strip()
    pass_w = password_entry.get().strip()

    if not user_id_get or not pass_w:
        error_var.set("Username and password required.")
        return

    if not is_i2c_module_loaded():
        error_var.set("I2C modules not loaded. Try 'sudo modprobe i2c-dev i2c-bcm2835'.")
        return

    user_id_entry.config(state='disabled')
    password_entry.config(state='disabled')
    i2c_entry.config(state='disabled')
    start_button.config(text="Uploading...", state='disabled')

    if is_connected():
        error_var.set("")
        start_db_reference()
        messagebox.showinfo("Started", "Uploading to Firebase started.")
    else:
        error_var.set("No Internet connection.")
        user_id_entry.config(state='normal')
        password_entry.config(state='normal')
        i2c_entry.config(state='normal')
        start_button.config(text="Start Uploading", state='normal')

def on_close():
    stop_thread.set()
    if is_internet_connected:
        delete_db_node()
    root.destroy()

# Tkinter GUI
root = tk.Tk()
root.title("IoT Cloud Security")
root.geometry("450x450")

ttk.Label(root, text="User ID:").pack(pady=5)
user_id_entry = ttk.Entry(root, width=30)
user_id_entry.pack(pady=5)

ttk.Label(root, text="Password:").pack(pady=5)
password_entry = ttk.Entry(root, width=30, show="*")
password_entry.pack(pady=5)

ttk.Label(root, text="I2C Address (Hex):").pack(pady=5)
i2c_entry = ttk.Entry(root, width=10)
i2c_entry.insert(0, "0x4F")
i2c_entry.pack(pady=5)

error_var = tk.StringVar()
ttk.Label(root, textvariable=error_var, foreground='red').pack()

start_button = ttk.Button(root, text="Start Uploading", command=start_uploading)
start_button.pack(pady=15)

decrypted_var = tk.StringVar()
encrypted_var = tk.StringVar()
ttk.Label(root, textvariable=decrypted_var).pack(pady=5)
ttk.Label(root, textvariable=encrypted_var).pack(pady=5)

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
