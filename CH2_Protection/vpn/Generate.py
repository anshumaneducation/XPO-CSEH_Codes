from cryptography.fernet import Fernet
import os

key = Fernet.generate_key()
with open('key.key', 'wb') as key_file:
    key_file.write(key)
print("Key generated and saved to 'key.key'")
