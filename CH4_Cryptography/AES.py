from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(plaintext: str, key ) -> str:
    key=key.encode()
    iv = get_random_bytes(16)  # AES block size is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encoded_ciphertext: str, key) -> str:
    key=key.encode()
    ciphertext = base64.b64decode(encoded_ciphertext)
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()