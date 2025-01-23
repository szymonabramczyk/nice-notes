import base64
import hashlib

from Crypto.Cipher import AES

from .. import Config


def encrypt(plaintext, encryption_key):
    key = hashlib.sha256(encryption_key.encode()).digest()
    aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)
    return ciphertext, tag, aes.nonce


def decrypt(content, key, nonce, tag):
    key = hashlib.sha256(key.encode()).digest()
    aes = AES.new(key, AES.MODE_GCM, nonce)
    return aes.decrypt_and_verify(content, tag)


def decrypt_secret(encrypted_key):
    try:
        key = hashlib.sha256(Config.SECRET_KEY.encode()).digest()
        data = base64.b64decode(encrypted_key)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

