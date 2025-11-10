import base64
from Crypto.Cipher import AES

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt_b64(key32: bytes, text: str) -> str:
    cipher = AES.new(key32, AES.MODE_ECB)
    padded = pkcs7_pad(text.encode('utf-8'))
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('ascii')

def aes_decrypt_b64(key32: bytes, b64_text: str) -> str:
    cipher = AES.new(key32, AES.MODE_ECB)
    encrypted = base64.b64decode(b64_text.encode('ascii'))
    decrypted = cipher.decrypt(encrypted)
    return pkcs7_unpad(decrypted).decode('utf-8')
