"""Versioned AES-256-GCM envelope. A random key is stored only in deployment secrets."""
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC=b'VDRPT001'

def encrypt_payload(data,key_hex=None):
    key=bytes.fromhex(key_hex) if key_hex else AESGCM.generate_key(bit_length=256)
    if len(key)!=32:raise ValueError('Invalid encryption key')
    nonce=secrets.token_bytes(12)
    return MAGIC+nonce+AESGCM(key).encrypt(nonce,data,MAGIC),key.hex()

def decrypt_payload(envelope,key_hex):
    try:
        key=bytes.fromhex(key_hex)
        if len(key)!=32 or not envelope.startswith(MAGIC) or len(envelope)<36:raise ValueError('Invalid envelope')
        return AESGCM(key).decrypt(envelope[8:20],envelope[20:],MAGIC)
    except (InvalidTag,TypeError,ValueError) as exc:raise ValueError('Report authentication failed') from exc
