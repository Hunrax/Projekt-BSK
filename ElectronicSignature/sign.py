from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
import wmi
import base64

def sign_file(key_path, pin, file_path):
    pin_hash = hashlib.sha256(pin.encode())

    key_file = open(key_path, "r")
    key = key_file.read().encode()
    key_file.close()

    try:
        private_key = load_pem_private_key(key, pin_hash.digest())
    except ValueError:
        raise ValueError("Incorrect pin")

    file_to_sign = open(file_path, "rb")
    file_content = file_to_sign.read()
    file_to_sign.close()
    
    file_hash = hashlib.sha256(file_content).digest()

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )



    print(base64.b64encode(signature).decode())