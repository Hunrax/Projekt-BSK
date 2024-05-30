from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib


def decrypt_file(file_path, private_key_path, pin):
    pin_hash = hashlib.sha256(pin.encode())

    key_file = open(private_key_path, "r")
    key = key_file.read().encode()
    key_file.close()

    try:
        private_key = load_pem_private_key(key, pin_hash.digest())
    except ValueError:
        raise ValueError("Incorrect pin")

    file_to_decrypt = open(file_path, "rb")
    file_content = file_to_decrypt.read()
    file_to_decrypt.close()

    plaintext = private_key.decrypt(
        file_content,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    decrypted_file = open(str(file_path).removesuffix(".encrypted"), "wb")
    decrypted_file.write(plaintext)
    decrypted_file.close()

# decrypt_file("C:\\Users\\jasie\\Desktop\\dupa.txt.encrypted", "G:\\private.pem", "1234")