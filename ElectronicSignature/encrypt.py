from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def encrypt_file(file_path, public_key_path):
    file_to_encrypt = open(file_path, "rb")
    file_content = file_to_encrypt.read()
    file_to_encrypt.close()

    key_file = open(public_key_path, "r")
    key = key_file.read().encode()
    key_file.close()
    public_key = load_pem_public_key(key)

    cyphertext = public_key.encrypt(
        file_content,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_file = open(file_path+".encrypted", "wb")
    encrypted_file.write(cyphertext)
    encrypted_file.close()