from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import hashlib
import wmi
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
import os
from pathlib import Path

def verify_signature(signature_path, public_key_path):
    tree = ET.parse(signature_path)
    root = tree.getroot()
    signature = base64.b64decode(root.find('Signature').text)  
    file_name = root.find("DocumentInfo").find("Name").text
    file_path = str(Path(signature_path).parent) + "\\" +file_name
    
    file_to_verify = open(file_path, "rb")
    file_content = file_to_verify.read()
    file_to_verify.close()   
    file_hash = hashlib.sha256(file_content).digest()

    key_file = open(public_key_path, "r")
    key = key_file.read().encode()
    key_file.close()
    public_key = load_pem_public_key(key)

    public_key.verify(
        signature,
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
