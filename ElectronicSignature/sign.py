from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
import wmi
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
import os

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

    # print(base64.b64encode(signature).decode())

    signature_xml = ET.Element("Signature")

    document_info = ET.SubElement(signature_xml, "DocumentInfo")
    file_name = ET.SubElement(document_info, "Name")
    file_name.text = os.path.basename(file_path)
    size = ET.SubElement(document_info, "Size")
    size.text = str(os.path.getsize(file_path))
    extension = ET.SubElement(document_info, "Extension")
    extension.text = os.path.splitext(file_path)[1]
    date_modified = ET.SubElement(document_info, "DateModified")
    date_modified.text = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%dT%H:%M:%S")

    signing_user = ET.SubElement(signature_xml, "SigningUser")
    name = ET.SubElement(signing_user, "Name")
    name.text = os.getlogin()

    signature_node = ET.SubElement(signature_xml, "Signature")
    signature_node.text = base64.b64encode(signature).decode()

    timestamp = ET.SubElement(signature_xml, "Timestamp")
    local_time = ET.SubElement(timestamp, "LocalTime")
    local_time.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S") 

    tree = ET.ElementTree(signature_xml)
    ET.indent(tree, space="\t", level=0)
    tree.write(file_path+".xml")