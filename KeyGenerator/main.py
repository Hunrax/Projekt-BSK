from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import wmi

USB_DRIVE_NAME = "PRIVATE_KEY"

c = wmi.WMI()
usb_letter = ""

for disk in c.Win32_LogicalDisk():
    if disk.DriveType == 2 and disk.VolumeName == USB_DRIVE_NAME:
        print(f'USB drive "{disk.VolumeName}" detected as: {disk.DeviceID}')
        usb_letter = disk.DeviceID
        break
    
if usb_letter == "":
    print(f'USB drive "{USB_DRIVE_NAME}" not found. Connect it or rename connected drive to match the expected value.')
    exit()

private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 4096
)

public_key = private_key.public_key()

print("Enter pin to your new private key:")
pin = input().encode()
pin_hash = hashlib.sha256(pin)

private_key_file = open(f"{usb_letter}\\private.pem", "w")
private_key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(pin_hash.digest())).decode())
private_key_file.close()
print(f"Encrypted private key saved to {usb_letter}\\private.pem. For best protection don't copy it anywhere.")

public_key_file = open(f"{usb_letter}\\public.pub", "w")
public_key_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
public_key_file.close()
print(f"Public key saved to {usb_letter}\\public.pub. You can copy it to your computer and send to anyone to verify your signatures or encrypt file for you.")