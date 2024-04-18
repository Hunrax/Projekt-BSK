import wmi
import os

USB_DRIVE_NAME = "PRIVATE_KEY"

def check_key_status():
    c = wmi.WMI()
    for disk in c.Win32_LogicalDisk():
        if disk.DriveType == 2 and disk.VolumeName == USB_DRIVE_NAME:
            usb_letter = disk.DeviceID
            if os.path.exists(f"{usb_letter}\\private.pem"):
                return f"{usb_letter}\\private.pem"
    return False
