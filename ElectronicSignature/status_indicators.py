import tkinter as tk
import wmi
import os

class StatusIndicators(tk.Frame):

    def __init__(self, container):
        super().__init__(container)
        self.app = container
        self._taskID = None
        self.delay = 2000

        self.usb_status = tk.Label(self, text="dupa")
        self.usb_status.pack()

    def start(self):
        self.after(0, self._loop)

    # calls its self after a specific <delay>
    def _loop(self):
        if self.check_key_status():
            self.usb_status.config(text="USB key detected")
        else:
            self.usb_status.config(text="USB key not connected")

        self._taskID = self.after(self.delay, self._loop)

    # stopps the loop method calling its self
    def stop(self):
        self.after_cancel(self._taskID)
        # Depends if you want to destroy the widget after the loop has stopped
        self.destroy()

    def check_key_status(self):
        c = wmi.WMI()
        for disk in c.Win32_LogicalDisk():
            if disk.DriveType == 2 and disk.VolumeName == self.app.USB_DRIVE_NAME:
                usb_letter = disk.DeviceID
                if os.path.exists(f"{usb_letter}\\private.pem"):
                    return True
        return False