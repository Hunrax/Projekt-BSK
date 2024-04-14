from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
import status_indicators
import wmi
import os

USB_DRIVE_NAME = "PRIVATE_KEY"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.frames = {}

        self.title("Qualified Electronic Signature")
        self.geometry("800x600")
        self.configure(background="#006666")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames["StartPage"] = StartPage(parent=container, controller=self)
        self.frames["SignDocument"] = SignDocument(parent=container, controller=self)

        self.frames["StartPage"].grid(row=0, column=0, sticky="nsew")
        self.frames["SignDocument"].grid(row=0, column=0, sticky="nsew")

        self.show_view("StartPage")


    def show_view(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


    def check_key_status(self):
        c = wmi.WMI()
        for disk in c.Win32_LogicalDisk():
            if disk.DriveType == 2 and disk.VolumeName == USB_DRIVE_NAME:
                usb_letter = disk.DeviceID
                if os.path.exists(f"{usb_letter}\\private.pem"):
                    return f"{usb_letter}\\private.pem"
        return False


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        sign_button = tk.Button(self, text="Sign Document", command=lambda: controller.show_view("SignDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="top")


class SignDocument(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        sign_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="bottom")
        

if __name__ == "__main__":
    app = App()

    app.status_indicators = status_indicators.StatusIndicators(app)
    app.status_indicators.pack()
    app.status_indicators.start()

    app.mainloop()

