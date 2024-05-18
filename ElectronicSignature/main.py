from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
from tkinter import filedialog as fd
from tkinter.messagebox import showerror
import status_indicators
from utilities import check_key_status
from sign import sign_file


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
        self.frames["VerifySignature"] = VerifySignature(parent=container, controller=self)

        self.frames["StartPage"].grid(row=0, column=0, sticky="nsew")
        self.frames["SignDocument"].grid(row=0, column=0, sticky="nsew")
        self.frames["VerifySignature"].grid(row=0, column=0, sticky="nsew")

        self.show_view("StartPage")


    def show_view(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        sign_button = tk.Button(self, text="Sign document", command=lambda: controller.show_view("SignDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="top")
        verify_button = tk.Button(self, text="Verify signature", command=lambda: controller.show_view("VerifySignature"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        verify_button.pack()


class SignDocument(tk.Frame):
    def chose_file(self):
        self.file_to_sign.set(fd.askopenfilename(title="Choose a file to sign"))
        self.update_idletasks()

    def sign(self, pin):
        private_key_path = check_key_status()
        if private_key_path == False:
            showerror("Error", "Private key not detected")
            return
        if self.file_to_sign.get() is None or self.file_to_sign.get() == "":
            showerror("Error", "Please select file to sign")
            return
        if pin == "":
            showerror("Error", "Enter pin to connected private key")
            return
        
        try:
            sign_file(private_key_path, pin, self.file_to_sign.get())
        except ValueError:
            showerror("Error", "Incorect pin")
            return
        
        self.controller.show_view("StartPage")
        
        
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.file_to_sign = tk.StringVar()
        pin_label = tk.Label(self, text="Enter pin:")
        pin_label.pack()
        pin_input = tk.Entry(self)
        pin_input.pack()
        pick_file_label = tk.Label(self, textvariable=self.file_to_sign)
        pick_file_label.pack()
        pick_file_button = tk.Button(self, text="Pick file to sign", command=self.chose_file)
        pick_file_button.pack()
        sign_button = tk.Button(self, text="Sign file", command=lambda: self.sign(pin=pin_input.get()))
        sign_button.pack()
        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom")

class VerifySignature(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.signature = tk.StringVar()
        self.public_key = tk.StringVar()
        pick_signature_label = tk.Label(self, textvariable=self.signature)
        pick_signature_label.pack()
        pick_signature_button = tk.Button(self, text="Pick signature to verify")
        pick_signature_button.pack()
        pick_public_key_label = tk.Label(self, textvariable=self.public_key)
        pick_public_key_label.pack()
        pick_public_key_button = tk.Button(self, text="Pick public key")
        pick_public_key_button.pack()
        verify_button = tk.Button(self, text="Verify signature")
        verify_button.pack()
        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom") 


if __name__ == "__main__":
    app = App()

    app.status_indicators = status_indicators.StatusIndicators(app)
    app.status_indicators.pack()
    app.status_indicators.start()

    app.mainloop()

