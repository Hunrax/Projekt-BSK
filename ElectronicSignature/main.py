from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import filedialog as fd
from tkinter.messagebox import showerror, showinfo
import status_indicators
from utilities import check_key_status
from sign import sign_file
from verify import verify_signature
from encrypt import encrypt_file
from decrypt import decrypt_file

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
        self.frames["EncryptDocument"] = EncryptDocument(parent=container, controller=self)
        self.frames["DecryptDocument"] = DecryptDocument(parent=container, controller=self)

        self.frames["StartPage"].grid(row=0, column=0, sticky="nsew")
        self.frames["SignDocument"].grid(row=0, column=0, sticky="nsew")
        self.frames["VerifySignature"].grid(row=0, column=0, sticky="nsew")
        self.frames["EncryptDocument"].grid(row=0, column=0, sticky="nsew")
        self.frames["DecryptDocument"].grid(row=0, column=0, sticky="nsew")

        self.show_view("StartPage")


    def show_view(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        sign_button = tk.Button(self, text="Sign document", command=lambda: controller.show_view("SignDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="top", pady=20)
        verify_button = tk.Button(self, text="Verify signature", command=lambda: controller.show_view("VerifySignature"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        verify_button.pack(pady=0)
        encrypt_button = tk.Button(self, text="Encrypt file", command=lambda: controller.show_view("EncryptDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        encrypt_button.pack(pady=20)
        decrypt_button = tk.Button(self, text="Decrypt file", command=lambda: controller.show_view("DecryptDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        decrypt_button.pack(pady=0)


class SignDocument(tk.Frame):
    def chose_file(self):
        self.file_to_sign.set(fd.askopenfilename(title="Choose a file to sign", filetypes=[("text file", ".txt"), ("pdf file", ".pdf")]))
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
        showinfo("Success", "Successfully signed the file")
        self.file_to_sign.set("")
        self.pin_input.delete(0, 'end')
        self.update_idletasks()
        self.controller.show_view("StartPage")
        
        
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.file_to_sign = tk.StringVar()
        pin_label = tk.Label(self, text="Enter pin:")
        pin_label.pack()
        self.pin_input = tk.Entry(self)
        self.pin_input.pack()
        pick_file_label = tk.Label(self, textvariable=self.file_to_sign)
        pick_file_label.pack()
        pick_file_button = tk.Button(self, text="Pick file to sign", command=self.chose_file)
        pick_file_button.pack()
        sign_button = tk.Button(self, text="Sign file", command=lambda: self.sign(pin=self.pin_input.get()))
        sign_button.pack()
        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom")

class VerifySignature(tk.Frame):
    def choose_singature(self):
        self.signature.set(fd.askopenfilename(title="Choose the signature file", filetypes=[("signature files",".xml")]))
        self.update_idletasks()

    def choose_public_key(self):
        self.public_key.set(fd.askopenfilename(title="Choose the public key", filetypes=[("public key", ".pub")]))
        self.update_idletasks()

    def verify_signature(self):
        if self.signature.get() is None or self.signature.get() == "":
            showerror("Error", "Please select signature")
            return
        if self.public_key.get() is None or self.public_key.get() == "":
            showerror("Error", "Please select public key")
            return
        try:
            verify_signature(self.signature.get(), self.public_key.get())
        except InvalidSignature:
            showerror("Invalid signature", "Signature is invalid")
            return
        showinfo("Valid signature", "Signature is valid (:")
        self.signature.set("")
        self.public_key.set("")
        self.update_idletasks()
        self.controller.show_view("StartPage")

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.signature = tk.StringVar()
        self.public_key = tk.StringVar()
        pick_signature_label = tk.Label(self, textvariable=self.signature)
        pick_signature_label.pack()
        pick_signature_button = tk.Button(self, text="Pick signature to verify", command=self.choose_singature)
        pick_signature_button.pack()
        pick_public_key_label = tk.Label(self, textvariable=self.public_key)
        pick_public_key_label.pack()
        pick_public_key_button = tk.Button(self, text="Pick public key", command=self.choose_public_key)
        pick_public_key_button.pack()
        verify_button = tk.Button(self, text="Verify signature", command=self.verify_signature)
        verify_button.pack()
        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom") 

class EncryptDocument(tk.Frame):
    def chose_file(self):
        self.file_to_encrypt.set(fd.askopenfilename(title="Choose a file to encrypt", filetypes=[("text file", ".txt")]))
        self.update_idletasks()

    def chose_key(self):
        self.public_key.set(fd.askopenfilename(title="Choose a public key", filetypes=[("public key", ".pub")]))
        self.update_idletasks()

    def encrypt(self):
        if self.file_to_encrypt.get() is None or self.file_to_encrypt.get() == "":
            showerror("Error", "Please select a file")
            return
        if self.public_key.get() is None or self.public_key.get() == "":
            showerror("Error", "Please select a public key")
            return
        try:
            encrypt_file(self.file_to_encrypt.get(), self.public_key.get()) 
        except ValueError:
            showerror("Error", "Error while encrypting, is the file too big?")
            return
        showinfo("Success", "Encryption successful (:")
        self.file_to_encrypt.set("")
        self.public_key.set("")
        self.update_idletasks()
        self.controller.show_view("StartPage")

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.file_to_encrypt = tk.StringVar()
        self.public_key = tk.StringVar()

        pick_file_button = tk.Button(self, text="Pick file to encrypt", command=self.chose_file)
        pick_file_button.pack()
        pick_file_label = tk.Label(self, textvariable=self.file_to_encrypt)
        pick_file_label.pack()

        pick_key_button = tk.Button(self, text="Pick a public key", command=self.chose_key)
        pick_key_button.pack()
        pick_key_label = tk.Label(self, textvariable=self.public_key)
        pick_key_label.pack()

        encrypt_button = tk.Button(self, text="Encrypt file", command=self.encrypt)
        encrypt_button.pack()

        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom") 

class DecryptDocument(tk.Frame):
    def chose_file(self):
        self.file_to_decrypt.set(fd.askopenfilename(title="Choose a file to decrypt", filetypes=[("encrypted file", ".encrypted")]))
        self.update_idletasks()

    def decrypt(self, pin):
        if self.file_to_decrypt.get() is None or self.file_to_decrypt.get() == "":
            showerror("Error", "Please select a file")
            return
        private_key_path = check_key_status()
        if private_key_path == False:
            showerror("Error", "Private key not detected")
            return
        try:
            decrypt_file(self.file_to_decrypt.get(), private_key_path, pin) 
        except ValueError:
            showerror("Error", "Error while decrypting, is the pin correct?")
            return
        
        showinfo("Success", "Decryption successful (:")
        self.file_to_decrypt.set("")
        self.update_idletasks()
        self.controller.show_view("StartPage")

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.file_to_decrypt = tk.StringVar()

        pick_file_button = tk.Button(self, text="Pick file to decrypt", command=self.chose_file)
        pick_file_button.pack()
        pick_file_label = tk.Label(self, textvariable=self.file_to_decrypt)
        pick_file_label.pack()

        pin_label = tk.Label(self, text="Enter pin:")
        pin_label.pack()
        self.pin_input = tk.Entry(self)
        self.pin_input.pack()

        decrypt_button = tk.Button(self, text="Decrypt file", command=lambda: self.decrypt(pin=self.pin_input.get()))
        decrypt_button.pack()

        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom") 


if __name__ == "__main__":
    app = App()

    app.status_indicators = status_indicators.StatusIndicators(app)
    app.status_indicators.pack()
    app.status_indicators.start()

    app.mainloop()

