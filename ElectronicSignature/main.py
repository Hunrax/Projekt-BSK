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

        self.frames["StartPage"].grid(row=0, column=0, sticky="nsew")
        self.frames["SignDocument"].grid(row=0, column=0, sticky="nsew")

        self.show_view("StartPage")


    def show_view(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        sign_button = tk.Button(self, text="Sign Document", command=lambda: controller.show_view("SignDocument"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="top")


class SignDocument(tk.Frame):
    def chose_file(self):
        self.file_to_sign = fd.askopenfilename(title="Choose a file to sign")

    def sign(self, pin):
        private_key_path = check_key_status()
        if private_key_path == False:
            showerror("Error", "Private key not detected")
            return
        if self.file_to_sign is None or self.file_to_sign == "":
            showerror("Error", "Please select file to sign")
            return
        if pin == "":
            showerror("Error", "Enter pin to connected private key")
            return
        
        try:
            sign_file(private_key_path, pin, self.file_to_sign)
        except ValueError:
            showerror("Error", "Incorect pin")
            return
        
        self.controller.show_view("Start Page")
        
        
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.file_to_sign = None
        pin_input = tk.Entry(self)
        pin_input.pack()
        pick_file_button = tk.Button(self, text="Pick file to sign", command=self.chose_file)
        pick_file_button.pack()
        sign_button = tk.Button(self, text="Sign file", command=lambda: self.sign(pin=pin_input.get()))
        sign_button.pack()
        back_button = tk.Button(self, text="Go back", command=lambda: controller.show_view("StartPage"), bg="#6699ff", fg="#000000", relief=tk.FLAT)
        back_button.pack(side="bottom")
        

if __name__ == "__main__":
    app = App()

    app.status_indicators = status_indicators.StatusIndicators(app)
    app.status_indicators.pack()
    app.status_indicators.start()

    app.mainloop()

