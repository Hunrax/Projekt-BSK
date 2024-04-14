from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
import status_indicators

def signDocument():
    print("przycisk")
    return


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.USB_DRIVE_NAME = "PRIVATE_KEY"

        self.title("Qualified Electronic Signature")
        self.geometry("800x600")
        self.configure(background="#006666")

        sign_button = tk.Button(self, text="Sign Document", command=signDocument, bg="#6699ff", fg="#000000", relief=tk.FLAT)
        sign_button.pack(side="top")

if __name__ == "__main__":
    app = App()

    app.status_indicators = status_indicators.StatusIndicators(app)
    app.status_indicators.pack()
    app.status_indicators.start()


    app.mainloop()

