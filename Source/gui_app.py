import tkinter as tk
from tkinter import filedialog, messagebox

from otp_core import OTP
from file_handler import FileHandler
from utils import auto_rename


# ===================== THEME =====================
BG_COLOR = "#0f172a"        # Dark navy
FG_COLOR = "#e5e7eb"        # Light text
ACCENT = "#22c55e"          # Neon green
BTN_BG = "#1e293b"
BTN_HOVER = "#334155"
FONT_TITLE = ("Consolas", 16, "bold")
FONT_TEXT = ("Consolas", 11)
FONT_BTN = ("Consolas", 10, "bold")


class OTPApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("OTP Cryptography Toolkit")
        root.geometry("520x620")
        root.configure(bg=BG_COLOR)
        root.resizable(False, False)

        # ===================== TITLE =====================
        tk.Label(
            root,
            text="OTP CRYPTOGRAPHY TOOLKIT",
            fg=ACCENT,
            bg=BG_COLOR,
            font=FONT_TITLE
        ).pack(pady=15)

        # ===================== TEXT INPUT =====================
        self.text_input = tk.Text(
            root,
            height=5,
            width=55,
            bg="#020617",
            fg=ACCENT,
            insertbackground=ACCENT,
            font=FONT_TEXT,
            relief="flat"
        )
        self.text_input.pack(pady=10)

        # ===================== TEXT BUTTONS =====================
        self.make_button("Encrypt Text", self.gui_encrypt_text)
        self.make_button("Decrypt Text", self.gui_decrypt_text)

        self.separator("FILE OPERATIONS")

        # ===================== FILE BUTTONS =====================
        self.make_button("Encrypt File", self.gui_encrypt_file)
        self.make_button("Decrypt File", self.gui_decrypt_file)



        # ===================== FOOTER =====================
        tk.Label(
            root,
            text="One-Time Pad • Educational Use Only",
            fg="#94a3b8",
            bg=BG_COLOR,
            font=("Consolas", 9)
        ).pack(side="bottom", pady=10)

    # ===================== UI HELPERS =====================
    def make_button(self, text, command):
        btn = tk.Button(
            self.root,
            text=text,
            command=command,
            bg=BTN_BG,
            fg=FG_COLOR,
            font=FONT_BTN,
            width=30,
            relief="flat",
            activebackground=ACCENT,
            activeforeground="black",
            cursor="hand2"
        )
        btn.pack(pady=6)

        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_BG))

    def separator(self, text):
        tk.Label(
            self.root,
            text=f"— {text} —",
            fg="#38bdf8",
            bg=BG_COLOR,
            font=("Consolas", 10, "bold")
        ).pack(pady=15)

    # ===================== TEXT =====================
    def gui_encrypt_text(self):
        message = self.text_input.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Text field is empty.")
            return

        ciphertext, key = OTP.encrypt(message.encode())
        part1, part2, key_hash = OTP.split_key(key)

        FileHandler.save("ciphertext.bin", ciphertext)
        FileHandler.save("key.part1", part1)
        FileHandler.save("key.part2", part2)
        FileHandler.save("key.hash", key_hash.encode())

        messagebox.showinfo("Success", "Text encrypted and files saved.")

    def gui_decrypt_text(self):
        try:
            ciphertext = FileHandler.load("ciphertext.bin")
            part1 = FileHandler.load("key.part1")
            part2 = FileHandler.load("key.part2")
            key_hash = FileHandler.load("key.hash").decode()

            key = OTP.recover_key(part1, part2, key_hash)
            plain = OTP.decrypt(ciphertext, key).decode()

            self.text_input.delete("1.0", tk.END)
            self.text_input.insert(tk.END, plain)

            messagebox.showinfo("Success", "Text decrypted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ===================== FILE =====================
    def gui_encrypt_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return

        data = FileHandler.load(path)
        ciphertext, key = OTP.encrypt(data)
        part1, part2, key_hash = OTP.split_key(key)

        FileHandler.save(path + ".enc", ciphertext)
        FileHandler.save(path + ".part1", part1)
        FileHandler.save(path + ".part2", part2)
        FileHandler.save(path + ".hash", key_hash.encode())

        messagebox.showinfo("Success", "File encrypted.")

    def gui_decrypt_file(self):
        cipher_path = filedialog.askopenfilename()
        part1_path = filedialog.askopenfilename()
        part2_path = filedialog.askopenfilename()
        hash_path = filedialog.askopenfilename()

        if not all([cipher_path, part1_path, part2_path, hash_path]):
            return

        ciphertext = FileHandler.load(cipher_path)
        part1 = FileHandler.load(part1_path)
        part2 = FileHandler.load(part2_path)
        key_hash = FileHandler.load(hash_path).decode()

        key = OTP.recover_key(part1, part2, key_hash)
        data = OTP.decrypt(ciphertext, key)

        out_path = auto_rename(cipher_path.replace('.enc', ''))
        FileHandler.save(out_path, data)
        messagebox.showinfo("Success", f"Saved: {out_path}")