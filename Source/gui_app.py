import tkinter as tk
from tkinter import filedialog, messagebox

from otp_core import OTP
from file_handler import FileHandler
from utils import auto_rename


class OTPApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("OTP Cryptography Toolkit")
        root.geometry("1920x1080")
        root.configure(bg="#0f172a")  # dark blue background
        root.resizable(False, False)

        # ====== STYLES ======
        self.bg = "#0f172a"
        self.card = "#020617"
        self.btn = "#2563eb"
        self.btn_hover = "#1d4ed8"
        self.text_fg = "#e5e7eb"
        self.border = "#334155"

        # ====== TITLE ======
        tk.Label(
            root,
            text="One-Time Pad Cryptography Toolkit",
            font=("Segoe UI", 16, "bold"),
            fg="#38bdf8",
            bg=self.bg
        ).pack(pady=15)

        # ====== TEXT CARD ======
        text_frame = tk.Frame(root, bg=self.card, bd=1, relief="solid")
        text_frame.pack(padx=15, pady=10, fill="x")

        tk.Label(
            text_frame,
            text="Text Encryption / Decryption",
            font=("Segoe UI", 11, "bold"),
            fg=self.text_fg,
            bg=self.card
        ).pack(anchor="w", padx=10, pady=(10, 5))

        self.text_input = tk.Text(
            text_frame,
            height=5,
            width=55,
            bg="#020617",
            fg=self.text_fg,
            insertbackground="white",
            relief="solid",
            bd=1
        )
        self.text_input.pack(padx=10, pady=5)

        btn_frame_text = tk.Frame(text_frame, bg=self.card)
        btn_frame_text.pack(pady=10)

        self.make_button(btn_frame_text, "Encrypt Text", self.gui_encrypt_text).pack(side="left", padx=10)
        self.make_button(btn_frame_text, "Decrypt Text", self.gui_decrypt_text).pack(side="left", padx=10)

        # ====== FILE CARD ======
        file_frame = tk.Frame(root, bg=self.card, bd=1, relief="solid")
        file_frame.pack(padx=15, pady=10, fill="x")

        tk.Label(
            file_frame,
            text="File Encryption / Decryption",
            font=("Segoe UI", 11, "bold"),
            fg=self.text_fg,
            bg=self.card
        ).pack(anchor="w", padx=10, pady=(10, 5))

        btn_frame_file = tk.Frame(file_frame, bg=self.card)
        btn_frame_file.pack(pady=15)

        self.make_button(btn_frame_file, "Encrypt File", self.gui_encrypt_file).pack(pady=5)
        self.make_button(btn_frame_file, "Decrypt File", self.gui_decrypt_file).pack(pady=5)

        # ====== KEY RECOVERY CARD ======
        key_frame = tk.Frame(root, bg=self.card, bd=1, relief="solid")
        key_frame.pack(padx=15, pady=10, fill="x")

        tk.Label(
            key_frame,
            text="Key Recovery",
            font=("Segoe UI", 11, "bold"),
            fg=self.text_fg,
            bg=self.card
        ).pack(anchor="w", padx=10, pady=(10, 5))

        self.make_button(
            key_frame,
            "Recover Key From Parts",
            self.gui_recover_key
        ).pack(pady=15)

        # ====== FOOTER ======
        tk.Label(
            root,
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg=self.bg
        ).pack(pady=10)

    # ====== BUTTON FACTORY ======
    def make_button(self, parent, text, command):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.btn,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=15,
            pady=8,
            cursor="hand2"
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=self.btn_hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.btn))
        return btn

    # -------- TEXT --------
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

    # -------- FILE --------
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

    # -------- KEY RECOVERY --------
    def gui_recover_key(self):
        p1 = filedialog.askopenfilename()
        p2 = filedialog.askopenfilename()
        h = filedialog.askopenfilename()
        if not all([p1, p2, h]):
            return

        key = OTP.recover_key(
            FileHandler.load(p1),
            FileHandler.load(p2),
            FileHandler.load(h).decode()
        )

        save_path = filedialog.asksaveasfilename(defaultextension=".key")
        if save_path:
            FileHandler.save(save_path, key)
            messagebox.showinfo("Success", "Key recovered.")
