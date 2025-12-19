import tkinter as tk
from tkinter import filedialog, messagebox

from otp_core import OTP
from file_handler import FileHandler
from utils import auto_rename

class OTPApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("OTP Cryptography Toolkit (Modular)")

        self.text_input = tk.Text(root, height=5, width=50)
        self.text_input.pack(pady=10)

        tk.Button(root, text="Encrypt Text", command=self.gui_encrypt_text).pack()
        tk.Button(root, text="Decrypt Text", command=self.gui_decrypt_text).pack(pady=5)

        tk.Label(root, text="--------------------------------").pack()

        tk.Button(root, text="Encrypt File", command=self.gui_encrypt_file).pack(pady=10)
        tk.Button(root, text="Decrypt File", command=self.gui_decrypt_file).pack(pady=5)

        tk.Label(root, text="--------------------------------").pack()

        tk.Button(root, text="Recover Key From Parts", command=self.gui_recover_key).pack(pady=10)

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