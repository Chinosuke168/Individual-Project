import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox


# ============================================================
# ======================= FILE HANDLER ========================
# ============================================================
class FileHandler:
    @staticmethod
    def save(path: str, data: bytes):
        with open(path, "wb") as f:
            f.write(data)

    @staticmethod
    def load(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

# ============================================================
# ========================== GUI APP ==========================
# ============================================================

class OTPApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("OTP Cryptography Toolkit (OOP + Key Split + Key Verification)")

        self.text_input = tk.Text(root, height=5, width=50)
        self.text_input.pack(pady=10)

        tk.Button(root, text="Encrypt Text", command=self.gui_encrypt_text).pack()
        tk.Button(root, text="Decrypt Text", command=self.gui_decrypt_text).pack(pady=5)

        tk.Label(root, text="--------------------------------").pack()

        tk.Button(root, text="Encrypt File", command=self.gui_encrypt_file).pack(pady=10)
        tk.Button(root, text="Decrypt File", command=self.gui_decrypt_file).pack(pady=5)

        tk.Label(root, text="--------------------------------").pack()

        tk.Button(root, text="Recover Key From Parts", command=self.gui_recover_key).pack(pady=10)

    # ======================= TEXT FUNCTIONS =====================

    def gui_encrypt_text(self):
        message = self.text_input.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Text field is empty.")
            return

        data = message.encode()
        ciphertext, key = OTP.encrypt(data)
        part1, part2, key_hash = OTP.split_key(key)

        FileHandler.save("ciphertext.bin", ciphertext)
        FileHandler.save("key.part1", part1)
        FileHandler.save("key.part2", part2)
        FileHandler.save("key.hash", key_hash.encode())

        messagebox.showinfo("Success",
                            "Text encrypted.\nSaved:\n - ciphertext.bin\n - key.part1\n - key.part2\n - key.hash")

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
        except FileNotFoundError:
            messagebox.showerror("Error", "Missing ciphertext or key files.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    # ======================= FILE FUNCTIONS =====================

    def gui_encrypt_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if not path:
            return

        data = FileHandler.load(path)
        ciphertext, key = OTP.encrypt(data)
        part1, part2, key_hash = OTP.split_key(key)

        FileHandler.save(path + ".enc", ciphertext)
        FileHandler.save(path + ".part1", part1)
        FileHandler.save(path + ".part2", part2)
        FileHandler.save(path + ".hash", key_hash.encode())

        messagebox.showinfo("Success",
                            f"Encrypted:\n{path}.enc\n{path}.part1\n{path}.part2\n{path}.hash")

    def gui_decrypt_file(self):
        cipher_path = filedialog.askopenfilename(title="Select encrypted file (.enc)")
        if not cipher_path:
            return

        part1_path = filedialog.askopenfilename(title="Select key part 1 (.part1)")
        part2_path = filedialog.askopenfilename(title="Select key part 2 (.part2)")
        hash_path = filedialog.askopenfilename(title="Select key hash (.hash)")

        if not part1_path or not part2_path or not hash_path:
            return

        ciphertext = FileHandler.load(cipher_path)
        part1 = FileHandler.load(part1_path)
        part2 = FileHandler.load(part2_path)
        key_hash = FileHandler.load(hash_path).decode()

        try:
            key = OTP.recover_key(part1, part2, key_hash)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        data = OTP.decrypt(ciphertext, key)

        # restore original filename (remove .enc)
        out_path = cipher_path[:-4] if cipher_path.endswith(".enc") else cipher_path + ".dec"
        out_path = auto_rename(out_path)

        FileHandler.save(out_path, data)
        messagebox.showinfo("Success", f"Decrypted file saved as:\n{out_path}")

    # ===================== RECOVER KEY ONLY =====================

    def gui_recover_key(self):
        p1 = filedialog.askopenfilename(title="Select key.part1")
        if not p1:
            return
        p2 = filedialog.askopenfilename(title="Select key.part2")
        hash_path = filedialog.askopenfilename(title="Select key.hash")
        if not p2 or not hash_path:
            return

        part1 = FileHandler.load(p1)
        part2 = FileHandler.load(p2)
        key_hash = FileHandler.load(hash_path).decode()

        try:
            key = OTP.recover_key(part1, part2, key_hash)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".key", title="Save recovered key as")
        if not save_path:
            return

        FileHandler.save(save_path, key)
        messagebox.showinfo("Success", f"Recovered key saved:\n{save_path}")

# ============================================================
# ============================= MAIN ==========================
# ============================================================

if __name__ == "__main__":
    root = tk.Tk()
    OTPApp(root)
    root.mainloop()
