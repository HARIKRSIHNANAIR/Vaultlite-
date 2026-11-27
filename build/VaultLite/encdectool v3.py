"""
VaultLite — Text & File Encryption
---------------------------------
A Tkinter desktop app for password-based encryption using Fernet and PBKDF2-HMAC-SHA256.

Install:
    py -m pip install cryptography

Run:
    py encdectool_upgraded.py

Security notes:
- This is a learning/personal utility, not a certified security product.
- Keep your password safe; there is no password recovery.
- Encrypted files are saved to a new path; the source file is not overwritten by default.
"""

import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_BG = "#0b1120"
CARD_BG = "#151f32"
FIELD_BG = "#0f1728"
TEXT = "#edf2ff"
MUTED = "#9eacc7"
ACCENT = "#68a7ff"
ACCENT_DARK = "#2c6ac4"
SUCCESS = "#73d6a2"
BORDER = "#293752"
ITERATIONS = 600_000
SALT_SIZE = 16
MAGIC = b"VLT1"  # format marker for this app's encrypted files


def derive_cipher(password: str, salt: bytes) -> Fernet:
    """Derive a Fernet key from the user's password and a random salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def encrypt_text_value(plain_text: str, password: str) -> str:
    """Return a portable, base64-encoded encrypted text string."""
    salt = os.urandom(SALT_SIZE)
    token = derive_cipher(password, salt).encrypt(plain_text.encode("utf-8"))
    return base64.urlsafe_b64encode(MAGIC + salt + token).decode("ascii")


def decrypt_text_value(encoded_value: str, password: str) -> str:
    """Decode and decrypt text produced by encrypt_text_value()."""
    raw = base64.urlsafe_b64decode(encoded_value.encode("ascii"))
    if not raw.startswith(MAGIC) or len(raw) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("This does not look like a VaultLite encrypted text.")
    offset = len(MAGIC)
    salt = raw[offset:offset + SALT_SIZE]
    token = raw[offset + SALT_SIZE:]
    return derive_cipher(password, salt).decrypt(token).decode("utf-8")


def encrypt_file_bytes(data: bytes, password: str) -> bytes:
    """Encrypt file bytes; output includes a marker, salt, and Fernet token."""
    salt = os.urandom(SALT_SIZE)
    token = derive_cipher(password, salt).encrypt(data)
    return MAGIC + salt + token


def decrypt_file_bytes(data: bytes, password: str) -> bytes:
    """Decrypt file bytes created by encrypt_file_bytes()."""
    if not data.startswith(MAGIC) or len(data) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("This does not look like a VaultLite encrypted file.")
    offset = len(MAGIC)
    salt = data[offset:offset + SALT_SIZE]
    token = data[offset + SALT_SIZE:]
    return derive_cipher(password, salt).decrypt(token)


class VaultLiteApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("VaultLite | Text & File Encryption")
        self.root.geometry("900x720")
        self.root.minsize(760, 640)
        self.root.configure(bg=APP_BG)

        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready — enter a password to begin.")
        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=APP_BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=CARD_BG,
            foreground=TEXT,
            padding=(18, 10),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT_DARK)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Vault.Horizontal.TProgressbar",
            troughcolor=FIELD_BG,
            background=ACCENT,
            bordercolor=FIELD_BG,
        )
    def _label(self, parent, text=None, **kwargs):
            if text is not None:
                kwargs["text"] = text
            return tk.Label(
                parent, bg=kwargs.pop("bg", CARD_BG),
                fg=kwargs.pop("fg", TEXT), font=kwargs.pop("font", ("Segoe UI", 10)),
                **kwargs
            )

    def _button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command,
            bg=ACCENT_DARK if primary else "#22304a",
            fg="#ffffff" if primary else TEXT,
            activebackground=ACCENT, activeforeground="#ffffff",
            relief="flat", bd=0, padx=16, pady=10,
            font=("Segoe UI", 10, "bold"), cursor="hand2",
        )

    def _build_ui(self):
        header = tk.Frame(self.root, bg=APP_BG)
        header.pack(fill="x", padx=28, pady=(24, 14))
        self._label(header, "VAULTLITE", bg=APP_BG, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        self._label(
            header, "Private by design • Password-based text and file encryption",
            bg=APP_BG, fg=MUTED, font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(3, 0))

        pw_card = tk.Frame(self.root, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        pw_card.pack(fill="x", padx=28, pady=(0, 16))
        self._label(pw_card, "MASTER PASSWORD", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18, pady=(14, 7))
        pw_row = tk.Frame(pw_card, bg=CARD_BG)
        pw_row.pack(fill="x", padx=18, pady=(0, 14))
        self.password_entry = tk.Entry(
            pw_row, textvariable=self.password_var, show="•",
            bg=FIELD_BG, fg=TEXT, insertbackground=TEXT, relief="flat",
            font=("Segoe UI", 12), highlightthickness=1, highlightbackground=BORDER,
        )
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=10)
        self._button(pw_row, "Show / Hide", self.toggle_password).pack(side="left", padx=(10, 0))
        self._label(
            pw_card, "Use a strong, unique password. Losing it means losing access to your data.",
            fg=MUTED, font=("Segoe UI", 9)
        ).pack(anchor="w", padx=18, pady=(0, 14))

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=28, pady=(0, 14))
        self.text_tab = tk.Frame(notebook, bg=CARD_BG)
        self.file_tab = tk.Frame(notebook, bg=CARD_BG)
        notebook.add(self.text_tab, text="  Text Vault  ")
        notebook.add(self.file_tab, text="  File Vault  ")
        self._build_text_tab()
        self._build_file_tab()

        footer = tk.Frame(self.root, bg=APP_BG)
        footer.pack(fill="x", padx=28, pady=(0, 18))
        self._label(footer, textvariable=self.status_var, bg=APP_BG, fg=SUCCESS, font=("Segoe UI", 9)).pack(side="left")
        self._label(footer, "AES encryption via Fernet • PBKDF2-HMAC-SHA256", bg=APP_BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="right")

    def _build_text_tab(self):
        pad = {"padx": 18}
        self._label(self.text_tab, "INPUT TEXT / ENCRYPTED STRING", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(18, 8), **pad)
        self.text_input = tk.Text(
            self.text_tab, height=7, wrap="word", undo=True,
            bg=FIELD_BG, fg=TEXT, insertbackground=TEXT,
            relief="flat", padx=12, pady=10, font=("Consolas", 10),
            highlightthickness=1, highlightbackground=BORDER,
        )
        self.text_input.pack(fill="both", expand=True, padx=18)
        row = tk.Frame(self.text_tab, bg=CARD_BG)
        row.pack(fill="x", padx=18, pady=12)
        self._button(row, "Encrypt text", self.encrypt_text, primary=True).pack(side="left")
        self._button(row, "Decrypt text", self.decrypt_text).pack(side="left", padx=8)
        self._button(row, "Clear", self.clear_text).pack(side="left")
        self._button(row, "Copy output", self.copy_output).pack(side="right")

        self._label(self.text_tab, "OUTPUT", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18, pady=(3, 8))
        self.text_output = tk.Text(
            self.text_tab, height=7, wrap="word",
            bg=FIELD_BG, fg=SUCCESS, insertbackground=TEXT,
            relief="flat", padx=12, pady=10, font=("Consolas", 10),
            highlightthickness=1, highlightbackground=BORDER,
        )
        self.text_output.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    def _build_file_tab(self):
        intro = tk.Frame(self.file_tab, bg=CARD_BG)
        intro.pack(fill="x", padx=22, pady=(24, 18))
        self._label(intro, "Encrypt or decrypt a file", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        self._label(
            intro,
            "Choose a file, then choose where to save the result. The original file is left untouched.",
            fg=MUTED, font=("Segoe UI", 10), wraplength=700, justify="left"
        ).pack(anchor="w", pady=(7, 0))

        action_card = tk.Frame(self.file_tab, bg=FIELD_BG, highlightbackground=BORDER, highlightthickness=1)
        action_card.pack(fill="x", padx=22, pady=10)
        self._button(action_card, "📁  Encrypt a file", lambda: self.process_file("encrypt"), primary=True).pack(
            fill="x", padx=18, pady=(18, 8)
        )
        self._button(action_card, "🔓  Decrypt a VaultLite file", lambda: self.process_file("decrypt")).pack(
            fill="x", padx=18, pady=(0, 18)
        )

        note = tk.Frame(self.file_tab, bg=CARD_BG)
        note.pack(fill="x", padx=22, pady=12)
        self._label(note, "Important", fg=ACCENT, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._label(
            note,
            "Keep a backup of important files. This version reads each file into memory, so very large files may need a streaming design.",
            fg=MUTED, wraplength=700, justify="left"
        ).pack(anchor="w", pady=(5, 0))

    def get_password(self):
        password = self.password_var.get()
        if len(password) < 8:
            messagebox.showerror("Password required", "Enter a password with at least 8 characters.")
            self.password_entry.focus_set()
            return None
        return password

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")
        self.show_password_var.set(not self.show_password_var.get())

    def set_output(self, value):
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert("1.0", value)

    def encrypt_text(self):
        password = self.get_password()
        if password is None:
            return
        plain_text = self.text_input.get("1.0", "end-1c")
        if not plain_text:
            messagebox.showwarning("Nothing to encrypt", "Type some text in the input box first.")
            return
        try:
            self.set_output(encrypt_text_value(plain_text, password))
            self.status_var.set("Text encrypted successfully.")
        except Exception as exc:
            messagebox.showerror("Encryption failed", f"Could not encrypt the text.\n\n{exc}")

    def decrypt_text(self):
        password = self.get_password()
        if password is None:
            return
        encrypted = self.text_input.get("1.0", "end-1c").strip()
        if not encrypted:
            messagebox.showwarning("Nothing to decrypt", "Paste an encrypted string into the input box first.")
            return
        try:
            self.set_output(decrypt_text_value(encrypted, password))
            self.status_var.set("Text decrypted successfully.")
        except (InvalidToken, ValueError, UnicodeDecodeError, base64.binascii.Error):
            messagebox.showerror("Decryption failed", "Wrong password, damaged data, or unsupported encrypted text.")
            self.status_var.set("Decryption failed.")
        except Exception as exc:
            messagebox.showerror("Decryption failed", str(exc))

    def clear_text(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.delete("1.0", tk.END)
        self.status_var.set("Text fields cleared.")

    def copy_output(self):
        value = self.text_output.get("1.0", "end-1c")
        if not value:
            messagebox.showinfo("No output", "There is no output to copy yet.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()
        self.status_var.set("Output copied to clipboard.")

    def process_file(self, mode):
        password = self.get_password()
        if password is None:
            return

        if mode == "encrypt":
            source_path = filedialog.askopenfilename(title="Choose a file to encrypt")
        else:
            source_path = filedialog.askopenfilename(
                title="Choose a VaultLite encrypted file",
                filetypes=[("Encrypted files", "*.vlt"), ("All files", "*.*")]
            )
        if not source_path:
            return

        base = os.path.basename(source_path)
        suggested = base + ".vlt" if mode == "encrypt" else (
            base[:-4] if base.endswith(".vlt") else "decrypted_" + base
        )
        save_path = filedialog.asksaveasfilename(
            title="Save the result as",
            initialfile=suggested,
            defaultextension=".vlt" if mode == "encrypt" else "",
        )
        if not save_path:
            return

        try:
            with open(source_path, "rb") as file_handle:
                source_data = file_handle.read()

            if mode == "encrypt":
                result = encrypt_file_bytes(source_data, password)
            else:
                result = decrypt_file_bytes(source_data, password)

            # Avoid accidentally overwriting the selected source file.
            if os.path.abspath(save_path) == os.path.abspath(source_path):
                messagebox.showerror("Choose a different path", "Save the result to a different file so the original stays safe.")
                return

            with open(save_path, "wb") as file_handle:
                file_handle.write(result)

            self.status_var.set(f"File {mode}ion completed.")
            messagebox.showinfo("Success", f"File processed successfully.\n\nSaved to:\n{save_path}")
        except (InvalidToken, ValueError, base64.binascii.Error):
            messagebox.showerror("File processing failed", "Wrong password, damaged data, or file not encrypted by VaultLite.")
            self.status_var.set("File processing failed.")
        except OSError as exc:
            messagebox.showerror("File error", f"Could not read or save the file.\n\n{exc}")
            self.status_var.set("File operation failed.")
        except Exception as exc:
            messagebox.showerror("Unexpected error", str(exc))
            self.status_var.set("File operation failed.")


def main():
    root = tk.Tk()
    VaultLiteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
