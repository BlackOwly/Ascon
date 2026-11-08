# gui/main_window.py
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.file_utils import (
    generate_random_key, generate_random_nonce,
    save_keypair, list_saved_keys, load_keypair,
    read_file, write_file,           # ← обязательно для encrypt_file/decrypt_file
    KEYS_DIR, PROJECT_ROOT,          # ← используются в _refresh_saved_keys_combo / _short_path
)
from core.ascon import Ascon

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ascon Cipher Tool")
        self.geometry("780x580")
        self.minsize(660, 500)

        self._setup_styles()

        self.enc_file_path = None
        self.dec_file_path = None

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.encrypt_tab = self._create_encrypt_tab()
        self.decrypt_tab = self._create_decrypt_tab()
        self.notebook.add(self.encrypt_tab, text="  Шифрование  ")
        self.notebook.add(self.decrypt_tab, text="  Расшифровка  ")

        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(self, textvariable=self.status_var, anchor="w",
                  relief="sunken", padding=(8, 4)).pack(fill="x", side="bottom")

        # Первичное заполнение списков ключей
        self._refresh_saved_keys_combo(self.enc_saved_combo)
        self._refresh_saved_keys_combo(self.dec_saved_combo)

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook.Tab", padding=(14, 6))
        style.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))

    # ---------- Общий блок «ключ + nonce + панель действий» ----------

    def _build_key_section(self, parent):
        ttk.Label(parent, text="Ключ (hex, 32 символа = 128 бит):").pack(anchor="w")
        key_var = tk.StringVar()
        ttk.Entry(parent, textvariable=key_var).pack(fill="x", pady=(2, 10))

        ttk.Label(parent, text="Nonce (hex, 32 символа = 128 бит):").pack(anchor="w")
        nonce_var = tk.StringVar()
        ttk.Entry(parent, textvariable=nonce_var).pack(fill="x", pady=(2, 10))

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(4, 0))

        ttk.Button(actions, text="Сгенерировать пару",
                   command=lambda: self._generate_pair(key_var, nonce_var)
                   ).pack(side="left")
        ttk.Button(actions, text="Сохранить",
                   command=lambda: self._save_current(key_var, nonce_var)
                   ).pack(side="left", padx=(6, 0))

        ttk.Label(actions, text="Загрузить:").pack(side="left", padx=(14, 4))
        combo = ttk.Combobox(actions, state="readonly", width=34)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>",
                   lambda _e, c=combo, k=key_var, n=nonce_var:
                   self._load_selected(c, k, n))
        ttk.Button(actions, text="⟳", width=3,
                   command=lambda c=combo: self._refresh_saved_keys_combo(c)
                   ).pack(side="left", padx=(4, 0))

        return key_var, nonce_var, combo

    # ---------- Вкладка шифрования ----------

    def _create_encrypt_tab(self):
        frame = ttk.Frame(self.notebook, padding=18)

        file_row = ttk.Frame(frame)
        file_row.pack(fill="x", pady=(0, 14))
        self.enc_file_var = tk.StringVar(value="Файл не выбран")
        ttk.Label(file_row, textvariable=self.enc_file_var,
                  anchor="w").pack(side="left", fill="x", expand=True)
        ttk.Button(file_row, text="Выбрать файл...",
                   command=self.choose_file_for_encryption).pack(side="right")

        self.key_var, self.nonce_var, self.enc_saved_combo = \
            self._build_key_section(frame)

        ttk.Button(frame, text="Зашифровать и сохранить...",
                   command=self.encrypt_file,
                   style="Accent.TButton").pack(fill="x", pady=(22, 0), ipady=6)

        return frame

    # ---------- Вкладка расшифровки ----------

    def _create_decrypt_tab(self):
        frame = ttk.Frame(self.notebook, padding=18)

        file_row = ttk.Frame(frame)
        file_row.pack(fill="x", pady=(0, 14))
        self.dec_file_var = tk.StringVar(value="Файл не выбран")
        ttk.Label(file_row, textvariable=self.dec_file_var,
                  anchor="w").pack(side="left", fill="x", expand=True)
        ttk.Button(file_row, text="Выбрать файл...",
                   command=self.choose_file_for_decryption).pack(side="right")

        self.dec_key_var, self.dec_nonce_var, self.dec_saved_combo = \
            self._build_key_section(frame)

        ttk.Button(frame, text="Расшифровать и сохранить...",
                   command=self.decrypt_file,
                   style="Accent.TButton").pack(fill="x", pady=(22, 0), ipady=6)

        return frame

    # ---------- Логика работы с ключами ----------

    def _generate_pair(self, key_var, nonce_var):
        """Генерирует новую пару ключ+nonce и сразу сохраняет её в проект."""
        key = generate_random_key(16)
        nonce = generate_random_nonce(16)
        key_var.set(key.hex())
        nonce_var.set(nonce.hex())
        path = save_keypair(key, nonce)
        self.status_var.set(f"Сгенерировано и сохранено: {self._short_path(path)}")
        self._refresh_saved_keys_combo(self.enc_saved_combo)
        self._refresh_saved_keys_combo(self.dec_saved_combo)

    def _save_current(self, key_var, nonce_var):
        """Сохраняет текущие значения полей как новый файл ключа."""
        key_hex = key_var.get().strip()
        nonce_hex = nonce_var.get().strip()
        if not key_hex or not nonce_hex:
            messagebox.showwarning("Нечего сохранять",
                                   "Сначала заполните поля ключа и nonce.")
            return
        try:
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
        except ValueError:
            messagebox.showerror("Ошибка",
                                 "Ключ и nonce должны быть в hex-формате.")
            return
        if len(key) != 16 or len(nonce) != 16:
            messagebox.showerror(
                "Ошибка",
                "Ожидается по 16 байт (32 hex-символа) для ключа и nonce."
            )
            return
        path = save_keypair(key, nonce)
        self.status_var.set(f"Сохранено: {self._short_path(path)}")
        self._refresh_saved_keys_combo(self.enc_saved_combo)
        self._refresh_saved_keys_combo(self.dec_saved_combo)

    def _refresh_saved_keys_combo(self, combo):
        names = [p.name for p in list_saved_keys()]
        current = combo.get()
        combo["values"] = names
        if names:
            combo.set(current if current in names else names[0])
        else:
            combo.set("")

    def _load_selected(self, combo, key_var, nonce_var):
        name = combo.get().strip()
        if not name:
            return
        path = KEYS_DIR / name
        if not path.exists():
            messagebox.showerror("Ошибка", f"Файл ключа не найден:\n{path}")
            self._refresh_saved_keys_combo(combo)
            return
        try:
            key, nonce, _variant = load_keypair(path)
        except Exception as e:
            messagebox.showerror("Ошибка",
                                 f"Не удалось прочитать файл ключа:\n{e}")
            return
        key_var.set(key.hex())
        nonce_var.set(nonce.hex())
        self.status_var.set(f"Загружен ключ: {name}")

    @staticmethod
    def _short_path(path) -> str:
        try:
            return str(path.relative_to(PROJECT_ROOT))
        except ValueError:
            return str(path)

    # ---------- Вкладки / файлы ----------

    def _on_tab_changed(self, _event):
        # При переключении вкладок обновляем списки — вдруг ключи появились снаружи
        if hasattr(self, "enc_saved_combo"):
            self._refresh_saved_keys_combo(self.enc_saved_combo)
        if hasattr(self, "dec_saved_combo"):
            self._refresh_saved_keys_combo(self.dec_saved_combo)

    def choose_file_for_encryption(self):
        path = filedialog.askopenfilename(title="Выберите файл для шифрования")
        if path:
            self.enc_file_path = path
            self.enc_file_var.set(f"Выбран: {path}")
            self.status_var.set(f"Файл для шифрования: {path}")

    def choose_file_for_decryption(self):
        path = filedialog.askopenfilename(title="Выберите файл для расшифровки")
        if path:
            self.dec_file_path = path
            self.dec_file_var.set(f"Выбран: {path}")
            self.status_var.set(f"Файл для расшифровки: {path}")

    def encrypt_file(self):
        if not self.enc_file_path:
            messagebox.showwarning("Файл не выбран", "Выберите файл для шифрования.")
            return
        try:
            key = bytes.fromhex(self.key_var.get().strip())
            nonce = bytes.fromhex(self.nonce_var.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Ключ и nonce должны быть в hex-формате.")
            return
        if len(key) != 16 or len(nonce) != 16:
            messagebox.showerror("Ошибка", "Ключ и nonce должны быть по 16 байт (32 hex-символа).")
            return

        try:
            plaintext = read_file(self.enc_file_path)
        except Exception as e:
            messagebox.showerror("Ошибка чтения", str(e))
            return

        try:
            blob = Ascon().encrypt(key, nonce, plaintext)
        except Exception as e:
            messagebox.showerror("Ошибка шифрования", str(e))
            return

        default_name = os.path.basename(self.enc_file_path) + ".ascon"
        out_path = filedialog.asksaveasfilename(
            title="Сохранить зашифрованный файл",
            initialfile=default_name,
            defaultextension=".ascon",
            filetypes=[("Ascon encrypted", "*.ascon"), ("Все файлы", "*.*")],
        )
        if not out_path:
            self.status_var.set("Сохранение отменено")
            return

        try:
            write_file(out_path, blob)
        except Exception as e:
            messagebox.showerror("Ошибка записи", str(e))
            return

        tag_hex = blob[-16:].hex()
        self.status_var.set(
            f"Зашифровано: {self._short_path(out_path)}  "
            f"({len(plaintext)} → {len(blob)} байт, tag={tag_hex})"
        )
        messagebox.showinfo("Готово", f"Файл сохранён:\n{out_path}\n\nТег: {tag_hex}")

    def decrypt_file(self):
        if not self.dec_file_path:
            messagebox.showwarning("Файл не выбран", "Выберите файл для расшифровки.")
            return
        try:
            key = bytes.fromhex(self.dec_key_var.get().strip())
            nonce = bytes.fromhex(self.dec_nonce_var.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Ключ и nonce должны быть в hex-формате.")
            return
        if len(key) != 16 or len(nonce) != 16:
            messagebox.showerror("Ошибка", "Ключ и nonce должны быть по 16 байт (32 hex-символа).")
            return

        try:
            blob = read_file(self.dec_file_path)
        except Exception as e:
            messagebox.showerror("Ошибка чтения", str(e))
            return

        try:
            plaintext = Ascon().decrypt(key, nonce, blob)
        except ValueError as e:
            messagebox.showerror("Ошибка аутентификации", str(e))
            self.status_var.set("Расшифровка не удалась: тег не совпадает")
            return
        except Exception as e:
            messagebox.showerror("Ошибка расшифровки", str(e))
            return

        base = os.path.basename(self.dec_file_path)
        default_name = base[:-len(".ascon")] if base.endswith(".ascon") else base + ".dec"
        out_path = filedialog.asksaveasfilename(
            title="Сохранить расшифрованный файл",
            initialfile=default_name,
            filetypes=[("Все файлы", "*.*")],
        )
        if not out_path:
            self.status_var.set("Сохранение отменено")
            return

        try:
            write_file(out_path, plaintext)
        except Exception as e:
            messagebox.showerror("Ошибка записи", str(e))
            return

        self.status_var.set(
            f"Расшифровано: {self._short_path(out_path)}  "
            f"({len(blob)} → {len(plaintext)} байт)"
        )
        messagebox.showinfo("Готово", f"Файл сохранён:\n{out_path}")
def run():
    app = MainWindow()
    app.mainloop()
