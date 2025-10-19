import sqlite3
import hashlib
import re
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox


# ==========================
# BANCO DE DADOS (SQLite)
# ==========================
DB_NAME = "usuarios.db"


def inicializar_banco():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ==========================
# CLASSE PRINCIPAL
# ==========================
class Connection:
    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password
        self.connected = False

    @staticmethod
    def hash_password(password: str) -> str:
        """Retorna o hash SHA256 da senha"""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def is_valid_password(password: str) -> bool:
        """Valida se a senha cumpre os requisitos mínimos"""
        return (
            len(password) >= 8
            and re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"[0-9]", password)
            and re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password)
        )

    def authenticate(self):
        """Verifica login no banco"""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM usuarios WHERE username = ?", (self.username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            raise ValueError("Usuário não encontrado.")
        if self.hash_password(self.password) != result[0]:
            raise ValueError("Senha incorreta.")

        self.connected = True

    def register_user(self):
        """Registra novo usuário"""
        if not self.username or not self.password:
            raise ValueError("Usuário e senha são obrigatórios.")
        if not self.is_valid_password(self.password):
            raise ValueError(
                "Senha inválida!\nDeve conter no mínimo:\n"
                "- 8 caracteres\n- 1 letra maiúscula\n- 1 minúscula\n- 1 número\n- 1 símbolo especial"
            )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO usuarios (username, password_hash) VALUES (?, ?)",
                (self.username, self.hash_password(self.password)),
            )
            conn.commit()
            messagebox.showinfo("Sucesso", f"Usuário '{self.username}' criado com sucesso!")
        except sqlite3.IntegrityError:
            raise ValueError("Usuário já existe.")
        finally:
            conn.close()


# ==========================
# INTERFACE GRÁFICA (Tkinter + TTKBootstrap)
# ==========================
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Sistema de Login - SQLite")
        self.root.geometry("400x400")
        self.root.resizable(False, False)
        self.root.configure(padx=20, pady=20)

        # Tema escuro moderno
        style = ttk.Style("darkly")

        # ===== Título =====
        ttk.Label(
            root,
            text="🔐 Sistema de Login",
            font=("Segoe UI", 16, "bold"),
            bootstyle="info"
        ).pack(pady=20)

        # ===== Entrada de usuário =====
        ttk.Label(root, text="Usuário:", bootstyle="info").pack(anchor="w", padx=20)
        self.entry_user = ttk.Entry(root, width=30)
        self.entry_user.pack(pady=5)

        # ===== Entrada de senha =====
        ttk.Label(root, text="Senha:", bootstyle="info").pack(anchor="w", padx=20)
        self.entry_pass = ttk.Entry(root, show="*", width=30)
        self.entry_pass.pack(pady=5)

        # ===== Estilo global dos botões =====
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)

        # ===== Botões =====
        self.btn_login = ttk.Button(
            root,
            text="🔓 Entrar",
            bootstyle="success-outline",
            width=25,
            command=self.login
        )
        self.btn_login.pack(pady=10)

        self.btn_register = ttk.Button(
            root,
            text="➕ Criar Novo Usuário",
            bootstyle="info-outline",
            width=25,
            command=self.register
        )
        self.btn_register.pack(pady=5)

        self.btn_exit = ttk.Button(
            root,
            text="🚪 Sair",
            bootstyle="danger-outline",
            width=25,
            command=root.quit
        )
        self.btn_exit.pack(pady=10)

    # ======= Funções da interface =======
    def login(self):
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        try:
            user = Connection(username, password)
            user.authenticate()
            messagebox.showinfo("Sucesso", f"Bem-vindo, {username}!")
        except Exception as e:
            messagebox.showerror("Erro de Login", str(e))

    def register(self):
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        try:
            user = Connection(username, password)
            user.register_user()
        except Exception as e:
            messagebox.showerror("Erro ao Registrar", str(e))


# ==========================
# EXECUÇÃO
# ==========================
if __name__ == "__main__":
    inicializar_banco()
    root = ttk.Window(themename="darkly")
    app = LoginApp(root)
    root.mainloop()
