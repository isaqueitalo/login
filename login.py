import hashlib
import re
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, simpledialog

# =====================================
# CLASSE DE CONEXÃO (mesma lógica anterior)
# =====================================
class Connection:
    _valid_users = {
        "admin_master": hashlib.sha256("Senha@123".encode()).hexdigest(),
        "guest_user": hashlib.sha256("Guest@456".encode()).hexdigest()
    }

    def __init__(self, host='localhost'):
        self.host = host
        self._user = None
        self._password = None
        self.connected = False

    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, value):
        if not value or not value.strip():
            raise ValueError("Usuário não pode ser vazio!")
        if value not in self._valid_users:
            raise ValueError(f"Usuário '{value}' não existe!")
        self._user = value

    @property
    def password(self):
        return "*" * len(self._password) if self._password else None

    @password.setter
    def password(self, value):
        if not value or not value.strip():
            raise ValueError("Senha não pode ser vazia!")
        if not self.is_valid_password(value):
            raise ValueError("Senha inválida! Ela deve conter:\n"
                             "- 8 caracteres\n"
                             "- 1 letra maiúscula\n"
                             "- 1 letra minúscula\n"
                             "- 1 número\n"
                             "- 1 caractere especial")
        self._password = value

    def authenticate(self):
        hashed_input = self.hash_password(self._password)
        if self._valid_users.get(self._user) != hashed_input:
            raise ValueError("Senha incorreta!")

    @staticmethod
    def is_valid_password(password):
        return (len(password) >= 8 and
                re.search(r"[A-Z]", password) and
                re.search(r"[a-z]", password) and
                re.search(r"[0-9]", password) and
                re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", password))

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    @classmethod
    def register_user(cls, username, password):
        if username in cls._valid_users:
            raise ValueError("Usuário já existe!")
        if not cls.is_valid_password(password):
            raise ValueError("Senha inválida!")
        cls._valid_users[username] = cls.hash_password(password)
        messagebox.showinfo("Sucesso", f"Usuário '{username}' criado com sucesso!")


# =====================================
# INTERFACE GRÁFICA (Tkinter + ttkbootstrap)
# =====================================
app = ttk.Window(themename="superhero")  # tema bonito e com botão azul
app.title("Sistema de Login - Dark Mode")
app.geometry("400x350")

frame = ttk.Frame(app, padding=20)
frame.pack(fill="both", expand=True)

# Título
ttk.Label(frame, text="🔒 Sistema de Login", font=("Segoe UI", 16, "bold")).pack(pady=10)

# Campo usuário
ttk.Label(frame, text="Usuário:").pack(anchor="w", pady=5)
entry_user = ttk.Entry(frame)
entry_user.pack(fill="x")

# Campo senha
ttk.Label(frame, text="Senha:").pack(anchor="w", pady=5)
entry_pass = ttk.Entry(frame, show="*")
entry_pass.pack(fill="x")

# Funções de login e cadastro
def realizar_login():
    try:
        usuario = entry_user.get().strip()
        senha = entry_pass.get().strip()
        conn = Connection()
        conn.user = usuario
        conn.password = senha
        conn.authenticate()
        messagebox.showinfo("Login bem-sucedido", f"Bem-vindo, {usuario}!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

def criar_usuario():
    try:
        novo_usuario = simpledialog.askstring("Novo Usuário", "Digite o nome do novo usuário:")
        if not novo_usuario:
            return
        nova_senha = simpledialog.askstring("Nova Senha", "Digite a senha:", show="*")
        Connection.register_user(novo_usuario, nova_senha)
    except Exception as e:
        messagebox.showerror("Erro ao criar usuário", str(e))

# Botões (azul e verde)
btn_login = ttk.Button(frame, text="Entrar", bootstyle="primary", command=realizar_login)
btn_login.pack(pady=10, fill="x")

btn_novo = ttk.Button(frame, text="Novo Usuário", bootstyle="success", command=criar_usuario)
btn_novo.pack(pady=5, fill="x")

# Rodapé
ttk.Label(frame, text="© 2025 Sistema de Login", font=("Segoe UI", 8)).pack(side="bottom", pady=10)

# Inicia o app
app.mainloop()
