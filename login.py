import hashlib
import re
from getpass import getpass


class Connection:
    # Credenciais fixas com senhas hash (poderiam ser carregadas de arquivo depois)
    _valid_users = {
        "admin_master": hashlib.sha256("Senha@123".encode()).hexdigest(),
        "guest_user": hashlib.sha256("Guest@456".encode()).hexdigest()
    }

    def __init__(self, host='localhost'):
        self.host = host
        self._user = None
        self._password = None
        self.connected = False

    # ===== Getter e Setter para user =====
    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, value: str):
        if not value or not value.strip():
            raise ValueError("Usuário não pode ser vazio!")
        if value not in self._valid_users:
            raise ValueError(f"Usuário '{value}' não é permitido!")
        self._user = value

    # ===== Getter e Setter para password =====
    @property
    def password(self):
        if self._password:
            return "*" * len(self._password)
        return None

    @password.setter
    def password(self, value: str):
        if not value or not value.strip():
            raise ValueError("Senha não pode ser vazia!")
        if not self.is_valid_password(value):
            raise ValueError(
                "Senha inválida! Ela deve conter no mínimo:\n"
                "- 8 caracteres\n- 1 letra maiúscula\n- 1 letra minúscula\n- 1 número\n- 1 caractere especial"
            )
        self._password = value

    # ===== Autenticação e Validação =====
    def authenticate(self):
        if self._user not in self._valid_users:
            raise ValueError("Usuário inválido!")
        hashed_input = self.hash_password(self._password)
        if self._valid_users[self._user] != hashed_input:
            raise ValueError("Senha incorreta!")

    @staticmethod
    def is_valid_password(password):
        """
        A senha deve conter:
        - pelo menos 8 caracteres
        - pelo menos uma letra maiúscula
        - pelo menos uma letra minúscula
        - pelo menos um número
        - pelo menos um caractere especial
        """
        return (
            len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", password)
        )

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def login_message(user, msg):
        print(f"login: {user}, {msg}")

    @classmethod
    def create_with_credentials(cls, user, password):
        connection = cls()
        connection.user = user
        connection.password = password
        return connection

    @classmethod
    def register_user(cls, username: str, password: str):
        if username in cls._valid_users:
            raise ValueError("Usuário já existe.")
        if not cls.is_valid_password(password):
            raise ValueError(
                "Senha inválida! Ela deve conter no mínimo:\n"
                "- 8 caracteres\n- 1 letra maiúscula\n- 1 letra minúscula\n- 1 número\n- 1 caractere especial"
            )
        cls._valid_users[username] = cls.hash_password(password)
        print(f"Usuário '{username}' criado com sucesso.")

    def connect(self):
        if not self._user or not self._password:
            raise ValueError("Usuário ou senha não fornecidos!")
        self.authenticate()
        self.connected = True
        self.login_message(self._user, "conectado com sucesso!")

    def disconnect(self):
        if self.connected:
            self.connected = False
            print("Conexão encerrada.")
        else:
            print("Nenhuma conexão ativa.")

    def __str__(self):
        status = "Conectado" if self.connected else "Desconectado"
        return f"Connection(user={self._user}, host={self.host}, status={status})"

    def __repr__(self):
        return f"<Connection user={self._user} connected={self.connected}>"


# =====================
# MENU INTERATIVO
# =====================
MAX_TENTATIVAS = 3
user = None

while True:
    print("\n====== MENU ======")
    print("1. Fazer login")
    print("2. Criar novo usuário")
    print("3. Sair")

    opcao = input("Escolha uma opção: ").strip()

    if opcao == "1":
        # Tentar login
        for tentativa in range(MAX_TENTATIVAS):
            try:
                login = input("Digite o usuário: ").strip()
                senha = getpass("Digite a senha: ").strip()

                user = Connection.create_with_credentials(login, senha)
                user.connect()
                print(user)
                break
            except Exception as e:
                print(f"Erro: {e}")
                if tentativa == MAX_TENTATIVAS - 1:
                    print("Número máximo de tentativas atingido.")
                    user = None
        if user:
            break  # Login bem-sucedido → sair do menu principal

    elif opcao == "2":
        # Criar novo usuário
        try:
            novo_usuario = input("Digite o novo nome de usuário: ").strip()
            nova_senha = getpass("Digite a nova senha: ").strip()
            Connection.register_user(novo_usuario, nova_senha)
        except Exception as e:
            print(f"Erro ao criar usuário: {e}")

    elif opcao == "3":
        print("Saindo do sistema.")
        exit()

    else:
        print("Opção inválida.")

# =====================
# Loop de comandos após login
# =====================
try:
    while True:
        comando = input("\nDigite 'sair' para encerrar o sistema: ").strip().lower()
        if comando == "sair":
            user.disconnect()
            print("Sistema encerrado.")
            break
        else:
            print("Comando inválido. Digite 'sair' para sair.")
except Exception as e:
    print(f"Erro: {e}")
######################################
# =====================