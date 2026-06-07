import asyncio
import os
from dataclasses import dataclass, field

from encryption import SecurityManager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")


@dataclass
class ClientState:
    """Estado de runtime do cliente CLI (identidade, chat ativo e grupos)."""
    username: str | None = None
    chatting_with: str | None = None
    active_group: str | None = None
    groups: dict[str, dict] = field(default_factory=dict)
    security: SecurityManager = field(default_factory=lambda: SecurityManager(KEYS_DIR))
    # Dados do /register em curso (username + pub_b64 esperado) para validar o CERT recebido.
    pending_register: dict | None = None
    # Target e cert quando o utilizador quer enviar mensagens offline.
    pending_offline_to: str | None = None
    pending_offline_cert: dict | None = None


    def reset_chat(self):
        """Limpa sessão 1-a-1 ativa e counters associados ao peer."""
        target = self.chatting_with
        if target:
            self.security.sessions.pop(target, None)
            self.security.send_counters.pop(target, None)
            self.security.recv_counters.pop(target, None)
        self.chatting_with = None
        self.active_group = None
        self.security.ephemeral_private = None


state = ClientState()

# Ponteiros globais para ligação TCP ativa.
reader_global: asyncio.StreamReader | None = None
writer_global: asyncio.StreamWriter | None = None

# Filas para sincronizar passos assíncronos de handshakes.
# `register_ack_queue` sinaliza fim de /register.
register_ack_queue: asyncio.Queue[bool] = asyncio.Queue()
# `chat_ack_queue` recebe a EPH do recetor (str, sucesso) ou False (erro/abort).
chat_ack_queue: asyncio.Queue = asyncio.Queue()
# `prekey_resp_queue` recebe dict com a pre-key ({id, pub, sig}) ou None (erro/pool vazio).
prekey_resp_queue: asyncio.Queue = asyncio.Queue()
# `salt_queue` recebe o salt PBKDF2 (str b64) em resposta a SALT_REQUEST.
salt_queue: asyncio.Queue[str] = asyncio.Queue()

# Nonce per-sessão emitido pelo servidor após o handshake de transporte.
# Usado no challenge-response do /login.
server_nonce: bytes | None = None
nonce_event: asyncio.Event = asyncio.Event()


def set_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Publica os sockets globais usados pelos módulos de transporte/receção."""
    global reader_global, writer_global
    reader_global = reader
    writer_global = writer
