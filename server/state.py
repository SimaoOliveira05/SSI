import os
from dataclasses import dataclass, field

HOST = "127.0.0.1"
PORT = 8888

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_SERVER_DIR, "data")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
PREKEYS_FILE = os.path.join(DATA_DIR, "prekeys.json")
SERVER_KEYS_DIR = os.path.join(DATA_DIR, "keys")


@dataclass
class Client:
    """Estado de sessao por utilizador autenticado no servidor."""
    username: str
    writer: object
    chatting_with: str | None = None
    c2s_key: bytes | None = None   # cliente -> servidor (servidor decifra)
    s2c_key: bytes | None = None   # servidor -> cliente (servidor cifra)
    send_counter: int = 0
    recv_counter: int = 0
    # Challenge-response auth: nonce per-sessão emitido logo após o handshake; consumido no /login.
    nonce: bytes | None = None
    # Salt gerado no /salt_request quando o username ainda não existe — usado pelo /register a seguir.
    pending_salt: bytes | None = None


# Runtime state (em memoria). users.json/prekeys.json persistem; grupos NAO
# persistem — sao efemeros e existem so enquanto ha membros online.
online_users: dict[str, Client] = {}
registered_users: dict[str, dict] = {}
groups: dict[str, dict] = {}
offline_queue: dict[str, list[dict]] = {}        # recipient -> [{sender, blob}]
prekeys: dict[str, dict[str, str]] = {}     # username -> {prekey_id: prekey_pub_b64}

server_private_key = None
server_public_key = None
