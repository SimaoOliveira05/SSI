import base64
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import state
from crypto_transport import (
    decrypt_counter_aead,
    encrypt_counter_aead,
    ratchet_key,
    rsa_verify_pem,
    x25519_pub_from_b64,
)
from protocol import Msg
from state import Client


# ── Logging ───────────────────────────────────────────────────────────────
# Formato uniforme para a demo: [hh:mm:ss.mmm] CATEGORIA  detalhe
# Categorias usadas: CONN, AUTH, RECV, RELAY, GROUP, OFFLINE, WARN.

_CAT_WIDTH = 8


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(category: str, msg: str) -> None:
    print(f"[{_ts()}] {category.upper():<{_CAT_WIDTH}} {msg}")


# ── Messaging ─────────────────────────────────────────────────────────────

async def send_raw(writer, msg_type: str, payload: str = ""):
    """Envia linha de protocolo sem cifragem (handshake inicial e erros fatais)."""
    line = f"{msg_type}:{payload}\n" if payload else f"{msg_type}\n"
    writer.write(line.encode())
    await writer.drain()


async def send(writer, msg_type: str, payload: str = "", client: Client | None = None):
    """Envia mensagem tipada; cifra em ENC quando a sessao de transporte existe."""
    line = f"{msg_type}:{payload}" if payload else msg_type
    if client and client.s2c_key:
        encrypted = server_encrypt(client, line)
        writer.write(f"{Msg.ENC}:{encrypted}\n".encode())
    else:
        writer.write(f"{line}\n".encode())
    await writer.drain()


async def server_msg(writer, text: str, client: Client | None = None):
    """Atalho para mensagens de sistema (Msg.SERVER)."""
    await send(writer, Msg.SERVER, text, client=client)


# ── Crypto helpers ────────────────────────────────────────────────────────

def b64_to_x25519_pub(b64: str) -> X25519PublicKey:
    return x25519_pub_from_b64(b64)


def server_encrypt(client: Client, plaintext: str) -> str:
    client.send_counter += 1
    ct = encrypt_counter_aead(client.s2c_key, plaintext, client.send_counter)
    client.s2c_key = ratchet_key(client.s2c_key)
    return ct


def server_decrypt(client: Client, b64_payload: str) -> str | None:
    if not client.c2s_key:
        return None
    plaintext, counter = decrypt_counter_aead(client.c2s_key, b64_payload, client.recv_counter)
    if plaintext is None or counter is None:
        return None
    client.recv_counter = counter
    client.c2s_key = ratchet_key(client.c2s_key)
    return plaintext


def verify_public_key(pubkey_b64: str) -> bool:
    """Valida se o material recebido e uma RSA public key PEM valida."""
    try:
        load_pem_public_key(base64.b64decode(pubkey_b64))
        return True
    except Exception:
        return False


def verify_signature(pubkey_b64: str, signature_b64: str, message: bytes) -> bool:
    """Verifica assinatura RSA-PSS sobre message com a chave publica dada."""
    return rsa_verify_pem(pubkey_b64, signature_b64, message)


