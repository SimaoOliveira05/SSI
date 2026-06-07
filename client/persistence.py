"""
Persistencia local do cliente (disco)
=====================================
Centraliza toda a I/O de ficheiros do cliente, com o mesmo rigor de
seguranca aplicado as mensagens:

- Chave RSA privada  -> PEM PKCS#8 cifrado com a password (BestAvailableEncryption).
- Prekey store        -> AES-256-GCM com file-key aleatoria, embrulhada em
                          RSA-OAEP da identidade (so a RSA privada — ela propria
                          protegida por password — a desembrulha).
- Certificado / chave publica do servidor -> material publico, em claro.

As funcoes sao puras (recebem tudo por argumento, nao tocam em
SecurityManager) — load_prekey_store NAO reescreve: devolve `migrated` e
deixa o chamador decidir.
"""

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat,
    PublicFormat, load_pem_private_key, load_pem_public_key,
)

# Wrap da file-key do prekey store: RSA-OAEP-SHA256 com a chave do proprio user.
_RSA_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)


# ── Chave RSA privada (cifrada por password) ──────────────────────────────

def save_private_key(keys_dir: str, name: str, key, password: str) -> None:
    os.makedirs(keys_dir, exist_ok=True)
    pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password.encode())
    )
    with open(os.path.join(keys_dir, f"{name}_private.pem"), "wb") as f:
        f.write(pem)


def load_private_key(keys_dir: str, name: str, password: str):
    """Carrega e desbloqueia a RSA privada. Lanca excecao se falhar."""
    with open(os.path.join(keys_dir, f"{name}_private.pem"), "rb") as f:
        return load_pem_private_key(f.read(), password=password.encode())


def pub_key_to_b64(public_key) -> str:
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pem).decode()


# ── Certificado proprio / chave publica do servidor (material publico) ─────

def load_certificate(keys_dir: str, name: str) -> dict | None:
    path = os.path.join(keys_dir, f"{name}_cert.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def save_certificate(keys_dir: str, name: str, cert: dict) -> None:
    with open(os.path.join(keys_dir, f"{name}_cert.json"), "w") as f:
        json.dump(cert, f, indent=2)


def load_server_public_key(keys_dir: str):
    try:
        with open(os.path.join(keys_dir, "server_public.pem"), "rb") as f:
            return load_pem_public_key(f.read())
    except FileNotFoundError:
        return None


# ── Prekey store (cifrado: AES-GCM + file-key embrulhada em RSA-OAEP) ──────

def _prekey_path(keys_dir: str, name: str) -> str:
    return os.path.join(keys_dir, f"{name}_prekeys.json")


def save_prekey_store(keys_dir: str, name: str, prekeys: dict, rsa_pubkey) -> None:
    """Cifra o store das pre-keys X25519 privadas em repouso."""
    plaintext = json.dumps({
        pk_id: base64.b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode()
        for pk_id, priv in prekeys.items()
    }).encode()

    file_key = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(file_key).encrypt(nonce, plaintext, None)
    wrapped = rsa_pubkey.encrypt(file_key, _RSA_OAEP)

    with open(_prekey_path(keys_dir, name), "w") as f:
        json.dump({
            "wrapped": base64.b64encode(wrapped).decode(),
            "nonce":   base64.b64encode(nonce).decode(),
            "ct":      base64.b64encode(ct).decode(),
        }, f)


def load_prekey_store(keys_dir: str, name: str, rsa_privkey) -> tuple[dict, bool]:
    """Devolve (prekeys, migrated).

    Aceita o formato legado em claro; nesse caso `migrated=True` e o chamador
    deve reescrever (save_prekey_store) para o passar a cifrado.
    """
    path = _prekey_path(keys_dir, name)
    if not os.path.exists(path):
        return {}, False

    with open(path) as f:
        data = json.load(f)

    if "ct" in data:                       # formato cifrado
        file_key = rsa_privkey.decrypt(base64.b64decode(data["wrapped"]), _RSA_OAEP)
        raw_json = AESGCM(file_key).decrypt(
            base64.b64decode(data["nonce"]), base64.b64decode(data["ct"]), None)
        store = json.loads(raw_json)
        migrated = False
    else:                                  # legado em claro
        store = data
        migrated = True

    prekeys = {
        pk_id: X25519PrivateKey.from_private_bytes(base64.b64decode(raw_b64))
        for pk_id, raw_b64 in store.items()
    }
    return prekeys, migrated
