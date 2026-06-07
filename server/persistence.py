import json
import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

import state
from crypto_transport import cert_signing_bytes, rsa_sign


def load_or_generate_server_keys():
    """Carrega par RSA-2048 do servidor do disco, ou gera se nao existir."""
    keys_dir = state.SERVER_KEYS_DIR
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "server_private.pem")
    pub_path = os.path.join(keys_dir, "server_public.pem")

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            state.server_private_key = load_pem_private_key(f.read(), password=None)
        print("[SignalUM] Server keys loaded from disk.")
    else:
        state.server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        priv_pem = state.server_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        pub_pem = state.server_private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)

        print("[SignalUM] New RSA-2048 server keys generated and saved.")

    state.server_public_key = state.server_private_key.public_key()


def issue_certificate(username: str, pubkey_b64: str) -> dict:
    """Emite certificado RSA-PSS assinado pelo servidor para identidade do utilizador."""
    cert = {
        "username": username,
        "pubkey": pubkey_b64,
        "issued_at": int(time.time()),
    }
    cert["signature"] = rsa_sign(state.server_private_key, cert_signing_bytes(cert))
    return cert


def load_users() -> dict:
    if not os.path.exists(state.USERS_FILE):
        return {}
    with open(state.USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_users():
    fd = os.open(state.USERS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state.registered_users, f, indent=2)


def load_prekeys() -> dict:
    if not os.path.exists(state.PREKEYS_FILE):
        return {}
    with open(state.PREKEYS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_prekeys():
    with open(state.PREKEYS_FILE, "w") as f:
        json.dump(state.prekeys, f, indent=2)
