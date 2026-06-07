import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

# Fonte unica do esquema de assinatura RSA-PSS usado em todo o projeto.
RSA_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
RSA_HASH = hashes.SHA256()


# ── RSA-PSS sign / verify (fonte unica) ───────────────────────────────────

def rsa_sign(private_key, data: bytes) -> str:
    """Assina data com RSA-PSS-SHA256, devolve assinatura em base64."""
    return base64.b64encode(private_key.sign(data, RSA_PSS, RSA_HASH)).decode()


def rsa_verify(public_key, sig_b64: str, data: bytes) -> bool:
    """Verifica assinatura RSA-PSS-SHA256 (base64) sobre data."""
    try:
        public_key.verify(base64.b64decode(sig_b64), data, RSA_PSS, RSA_HASH)
        return True
    except Exception:
        return False


def rsa_verify_pem(pubkey_pem_b64: str, sig_b64: str, data: bytes) -> bool:
    """Como rsa_verify mas a chave publica vem como PEM em base64."""
    try:
        return rsa_verify(load_pem_public_key(base64.b64decode(pubkey_pem_b64)), sig_b64, data)
    except Exception:
        return False


# ── Certificados (encode / bytes canonicos para assinatura) ───────────────

def encode_cert(cert: dict) -> str:
    return base64.b64encode(json.dumps(cert).encode()).decode()


def decode_cert(cert_b64: str) -> dict:
    return json.loads(base64.b64decode(cert_b64).decode())


def cert_signing_bytes(cert: dict) -> bytes:
    """Bytes canonicos assinados pelo servidor: cert sem o campo 'signature'."""
    content = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(content, sort_keys=True).encode()


# ── X25519 public key <-> base64 (raw) ────────────────────────────────────

def x25519_pub_from_b64(b64: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(base64.b64decode(b64))


def x25519_pub_to_b64(pub: X25519PublicKey) -> str:
    return base64.b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def generate_signed_eph(signing_key) -> tuple[X25519PrivateKey, str, str]:
    """Gera par X25519 efemero e assina a public key com signing_key (RSA-PSS).

    Retorna (eph_private, eph_pub_b64, sig_b64).
    """
    eph = X25519PrivateKey.generate()
    eph_pub_b64 = x25519_pub_to_b64(eph.public_key())
    sig_b64 = rsa_sign(signing_key, base64.b64decode(eph_pub_b64))
    return eph, eph_pub_b64, sig_b64


def generate_eph() -> tuple[X25519PrivateKey, str]:
    """Gera par X25519 efemero (sem assinatura). Retorna (eph_private, eph_pub_b64)."""
    eph = X25519PrivateKey.generate()
    return eph, x25519_pub_to_b64(eph.public_key())


def sts_transcript(signer_eph_b64: str, peer_eph_b64: str, id_a: str, id_b: str) -> bytes:
    """Transcript STS assinado: ephs + identidades dos dois participantes.

    - Ligar as DUAS ephs (a do par e gerada de novo a cada sessao) impede
      replay: uma assinatura gravada nao bate certo com a eph fresca numa
      sessao futura.
    - Ligar os usernames (em ordem canonica, independente de quem inicia)
      impede unknown key-share / misbinding: a assinatura afirma com QUEM
      a sessao e, nao apenas que a eph e do assinante.
    """
    a, b = sorted((id_a, id_b))
    ids = b"\x1f" + a.encode() + b"\x1f" + b.encode()
    return base64.b64decode(signer_eph_b64) + base64.b64decode(peer_eph_b64) + ids


def parse_signed_eph_with_cert(payload: str) -> tuple[str, str, dict]:
    """Faz parse do formato eph_pub_b64.sig_b64.cert_b64 (sig pode ser vazio)."""
    eph_pub_b64, sig_b64, cert_b64 = payload.split(".", 2)
    cert = json.loads(base64.b64decode(cert_b64).decode())
    return eph_pub_b64, sig_b64, cert


def pbkdf2_hash(password: str, salt: bytes) -> bytes:
    """Deriva hash de password com PBKDF2-SHA256 (600k iterações, 32 bytes)."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode())


def derive_server_session_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """Deriva chaves de transporte cliente-servidor separadas por sentido.

    Retorna (c2s, s2c): chave usada cliente->servidor e servidor->cliente.
    Separar por direcao elimina por construcao o risco de reutilizacao de
    nonce AES-GCM entre os dois emissores (mesma abordagem do canal P2P).
    """
    def _kdf(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"signalum-v1-server-salt",
            info=info,
        ).derive(shared_secret)

    return _kdf(b"signalum-server-v1:c2s"), _kdf(b"signalum-server-v1:s2c")


def ratchet_key(key: bytes) -> bytes:
    """Avança o symmetric ratchet: deriva a próxima chave (one-way via HKDF).

    Chamado após cada cifra/decifra P2P. A chave anterior é descartada,
    garantindo forward secrecy por mensagem: comprometer key_N não expõe
    mensagens cifradas com key_0..key_{N-1}.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"signalum-chat-ratchet-v1",
    ).derive(key)


def encrypt_counter_aead(key: bytes, plaintext: str, counter: int) -> str:
    """Cifra com AES-GCM usando counter como Associated Data."""
    nonce = os.urandom(12)
    ad = str(counter).encode()
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), ad)
    payload = f"{counter}.".encode() + nonce + ct
    return base64.b64encode(payload).decode()


def decrypt_counter_aead(key: bytes, b64_payload: str, last_counter: int) -> tuple[str | None, int | None]:
    """Decifra payload com protecao anti-replay por contador estritamente crescente."""
    try:
        data = base64.b64decode(b64_payload)
        header, body = data.split(b".", 1)
        counter = int(header.decode())
        if counter <= last_counter:
            return None, None

        nonce, ct = body[:12], body[12:]
        ad = str(counter).encode()
        plaintext = AESGCM(key).decrypt(nonce, ct, ad).decode()
        return plaintext, counter
    except Exception:
        return None, None
