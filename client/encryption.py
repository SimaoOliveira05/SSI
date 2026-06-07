import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key,
)
import persistence
from crypto_transport import (
    cert_signing_bytes,
    decrypt_counter_aead,
    derive_server_session_keys as _derive_server_session_keys,
    encode_cert,
    encrypt_counter_aead,
    generate_eph,
    ratchet_key,
    rsa_sign,
    rsa_verify,
    sts_transcript,
    x25519_pub_from_b64,
)


class SecurityManager:
    def __init__(self, keys_dir: str):
        self.keys_dir = keys_dir
        self.private_key = None          # RSAPrivateKey — assinatura
        self.username: str | None = None
        self.prekeys: dict[str, X25519PrivateKey] = {}  # prekey_id -> X25519PrivateKey
        self.ephemeral_private = None
        self._sts_self_eph_b64 = None   # eph pub local do handshake P2P em curso
        self._sts_peer_id = None        # iniciador: username certificado do peer
        self._sts_pending = None        # responder: dados p/ verificar EPH_CONFIRM

        self.sessions = {}
        self.send_counters = {}
        self.recv_counters = {}

        self.server_c2s_key = None   # cliente -> servidor (cliente cifra)
        self.server_s2c_key = None   # servidor -> cliente (cliente decifra)
        self.server_send_counter = 0
        self.server_recv_counter = 0

        self.my_cert = None
        self.server_public_key = persistence.load_server_public_key(self.keys_dir)

    # =========================================================================
    # KEY MANAGEMENT
    # =========================================================================

    def generate_keys(self, name: str, password: str) -> str:
        """Gera par RSA-2048 e retorna pub_b64 (PEM em base64)."""
        self.username = name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        persistence.save_private_key(self.keys_dir, name, self.private_key, password)
        return persistence.pub_key_to_b64(self.private_key.public_key())

    def sign_registration(self, pub_b64: str) -> str:
        """Assina a própria chave pública para proof of possession (CSR-like)."""
        return rsa_sign(self.private_key, pub_b64.encode())

    def load_keys(self, name: str, password: str) -> bool:
        try:
            self.private_key = persistence.load_private_key(self.keys_dir, name, password)
            self.username = name
            self.prekeys, migrated = persistence.load_prekey_store(
                self.keys_dir, name, self.private_key)
            if migrated:                       # legado em claro -> reescreve cifrado
                persistence.save_prekey_store(
                    self.keys_dir, name, self.prekeys, self.private_key.public_key())
            return True
        except Exception:
            return False

    def load_certificate(self, name: str) -> bool:
        cert = persistence.load_certificate(self.keys_dir, name)
        if cert is None:
            return False
        self.my_cert = cert
        return True

    # =========================================================================
    # SIGNING / VERIFICATION
    # =========================================================================

    def sign(self, data: bytes) -> str:
        return rsa_sign(self.private_key, data)

    def verify_certificate(self, cert: dict) -> bool:
        if not self.server_public_key:
            return False
        return rsa_verify(self.server_public_key, cert.get("signature", ""), cert_signing_bytes(cert))

    def verify_prekey(self, prekey: dict, cert: dict) -> bool:
        """Verifica que a pre-key foi assinada pelo dono (usando o seu certificado)."""
        return self._verify_sig(cert, prekey.get("sig", ""), (prekey["id"] + prekey["pub"]).encode())

    # =========================================================================
    # GROUP KEY PAYLOAD (sign + verify wrapper)
    # =========================================================================

    def sign_key_payload(self, encrypted_key_b64: str) -> str:
        """Assina o payload da sender key cifrada e anexa o certificado."""
        sig_b64 = self.sign(encrypted_key_b64.encode())
        cert_b64 = encode_cert(self.my_cert)
        return f"{encrypted_key_b64}.{sig_b64}.{cert_b64}"

    def verify_key_payload(self, key_payload: str) -> tuple[bool, str, str]:
        """Verifica assinatura e certificado de um GROUP_KEY recebido.
        Retorna (ok, encrypted_key_b64, cert_username).
        O encrypted_key_b64 tem formato: prekey_id.eph_pub.ct
        """
        try:
            parts = key_payload.rsplit(".", 2)
            if len(parts) != 3:
                return False, "", ""
            encrypted_key_b64, sig_b64, cert_b64 = parts
            cert = json.loads(base64.b64decode(cert_b64).decode())
            if not self.verify_certificate(cert):
                return False, "", ""
            if not self._verify_sig(cert, sig_b64, encrypted_key_b64.encode()):
                return False, "", ""
            return True, encrypted_key_b64, cert.get("username", "")
        except Exception:
            return False, "", ""

    # =========================================================================
    # EPHEMERAL HANDSHAKE (P2P e transporte)
    # =========================================================================

    def _cert_pubkey(self, cert: dict):
        return load_pem_public_key(base64.b64decode(cert["pubkey"]))

    def _verify_sig(self, cert: dict, sig_b64: str, data: bytes) -> bool:
        try:
            return rsa_verify(self._cert_pubkey(cert), sig_b64, data)
        except Exception:
            return False

    def build_eph_init(self) -> str:
        """STS msg 1 (iniciador): eph SEM assinatura (nada de replayable).

        Formato eph_pub..cert (campo de assinatura vazio).
        """
        self.ephemeral_private, eph_pub_b64 = generate_eph()
        self._sts_self_eph_b64 = eph_pub_b64
        cert_b64 = encode_cert(self.my_cert)
        return f"{eph_pub_b64}..{cert_b64}"

    def build_eph_response(self, peer_eph_pub_b64: str, peer_cert: dict) -> str:
        """STS msg 2 (recetor): gera ephB e assina (ephB || ephA || ids)."""
        self.ephemeral_private, eph_pub_b64 = generate_eph()
        self._sts_self_eph_b64 = eph_pub_b64
        peer_id = peer_cert.get("username", "")
        sig_b64 = self.sign(sts_transcript(eph_pub_b64, peer_eph_pub_b64, self.username, peer_id))
        self._sts_pending = {
            "peer_cert": peer_cert,
            "peer_id": peer_id,
            "self_eph": eph_pub_b64,
            "peer_eph": peer_eph_pub_b64,
        }
        cert_b64 = encode_cert(self.my_cert)
        return f"{eph_pub_b64}.{sig_b64}.{cert_b64}"

    def verify_eph_response(self, peer_eph_pub_b64: str, sig_b64: str, peer_cert: dict) -> tuple[bool, str]:
        """Iniciador verifica msg 2: cert valido + sig do peer sobre (ephB || ephA || ids)."""
        if not self.verify_certificate(peer_cert):
            return False, "Invalid certificate — possible MITM!"
        peer_id = peer_cert.get("username", "")
        data = sts_transcript(peer_eph_pub_b64, self._sts_self_eph_b64, self.username, peer_id)
        if not self._verify_sig(peer_cert, sig_b64, data):
            return False, "STS signature mismatch — possible replay/MITM!"
        self._sts_peer_id = peer_id
        return True, ""

    def build_eph_confirm(self, peer_eph_pub_b64: str) -> str:
        """STS msg 3 (iniciador): assina (ephA || ephB || ids) p/ confirmar a sessao."""
        return self.sign(sts_transcript(
            self._sts_self_eph_b64, peer_eph_pub_b64, self.username, self._sts_peer_id or ""))

    def verify_eph_confirm(self, sig_b64: str) -> tuple[bool, str]:
        """Recetor verifica msg 3: sig do iniciador sobre (ephA || ephB || ids)."""
        p = self._sts_pending
        self._sts_pending = None
        if not p:
            return False, "No pending handshake."
        data = sts_transcript(p["peer_eph"], p["self_eph"], self.username, p["peer_id"])
        if not self._verify_sig(p["peer_cert"], sig_b64, data):
            return False, "STS confirm signature mismatch — possible replay/MITM!"
        return True, ""

    def establish_session(self, my_username: str, target: str, peer_eph_pub_b64: str):
        """Finaliza handshake P2P e deriva chaves de sessao send/recv."""
        peer_eph_pub = self._b64_to_x25519_pub(peer_eph_pub_b64)
        shared_secret = self.ephemeral_private.exchange(peer_eph_pub)
        key_ab = self._derive_key(shared_secret, b"signalum-chat-v1:a2b")
        key_ba = self._derive_key(shared_secret, b"signalum-chat-v1:b2a")
        if my_username < target:
            self.sessions[target] = {"send": key_ab, "recv": key_ba}
        else:
            self.sessions[target] = {"send": key_ba, "recv": key_ab}
        self.send_counters[target] = 0
        self.recv_counters[target] = 0
        self.ephemeral_private = None

    # =========================================================================
    # RATCHET CHANNEL PRIMITIVES (partilhadas por P2P e transporte)
    # =========================================================================

    def _encrypt_and_ratchet(self, key: bytes, counter: int, plaintext: str) -> tuple[str, bytes]:
        """Cifra e avança o ratchet. Devolve (ciphertext, next_key); a chave anterior deve ser descartada."""
        ct = encrypt_counter_aead(key, plaintext, counter)
        return ct, ratchet_key(key)

    def _decrypt_and_ratchet(self, key: bytes, last_counter: int, b64_payload: str) -> tuple[str | None, bytes | None, int]:
        """Decifra e avança o ratchet. Devolve (plaintext, next_key, new_counter) ou (None, None, last_counter) em falha."""
        plaintext, new_counter = decrypt_counter_aead(key, b64_payload, last_counter)
        if plaintext is None:
            return None, None, last_counter
        return plaintext, ratchet_key(key), new_counter

    # =========================================================================
    # MESSAGE ENCRYPTION (P2P e grupos)
    # =========================================================================

    def encrypt_message(self, target_id: str, plaintext: str, key: bytes = None) -> str:
        session = self.sessions.get(target_id)
        enc_key = key if key is not None else (session or {}).get("send")
        if enc_key is None:
            return None
        counter = self.send_counters.get(target_id, 0) + 1
        self.send_counters[target_id] = counter
        ct, next_key = self._encrypt_and_ratchet(enc_key, counter, plaintext)
        if key is None and session is not None:  # ratchet só em P2P, não em grupo
            session["send"] = next_key
        return ct

    def decrypt_message(self, target_id: str, b64_payload: str, key: bytes = None) -> tuple[str | None, int]:
        session = self.sessions.get(target_id)
        dec_key = key if key is not None else (session or {}).get("recv")
        if dec_key is None:
            return None, 0
        last_recv = self.recv_counters.get(target_id, 0)
        try:
            counter = int(base64.b64decode(b64_payload).split(b".", 1)[0].decode())
            if counter <= last_recv:
                return "[REPLAY DETECTED]", counter
        except Exception:
            return None, 0
        plaintext, next_key, new_counter = self._decrypt_and_ratchet(dec_key, last_recv, b64_payload)
        if plaintext is None:
            return None, 0
        self.recv_counters[target_id] = new_counter
        if key is None and session is not None:  # ratchet só em P2P, não em grupo
            session["recv"] = next_key
        return plaintext, new_counter

    # =========================================================================
    # PRE-KEYS
    # =========================================================================

    def generate_prekeys(self, n: int = 10) -> list[dict]:
        """Gera n pre-keys X25519, guarda privadas localmente, retorna [{id, pub, sig}]."""
        result = []
        for _ in range(n):
            pk_id = base64.b64encode(os.urandom(16)).decode().rstrip("=")
            priv = X25519PrivateKey.generate()
            pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            pub_b64 = base64.b64encode(pub_raw).decode()
            sig_b64 = self.sign((pk_id + pub_b64).encode())
            self.prekeys[pk_id] = priv
            result.append({"id": pk_id, "pub": pub_b64, "sig": sig_b64})
        if self.username:
            persistence.save_prekey_store(
                self.keys_dir, self.username, self.prekeys, self.private_key.public_key())
        return result

    def _consume_prekey(self, prekey_id: str) -> X25519PrivateKey | None:
        priv = self.prekeys.pop(prekey_id, None)
        if priv is not None and self.username:
            persistence.save_prekey_store(
                self.keys_dir, self.username, self.prekeys, self.private_key.public_key())
        return priv

    # =========================================================================
    # PRE-KEY BASED ENCRYPTION (grupos e mensagens offline)
    # =========================================================================

    def encrypt_with_prekey(self, plaintext: bytes, prekey_id: str, prekey_pub_b64: str,
                             salt: bytes, info: bytes) -> str:
        """DH efemero + HKDF + AES-GCM usando pre-key publica do destinatario.
        Formato: prekey_id.eph_pub_b64.nonce_ct_b64
        """
        prekey_pub = X25519PublicKey.from_public_bytes(base64.b64decode(prekey_pub_b64))
        eph_priv = X25519PrivateKey.generate()
        shared = eph_priv.exchange(prekey_pub)
        enc_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)
        nonce = os.urandom(12)
        ct = AESGCM(enc_key).encrypt(nonce, plaintext, None)
        eph_pub_b64 = base64.b64encode(
            eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        return f"{prekey_id}.{eph_pub_b64}.{base64.b64encode(nonce + ct).decode()}"

    def decrypt_with_prekey_payload(self, payload: str, salt: bytes, info: bytes) -> bytes:
        """Decifra payload (prekey_id.eph_pub.ct) usando pre-key privada local (consumida apos uso)."""
        prekey_id, eph_pub_b64, ct_b64 = payload.split(".", 2)
        priv = self._consume_prekey(prekey_id)
        if priv is None:
            raise ValueError(f"No pre-key with id '{prekey_id}'")
        eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(eph_pub_b64))
        shared = priv.exchange(eph_pub)
        enc_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)
        data = base64.b64decode(ct_b64)
        return AESGCM(enc_key).decrypt(data[:12], data[12:], None)

    def encrypt_key_for_member(self, key: bytes, prekey: dict) -> str:
        """Cifra sender key para membro usando a sua pre-key."""
        return self.encrypt_with_prekey(key, prekey["id"], prekey["pub"],
                                        b"signalum-v1-sender-key-salt",
                                        b"signalum-sender-key-v1")

    def encrypt_offline_msg(self, message: str, prekey: dict) -> str:
        """Cifra mensagem offline para a pre-key do destinatario e assina-a
        com a chave RSA do remetente (envelope blob.sig.cert)."""
        blob = self.encrypt_with_prekey(message.encode(), prekey["id"], prekey["pub"],
                                        b"signalum-v1-offline-msg-salt",
                                        b"signalum-offline-msg-v1")
        return self.sign_key_payload(blob)

    def decrypt_received_key(self, payload: str) -> bytes:
        """Decifra sender key recebida (pre-key payload)."""
        return self.decrypt_with_prekey_payload(payload,
                                                b"signalum-v1-sender-key-salt",
                                                b"signalum-sender-key-v1")

    def decrypt_offline_msg(self, payload: str) -> tuple[str, str]:
        """Verifica assinatura+cert do remetente e decifra. Retorna (texto, sender).

        Lanca ValueError se nao autenticar (mensagem rejeitada, nao mostrada).
        """
        ok, blob, sender = self.verify_key_payload(payload)
        if not ok:
            raise ValueError("offline message authentication failed")
        text = self.decrypt_with_prekey_payload(blob,
                                                b"signalum-v1-offline-msg-salt",
                                                b"signalum-offline-msg-v1").decode()
        return text, sender

    # =========================================================================
    # SERVER-CLIENT TRANSPORT SESSION
    # =========================================================================

    def verify_server_eph(self, server_eph_payload: str) -> tuple[bool, str]:
        if not self.server_public_key:
            return False, ""
        try:
            eph_pub_b64, sig_b64 = server_eph_payload.split(".", 1)
        except Exception:
            return False, ""
        if not rsa_verify(self.server_public_key, sig_b64, base64.b64decode(eph_pub_b64)):
            return False, ""
        return True, eph_pub_b64

    def establish_server_session(self, server_eph_pub_b64: str) -> str:
        client_eph = X25519PrivateKey.generate()
        client_eph_pub_b64 = base64.b64encode(
            client_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        server_eph_pub = self._b64_to_x25519_pub(server_eph_pub_b64)
        shared_secret = client_eph.exchange(server_eph_pub)
        self.server_c2s_key, self.server_s2c_key = _derive_server_session_keys(shared_secret)
        self.server_send_counter = 0
        self.server_recv_counter = 0
        return client_eph_pub_b64


    def encrypt_for_server(self, plaintext: str) -> str:
        if not self.server_c2s_key:
            raise RuntimeError("No active server session.")
        self.server_send_counter += 1
        ct, self.server_c2s_key = self._encrypt_and_ratchet(self.server_c2s_key, self.server_send_counter, plaintext)
        return ct

    def decrypt_from_server(self, b64_payload: str) -> str | None:
        if not self.server_s2c_key:
            return None
        plaintext, next_key, counter = self._decrypt_and_ratchet(self.server_s2c_key, self.server_recv_counter, b64_payload)
        if plaintext is None:
            return None
        self.server_recv_counter = counter
        self.server_s2c_key = next_key
        return plaintext

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _b64_to_x25519_pub(self, b64: str) -> X25519PublicKey:
        return x25519_pub_from_b64(b64)

    def _derive_key(self, shared_secret: bytes, info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"signalum-v1-peer-salt",
            info=info,
        ).derive(shared_secret)
