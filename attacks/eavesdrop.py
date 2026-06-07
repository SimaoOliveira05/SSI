import asyncio
from datetime import datetime

# =============================================================================
# Passive MITM Proxy — Eavesdropper
#
# Sits between client (port 9999) and server (port 8888) and SILENTLY forwards
# every byte in both directions, printing a categorised log of each line.
#
# Unlike `mitm.py` (which tampers with EPH messages) and `replay_attack.py`
# (which floods replays), this script does NOT modify anything — it only
# observes. Its purpose is to demonstrate that, with all the cryptographic
# protections of CryptUM in place, a passive network attacker only sees:
#
#   - ENC:<base64...>      ← transport ciphertext (client ↔ server)
#   - EPH/PEER_EPH/...     ← public ephemeral keys + signatures
#   - MSG:<base64...>      ← P2P / group ciphertext relayed by the server
#
# Nothing readable. No plaintext. No keys. No usernames after login.
# =============================================================================

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9999
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

# Truncate long payloads in the log so the terminal stays readable.
PAYLOAD_PREVIEW = 60


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _preview(payload: str) -> str:
    if len(payload) <= PAYLOAD_PREVIEW:
        return payload
    return f"{payload[:PAYLOAD_PREVIEW]}... ({len(payload)} chars total)"


def _classify(msg_type: str) -> str:
    """Human-readable note about what this opaque payload means."""
    if msg_type == "ENC":
        return "transport-layer ciphertext (AES-GCM, server↔client)"
    if msg_type in ("SERVER_EPH", "CLIENT_EPH"):
        return "transport handshake (X25519 + RSA-PSS signature)"
    if msg_type in ("EPH", "PEER_EPH", "EPH_CONFIRM"):
        return "P2P STS handshake material (signed public keys)"
    if msg_type == "MSG":
        return "P2P ciphertext (server cannot read)"
    if msg_type.startswith("GROUP_"):
        return "group control / ciphertext (server cannot read message body)"
    return ""


def _log(direction: str, line: str):
    text = line.strip()
    if not text:
        return
    msg_type, sep, payload = text.partition(":")
    note = _classify(msg_type)
    arrow = "C → S" if direction == "C2S" else "S → C"
    print(f"[{_ts()}] {arrow}  {msg_type:<16} {_preview(payload) if sep else ''}")
    if note:
        print(f"                  └─ {note}")


async def relay(direction: str, src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    """Forward every line verbatim. Observe, never modify."""
    try:
        async for line_bytes in src:
            _log(direction, line_bytes.decode(errors="replace"))
            dst.write(line_bytes)
            await dst.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle_client(client_reader: asyncio.StreamReader,
                        client_writer: asyncio.StreamWriter):
    addr = client_writer.get_extra_info("peername")
    print(f"\n[EAVESDROP] ── New connection from {addr} ──")
    try:
        server_reader, server_writer = await asyncio.open_connection(
            SERVER_HOST, SERVER_PORT
        )
    except OSError as e:
        print(f"[EAVESDROP] Cannot reach server {SERVER_HOST}:{SERVER_PORT}: {e}")
        client_writer.close()
        return

    await asyncio.gather(
        relay("C2S", client_reader, server_writer),
        relay("S2C", server_reader, client_writer),
    )
    print(f"[EAVESDROP] ── Connection from {addr} closed ──\n")


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"[EAVESDROP] Passive proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[EAVESDROP] Forwarding (untouched) to {SERVER_HOST}:{SERVER_PORT}")
    print(f"[EAVESDROP] Mode: READ-ONLY — no tampering, no injection.\n")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[EAVESDROP] Stopped.")
