import asyncio
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.dirname(BASE_DIR)
sys.path.append(BASE_DIR)
sys.path.append(SRC_DIR)

from handlers import receive_messages, send_messages
import state as client_state
from protocol import Msg

HOST = "127.0.0.1"
PORT = 8888

if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        pass


async def _establish_transport(reader, writer):
    """Lê SERVER_EPH, verifica assinatura do servidor e envia CLIENT_EPH.

    Chamado imediatamente após connect — antes de qualquer input do utilizador.
    Retorna False se o servidor não se autenticar (possível MITM).
    """
    try:
        line_bytes = await asyncio.wait_for(reader.readline(), timeout=10.0)
    except asyncio.TimeoutError:
        print("[ERROR] Server did not send transport key in time.")
        return False

    text = line_bytes.decode().strip()
    msg_type, _, payload = text.partition(":")
    if msg_type != Msg.SERVER_EPH:
        print(f"[ERROR] Expected SERVER_EPH, got '{msg_type}'.")
        return False

    ok, server_eph_pub_b64 = client_state.state.security.verify_server_eph(payload)
    if not ok:
        print("[ERROR] Server authentication failed — possible MITM! Aborting.")
        return False

    client_eph_pub_b64 = client_state.state.security.establish_server_session(server_eph_pub_b64)
    writer.write(f"{Msg.CLIENT_EPH}:{client_eph_pub_b64}\n".encode())
    await writer.drain()
    return True


async def main():
    """Liga ao servidor, estabelece canal cifrado e corre loops de I/O."""
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to {HOST}:{PORT}. Is the server running?")
        sys.exit(1)

    client_state.set_connection(reader, writer)

    if not await _establish_transport(reader, writer):
        writer.close()
        await writer.wait_closed()
        sys.exit(1)

    try:
        await asyncio.gather(
            receive_messages(),
            send_messages(),
        )
    except asyncio.CancelledError:
        pass
    except (asyncio.IncompleteReadError, ConnectionResetError):
        print("[INFO] Connection closed.")
    finally:
        if client_state.writer_global:
            client_state.writer_global.close()
            await client_state.writer_global.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Client stopped.")
