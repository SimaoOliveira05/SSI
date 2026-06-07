import asyncio
import base64
import json
import os
import sys

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SRC_DIR)

import state
from crypto_transport import derive_server_session_keys, generate_signed_eph
from handlers import (
    handle_chat,
    handle_exit,
    handle_group_add,
    handle_group_create,
    handle_group_key,
    handle_group_kick,
    handle_group_list,
    handle_group_msg,
    handle_in_chat,
    handle_list,
    handle_login,
    handle_offline_msg,
    handle_prekey_get,
    handle_prekey_upload,
    handle_register,
    handle_salt_request,
    post_login_init,
)
from utils import b64_to_x25519_pub, log, send, send_raw, server_decrypt, server_msg
from persistence import load_or_generate_server_keys, load_prekeys, load_users
from protocol import Cmd, Msg


async def _do_server_handshake(reader, writer) -> state.Client | None:
    """Handshake de transporte: servidor autentica-se, cliente é sempre anónimo.

    Retorna transport_client ou None em falha.
    """
    server_eph, server_eph_pub_b64, eph_sig_b64 = generate_signed_eph(state.server_private_key)
    await send_raw(writer, Msg.SERVER_EPH, f"{server_eph_pub_b64}.{eph_sig_b64}")

    try:
        line_bytes = await asyncio.wait_for(reader.readline(), timeout=300.0)
    except asyncio.TimeoutError:
        return None
    if not line_bytes:
        return None

    text = line_bytes.decode().strip()
    msg_type, _, payload = text.partition(":")

    if msg_type != Msg.CLIENT_EPH:
        await send_raw(writer, Msg.SERVER, "[ERROR] Expected CLIENT_EPH.")
        return None

    try:
        client_eph_pub = b64_to_x25519_pub(payload)
    except Exception:
        return None
    shared_secret = server_eph.exchange(client_eph_pub)
    c2s_key, s2c_key = derive_server_session_keys(shared_secret)

    return state.Client(username="", writer=writer, c2s_key=c2s_key, s2c_key=s2c_key)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Loop principal por conexão cliente.

    Fases:
    1) Handshake de transporte (sempre, autenticado pelo servidor; opcionalmente
       mútuo no caso de login);
    2) Pós-handshake: tudo cifrado em ENC; dispatch de comandos / relay de chat.
    """
    peer = writer.get_extra_info("peername")
    log("conn", f"new TCP connection from {peer}")

    transport_client = await _do_server_handshake(reader, writer)
    if transport_client is None:
        log("conn", f"handshake failed / aborted for {peer}")
        writer.close()
        await writer.wait_closed()
        return

    # Challenge-response: emite um nonce por sessão. O cliente vai usá-lo no /login
    # para provar conhecimento do PBKDF2-hash da password sem o enviar.
    transport_client.nonce = os.urandom(16)
    await send(writer, Msg.NONCE, base64.b64encode(transport_client.nonce).decode(), client=transport_client)

    username: str | None = None
    log("auth", f"anonymous transport up for {peer} (awaiting /register or /login)")
    await server_msg(writer, "Welcome to SignalUM! Use /register or /login.", client=transport_client)

    try:
        async for line_bytes in reader:
            text = line_bytes.decode().strip()
            if not text:
                continue

            # Tudo após o handshake vem em ENC.
            enc_type, _, enc_payload = text.partition(":")
            if enc_type != Msg.ENC:
                log("warn", f"non-ENC frame from '{username or '<anon>'}' (type={enc_type!r}) — dropped")
                continue

            decrypted = server_decrypt(transport_client, enc_payload)
            if decrypted is None:
                log("warn", f"transport decrypt failed for '{username or '<anon>'}' (counter/MAC) — dropped")
                continue

            msg_type, _, payload = decrypted.partition(":")
            log("recv", f"from '{username or '<anon>'}': {msg_type}"
                + (f" {payload[:60]}{'...' if len(payload) > 60 else ''}" if payload else ""))

            in_chat = bool(
                username and state.online_users.get(username)
                and state.online_users[username].chatting_with
            )

            if in_chat and msg_type != Msg.CMD:
                # Mensagens de chat (EPH/EPH_CONFIRM/MSG) — relay puro.
                await handle_in_chat(writer, username, msg_type, payload)
                continue

            if in_chat and msg_type == Msg.CMD:
                verb = payload.strip().split(" ", 1)[0].lower()
                if verb == Cmd.EXIT:
                    await handle_exit(writer, username)
                    continue
                if verb == Cmd.QUIT:
                    await handle_exit(writer, username)
                    await server_msg(writer, "[OK] Bye!", client=transport_client)
                    break
                # Outros comandos (ex.: /prekey_get, /group_key ao ser convidado
                # para um grupo durante um chat) seguem o fluxo normal abaixo.

            if msg_type != Msg.CMD:
                await server_msg(writer, f"[ERROR] Unexpected message type '{msg_type}'.", client=transport_client)
                continue

            parts = payload.strip().split(" ", 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd == Cmd.SALT_REQUEST:
                if username is not None:
                    await server_msg(writer, "[ERROR] Already authenticated.", client=transport_client)
                    continue
                await handle_salt_request(writer, args, transport_client)
                continue

            if cmd == Cmd.REGISTER:
                if username is not None:
                    await server_msg(writer, "[ERROR] Already authenticated.", client=transport_client)
                    continue
                registered_name = await handle_register(writer, args, transport_client)
                if registered_name is None:
                    continue
                if registered_name in state.online_users:
                    await server_msg(writer, f"[ERROR] '{registered_name}' is already online.", client=transport_client)
                    continue
                transport_client.username = registered_name
                state.online_users[registered_name] = transport_client
                username = registered_name
                log("auth", f"REGISTER — new user '{registered_name}' (PBKDF2 + cert)")
                await post_login_init(writer, registered_name, transport_client)

            elif cmd == Cmd.LOGIN:
                if username is not None:
                    await server_msg(writer, "[ERROR] Already authenticated.", client=transport_client)
                    continue
                logged_name = await handle_login(writer, args, transport_client)
                if logged_name is None:
                    continue
                if logged_name in state.online_users:
                    await server_msg(writer, f"[ERROR] '{logged_name}' is already online.", client=transport_client)
                    continue
                transport_client.username = logged_name
                state.online_users[logged_name] = transport_client
                username = logged_name
                log("auth", f"LOGIN ok — '{logged_name}' (PBKDF2 password, transport AES-GCM up)")
                await post_login_init(writer, logged_name, transport_client)

            elif cmd == Cmd.QUIT:
                await server_msg(writer, "[OK] Bye!", client=transport_client)
                break

            elif username is None:
                await server_msg(writer, "[ERROR] Please /register first.", client=transport_client)

            elif cmd == Cmd.CHAT:
                await handle_chat(writer, username, args)

            elif cmd == Cmd.GROUP_CREATE:
                await handle_group_create(writer, username, args)

            elif cmd == Cmd.GROUP_MSG:
                await handle_group_msg(writer, username, args)

            elif cmd == Cmd.GROUP_KEY:
                await handle_group_key(writer, username, args)

            elif cmd == Cmd.GROUP_LIST:
                await handle_group_list(writer, username)

            elif cmd == Cmd.LIST:
                await handle_list(writer, username)

            elif cmd == Cmd.OFFLINE_MSG:
                await handle_offline_msg(writer, username, args)

            elif cmd == Cmd.PREKEY_UPLOAD:
                await handle_prekey_upload(writer, username, args)

            elif cmd == Cmd.PREKEY_GET:
                await handle_prekey_get(writer, username, args)

            elif cmd == Cmd.GROUP_ADD:
                await handle_group_add(writer, username, args)

            elif cmd == Cmd.GROUP_KICK:
                await handle_group_kick(writer, username, args)

            else:
                await server_msg(writer, f"[ERROR] Unknown command '{cmd}'.", client=transport_client)

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        if username is not None:
            log("conn", f"disconnect '{username}'")
            client = state.online_users.pop(username, None)
            if client and client.chatting_with and client.chatting_with in state.online_users:
                peer_client = state.online_users[client.chatting_with]
                peer_client.chatting_with = None
                await send(peer_client.writer, Msg.CHAT_ENDED, username, client=peer_client)
                await server_msg(
                    peer_client.writer,
                    f"[INFO] '{username}' disconnected.",
                    client=peer_client,
                )

            # Grupos efemeros: ao desligar, o utilizador sai de todos os grupos.
            # Restantes membros online sao notificados; grupos vazios destruidos.
            for group_id, ginfo in list(state.groups.items()):
                if username not in ginfo["members"]:
                    continue
                ginfo["members"].remove(username)
                if not ginfo["members"]:
                    del state.groups[group_id]
                    continue
                removed_payload = json.dumps({
                    "group_id": group_id,
                    "group_name": ginfo["name"],
                    "kicked_member": username,
                })
                for m in ginfo["members"]:
                    if m in state.online_users:
                        m_client = state.online_users[m]
                        await send(m_client.writer, Msg.GROUP_MEMBER_REMOVED, removed_payload, client=m_client)
        writer.close()
        await writer.wait_closed()


async def main():
    """Bootstrap do servidor: chaves, estado persistido e listener TCP."""
    os.makedirs(state.DATA_DIR, exist_ok=True)
    load_or_generate_server_keys()
    state.registered_users = load_users()
    state.prekeys = load_prekeys()

    server = await asyncio.start_server(handle_client, state.HOST, state.PORT)
    print("=" * 70)
    print(f" SignalUM server  ·  listening on {state.HOST}:{state.PORT}")
    print(" Log columns:  [hh:mm:ss.mmm]  CATEGORY   detail")
    print(" Categories:  CONN  AUTH  RECV  RELAY  GROUP  OFFLINE  WARN")
    print("=" * 70)
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SignalUM] Server stopped.")
