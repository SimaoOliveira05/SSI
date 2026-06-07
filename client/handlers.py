import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys

from crypto_transport import parse_signed_eph_with_cert, pbkdf2_hash
from protocol import Cmd, Msg
import state as client_state
from state import KEYS_DIR, chat_ack_queue, prekey_resp_queue, register_ack_queue, salt_queue, state
from ui import clear, print_info, print_sent_message, replace_emojis


# ── Transport ─────────────────────────────────────────────────────────────

async def send_raw(msg_type: str, payload: str = ""):
    """Envia mensagem sem envelope ENC (bootstrap de handshake)."""
    line = f"{msg_type}:{payload}\n" if payload else f"{msg_type}\n"
    client_state.writer_global.write(line.encode())
    await client_state.writer_global.drain()


async def send(msg_type: str, payload: str = ""):
    """Envia mensagem tipada; cifra automaticamente quando a sessao esta ativa."""
    line = f"{msg_type}:{payload}" if payload else msg_type
    if state.security.server_c2s_key:
        encrypted = state.security.encrypt_for_server(line)
        client_state.writer_global.write(f"{Msg.ENC}:{encrypted}\n".encode())
    else:
        client_state.writer_global.write(f"{line}\n".encode())
    await client_state.writer_global.drain()


async def send_cmd(command: str):
    """Atalho para comando de aplicacao (Msg.CMD)."""
    await send(Msg.CMD, command)


def drain_queue(q: asyncio.Queue):
    """Esvazia fila para evitar ler eventos stale de operacoes anteriores."""
    while not q.empty():
        try:
            q.get_nowait()
        except asyncio.QueueEmpty:
            break


# ── Helpers (partilhados por handlers de saida e de entrada) ──────────────

def _find_group_by_name(pattern: str) -> str | None:
    """Devolve o group_id cujo nome começa com `pattern` (case-insensitive), ou None."""
    return next(
        (gid for gid, g in state.groups.items()
         if g["name"].lower().startswith(pattern.lower())),
        None
    )

async def _prompt_secret(prompt: str) -> str | None:
    try:
        return await asyncio.to_thread(getpass.getpass, prompt)
    except (EOFError, KeyboardInterrupt):
        print_info("[ERROR] Password input cancelled.")
        return None


async def get_prekey_for(target: str, timeout: float = 10.0) -> dict | None:
    """Pede uma pre-key ao servidor para target e aguarda a resposta."""
    drain_queue(prekey_resp_queue)
    await send_cmd(f"{Cmd.PREKEY_GET} {target}")
    try:
        return await asyncio.wait_for(prekey_resp_queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        print_info(f"[ERROR] Timeout waiting for pre-key of '{target}'.")
        return None


async def upload_prekeys():
    """Gera e faz upload de 10 pre-keys para o servidor."""
    prekeys = state.security.generate_prekeys(n=10)
    payload = base64.b64encode(json.dumps(prekeys).encode()).decode()
    await send_cmd(f"{Cmd.PREKEY_UPLOAD} {payload}")


def _accept_certificate(cert: dict) -> bool:
    if not state.security.verify_certificate(cert):
        print_info("[ERROR] Certificate rejected — invalid server signature (possible MITM).")
        return False
    expected = state.pending_register
    if expected is None:
        print_info("[ERROR] Unexpected certificate received (no pending registration). Ignored.")
        return False
    if cert.get("username") != expected["username"] or cert.get("pubkey") != expected["pubkey"]:
        print_info("[ERROR] Certificate does not bind to the key we registered — possible MITM.")
        return False
    return True


async def distribute_sender_key(group_id, members, member_certs, my_sender_key):
    """Distribui a sender key para membros do grupo via pre-key DH (forward secrecy)."""
    for member in members:
        if member == state.username:
            continue
        cert = member_certs.get(member)
        if not cert:
            print_info(f"[WARN] No certificate for '{member}' — skipping.")
            continue

        await send_cmd(f"{Cmd.PREKEY_GET} {member}")
        try:
            prekey = await asyncio.wait_for(prekey_resp_queue.get(), timeout=10.0)
        except asyncio.TimeoutError:
            print_info(f"[WARN] Timeout for pre-key of '{member}' — skipping.")
            continue

        if prekey is None:
            print_info(f"[WARN] No pre-keys for '{member}' — sender key not delivered.")
            continue
        if not state.security.verify_prekey(prekey, cert):
            print_info(f"[WARN] Pre-key signature invalid for '{member}' — skipping.")
            continue

        encrypted_key = state.security.encrypt_key_for_member(my_sender_key, prekey)
        signed_payload = state.security.sign_key_payload(encrypted_key)
        await send_cmd(f"{Cmd.GROUP_KEY} {group_id} {member} {signed_payload}")


# ── Outgoing command handlers (iniciados pelo utilizador) ─────────────────

async def _get_salt(name: str, timeout: float = 10.0) -> bytes | None:
    """Pede o salt PBKDF2 do utilizador ao servidor e aguarda a resposta."""
    drain_queue(salt_queue)
    await send_cmd(f"{Cmd.SALT_REQUEST} {name}")
    try:
        salt_b64 = await asyncio.wait_for(salt_queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        print_info("[ERROR] Server did not respond with salt in time.")
        return None
    try:
        return base64.b64decode(salt_b64)
    except Exception:
        print_info("[ERROR] Invalid salt received.")
        return None


async def handle_register(name: str):
    key_path = f"{KEYS_DIR}/{name}_private.pem"
    if os.path.exists(key_path):
        print_info(f"[ERROR] Keys for '{name}' already exist locally.")
        return

    password = await _prompt_secret("Choose a password: ")
    if password is None:
        return

    # 1) Pede salt ao servidor (server-side, persistido após /register).
    salt = await _get_salt(name)
    if salt is None:
        return

    # 2) Calcula PBKDF2 client-side — a password nunca atravessa a rede.
    pw_hash = pbkdf2_hash(password, salt)
    pw_hash_b64 = base64.b64encode(pw_hash).decode()

    pub_b64 = state.security.generate_keys(name, password)
    sig_b64 = state.security.sign_registration(pub_b64)
    print_info(f"[OK] RSA-2048 key generated for '{name}'.")

    state.pending_register = {"username": name, "pubkey": pub_b64}
    await send_cmd(f"{Cmd.REGISTER} {name} {pw_hash_b64} {pub_b64} {sig_b64}")

    try:
        await asyncio.wait_for(register_ack_queue.get(), timeout=10.0)
    except asyncio.TimeoutError:
        print_info("[ERROR] Server did not respond to /register in time.")


async def handle_login(name: str):
    key_path = f"{KEYS_DIR}/{name}_private.pem"
    if not os.path.exists(key_path):
        print_info(f"[ERROR] No local keys for '{name}'. Did you /register?")
        return

    password = await _prompt_secret("Password: ")
    if password is None:
        return
    if not state.security.load_keys(name, password):
        print_info("[ERROR] Wrong password or corrupted key file.")
        return
    if not state.security.load_certificate(name):
        print_info(f"[ERROR] No certificate for '{name}'. Did you /register?")
        return

    # Garante que o nonce já chegou (vem do servidor logo após o handshake).
    try:
        await asyncio.wait_for(client_state.nonce_event.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        print_info("[ERROR] Server did not issue a session nonce.")
        return
    nonce = client_state.server_nonce
    if nonce is None:
        print_info("[ERROR] Missing session nonce.")
        return

    # 1) Salt do servidor (real se utilizador existe, "fake-mas-estável" caso contrário).
    salt = await _get_salt(name)
    if salt is None:
        return

    # 2) Challenge-response: HMAC(PBKDF2(password, salt), nonce). Nem password nem hash atravessam a rede.
    pw_hash = pbkdf2_hash(password, salt)
    response = hmac.new(pw_hash, nonce, hashlib.sha256).digest()
    response_b64 = base64.b64encode(response).decode()

    await send_cmd(f"{Cmd.LOGIN} {name} {response_b64}")


async def handle_chat(target: str):
    drain_queue(chat_ack_queue)

    eph_payload = state.security.build_eph_init()
    await send_cmd(f"{Cmd.CHAT} {target} {eph_payload}")

    try:
        result = await asyncio.wait_for(chat_ack_queue.get(), timeout=30.0)
    except asyncio.TimeoutError:
        print_info("[ERROR] No response in time.")
        state.reset_chat()
        return

    if not result:
        return

    state.chatting_with = target
    peer_eph_pub_b64, peer_eph_sig_b64, peer_cert = parse_signed_eph_with_cert(result)
    ok, err = state.security.verify_eph_response(peer_eph_pub_b64, peer_eph_sig_b64, peer_cert)
    if not ok:
        print_info(f"[ERROR] Handshake aborted — {err}")
        await send_cmd(Cmd.EXIT)
        state.reset_chat()
        return

    state.security.establish_session(state.username, target, peer_eph_pub_b64)
    sig_b64 = state.security.build_eph_confirm(peer_eph_pub_b64)
    await send(Msg.EPH_CONFIRM, sig_b64)
    clear()
    print_info(f"[INFO] Secure channel established with '{target}'.")


async def handle_group_enter(target_pattern: str):
    if not target_pattern:
        print_info("[ERROR] Usage: /group <name/prefix>")
        return
    if state.chatting_with:
        print_info("[ERROR] You're in a 1-on-1 chat. Use /exit first.")
        return

    found_group_id = _find_group_by_name(target_pattern)
    if not found_group_id:
        print_info(f"[ERROR] Group '{target_pattern}' not found.")
        return

    ginfo = state.groups[found_group_id]
    state.active_group = found_group_id
    clear()
    print_info(f"[INFO] Entered group '{ginfo['name']}'. Type /exit to leave.")
    for msg in ginfo['messages']:
        print_info(msg)


async def handle_group_create(args: str):
    parts = args.strip().split()
    if len(parts) < 2:
        print_info("[ERROR] Usage: /group_create <name> <members...>")
        return
    await send_cmd(f"{Cmd.GROUP_CREATE} {args}")


async def handle_offline_msg_send(message: str):
    target = state.pending_offline_to
    cert = state.pending_offline_cert
    if not target or not cert:
        print_info("[ERROR] No pending offline target.")
        return

    prekey = await get_prekey_for(target)
    if prekey is None:
        print_info(f"[ERROR] No pre-keys available for '{target}'.")
        return
    if not state.security.verify_prekey(prekey, cert):
        print_info(f"[ERROR] Pre-key signature invalid for '{target}' — aborting.")
        return

    blob = state.security.encrypt_offline_msg(message, prekey)
    await send_cmd(f"{Cmd.OFFLINE_MSG} {target} {blob}")
    print_sent_message(f"[{state.username}] {message}")


async def send_group_msg(group_id: str, message: str):
    ginfo = state.groups[group_id]
    formatted_message = f"[{state.username}] {message}"
    my_sender_key = base64.b64decode(ginfo["my_sender_key"])
    encrypted_blob = state.security.encrypt_message(
        group_id,
        formatted_message,
        key=my_sender_key
    )
    await send_cmd(f"{Cmd.GROUP_MSG} {group_id} {encrypted_blob}")
    print_sent_message(formatted_message)
    ginfo["messages"].append(formatted_message)


# ── Incoming event handlers (push do servidor) ────────────────────────────

async def on_group_created(data: dict):
    group_id = data["group_id"]
    my_sender_key = os.urandom(32)
    state.groups[group_id] = {
        "name": data["name"],
        "my_sender_key": base64.b64encode(my_sender_key).decode(),
        "sender_keys": {state.username: base64.b64encode(my_sender_key).decode()},
        "members": data["members"],
        "creator": state.username,
        "member_certs": data.get("member_certs", {}),
        "messages": [],
    }
    await distribute_sender_key(group_id, data["members"], data.get("member_certs", {}), my_sender_key)
    state.chatting_with = None
    state.active_group = group_id
    clear()
    print_info(f"[OK] Group '{data['name']}' created. Your sender key has been distributed.")


async def on_group_invite(data: dict):
    gid = data["group_id"]
    my_sender_key = os.urandom(32)
    state.groups[gid] = {
        "name": data["name"],
        "my_sender_key": base64.b64encode(my_sender_key).decode(),
        "sender_keys": {state.username: base64.b64encode(my_sender_key).decode()},
        "members": data["members"],
        "creator": data["creator"],
        "member_certs": data.get("member_certs", {}),
        "messages": [],
    }
    await distribute_sender_key(gid, data["members"], data.get("member_certs", {}), my_sender_key)
    print_info(f"[INFO] Added to group '{data['name']}' by '{data['creator']}'. Sender key distributed.")


async def on_group_member_added(data: dict):
    """Existing member: send our sender key to the newly added member."""
    group_id = data["group_id"]
    new_member = data["new_member"]
    new_member_cert = data["new_member_cert"]

    if group_id not in state.groups:
        return

    ginfo = state.groups[group_id]
    if new_member not in ginfo["members"]:
        ginfo["members"].append(new_member)
    ginfo.setdefault("member_certs", {})[new_member] = new_member_cert

    my_sender_key = base64.b64decode(ginfo["my_sender_key"])
    await distribute_sender_key(group_id, [new_member], {new_member: new_member_cert}, my_sender_key)
    print_info(f"[INFO] '{new_member}' added to group '{ginfo['name']}'. Sent them your sender key.")


async def on_group_member_removed(data: dict):
    """Handle a member being kicked: if us, leave; otherwise rotate sender key."""
    group_id = data["group_id"]
    group_name = data["group_name"]
    kicked_member = data["kicked_member"]

    if kicked_member == state.username:
        if state.active_group == group_id:
            state.active_group = None
            clear()
        state.groups.pop(group_id, None)
        print_info(f"[INFO] You were removed from group '{group_name}'.")
        return

    if group_id not in state.groups:
        return

    ginfo = state.groups[group_id]
    ginfo["members"] = [m for m in ginfo["members"] if m != kicked_member]
    ginfo.get("sender_keys", {}).pop(kicked_member, None)
    ginfo.get("member_certs", {}).pop(kicked_member, None)

    # Rotate our sender key so the kicked member can no longer decrypt future messages
    new_sender_key = os.urandom(32)
    ginfo["my_sender_key"] = base64.b64encode(new_sender_key).decode()
    ginfo["sender_keys"][state.username] = base64.b64encode(new_sender_key).decode()

    member_certs = ginfo.get("member_certs", {})
    await distribute_sender_key(group_id, ginfo["members"], member_certs, new_sender_key)
    print_info(f"[INFO] '{kicked_member}' removed from group '{ginfo['name']}'. Sender key rotated.")


async def on_sender_key(group_id: str, key_payload: str):
    if group_id not in state.groups:
        return
    ginfo = state.groups[group_id]

    ok, encrypted_key_b64, cert_username = state.security.verify_key_payload(key_payload)
    if not ok:
        print_info(f"[ERROR] Rejected sender key for '{ginfo['name']}' — invalid signature.")
        return
    try:
        sender_key = state.security.decrypt_received_key(encrypted_key_b64)
        ginfo["sender_keys"][cert_username] = base64.b64encode(sender_key).decode()
        # Chave nova => sequencia de contador recomeca. Reset do high-water
        # para nao rejeitar (falso replay) as mensagens sob a chave rotacionada.
        state.security.recv_counters.pop(f"{group_id}:{cert_username}", None)
    except Exception as e:
        print_info(f"[ERROR] Failed to decrypt sender key from '{cert_username}': {e}")
        return

    missing = [m for m in ginfo["members"] if m not in ginfo["sender_keys"]]
    if not missing:
        print_info(f"[OK] All sender keys received for '{ginfo['name']}'. Use /group {ginfo['name']} to join.")
    else:
        print_info(f"[OK] Sender key from '{cert_username}' received ({len(missing)} still pending).")


async def on_group_msg(group_id: str, sender: str, payload: str):
    if group_id not in state.groups:
        print_info("[WARN] Message for unknown group.")
        return
    ginfo = state.groups[group_id]
    sender_key_b64 = ginfo["sender_keys"].get(sender)
    if sender_key_b64 is None:
        print_info(f"[WARN] No sender key for '{sender}' — message discarded.")
        return

    plaintext, _ = state.security.decrypt_message(
        f"{group_id}:{sender}", payload, key=base64.b64decode(sender_key_b64)
    )
    if plaintext == "[REPLAY DETECTED]":
        print_info(f"[!] Replay detected in '{ginfo['name']}' from '{sender}'.")
        return
    if plaintext is None:
        print_info(f"[ERROR] Failed to decrypt message from '{sender}'.")
        return
    if state.active_group == group_id:
        print_info(plaintext)
    else:
        print_info(f"[MSG in '{ginfo['name']}'] New message from '{sender}'.")
    ginfo['messages'].append(plaintext)


async def on_incoming_handshake(eph_payload: str):
    peer_eph_pub_b64, _, peer_cert = parse_signed_eph_with_cert(eph_payload)
    if not state.security.verify_certificate(peer_cert):
        print_info("[ERROR] Handshake aborted — invalid certificate (possible MITM).")
        await send_cmd(Cmd.EXIT)
        state.reset_chat()
        return

    my_eph_payload = state.security.build_eph_response(peer_eph_pub_b64, peer_cert)
    state.security.establish_session(state.username, state.chatting_with, peer_eph_pub_b64)
    await send(Msg.EPH, my_eph_payload)
    print_info(f"[INFO] Verifying '{state.chatting_with}'...")


async def on_eph_confirm(sig_b64: str):
    ok, err = state.security.verify_eph_confirm(sig_b64)
    if not ok:
        print_info(f"[ERROR] Handshake aborted — {err}")
        await send_cmd(Cmd.EXIT)
        state.reset_chat()
        return
    clear()
    print_info(f"[INFO] Secure channel established with '{state.chatting_with}'.")


# ── Receive dispatch (tabela tipo de mensagem -> handler) ─────────────────

async def _ev_login_ok(payload: str):
    state.username = payload
    asyncio.ensure_future(upload_prekeys())


async def _ev_prekey_resp(payload: str):
    try:
        prekey = json.loads(base64.b64decode(payload).decode())
    except Exception:
        prekey = None
    await prekey_resp_queue.put(prekey)


async def _ev_prekey_error(payload: str):
    await prekey_resp_queue.put(None)


async def _ev_chat_incoming(payload: str):
    sender, _, eph_payload = payload.partition("|")
    state.chatting_with = sender
    await on_incoming_handshake(eph_payload)


async def _ev_chat_ended(payload: str):
    target = state.chatting_with
    was_chatting = target in state.security.sessions if target else False
    await chat_ack_queue.put(False)
    state.reset_chat()
    if was_chatting:
        clear()


async def _ev_chat_error(payload: str):
    await chat_ack_queue.put(False)


async def _ev_chat_offline(payload: str):
    cert = json.loads(base64.b64decode(payload).decode())
    if not state.security.verify_certificate(cert):
        print_info("[ERROR] Offline cert invalid — ignoring.")
        await chat_ack_queue.put(False)
        return
    state.pending_offline_to = cert["username"]
    state.pending_offline_cert = cert
    await chat_ack_queue.put(False)
    print_info(f"[INFO] '{cert['username']}' is offline. Type your message to queue it.")


async def _ev_offline_msg(payload: str):
    claimed_sender, _, envelope = payload.partition(".")
    try:
        text, sender = state.security.decrypt_offline_msg(envelope)
    except Exception:
        print_info(f"[ERROR] Offline message from '{claimed_sender}' rejected — not authenticated.")
    else:
        if claimed_sender and claimed_sender != sender:
            print_info(f"[!] Offline sender mismatch: server said '{claimed_sender}', signed by '{sender}'.")
        print_info(f"[offline][{sender}] {text}")


async def _ev_register_ok(payload: str):
    cert = json.loads(base64.b64decode(payload).decode())
    if not _accept_certificate(cert):
        await register_ack_queue.put(False)
        return
    cert_path = f"{KEYS_DIR}/{cert['username']}_cert.json"
    with open(cert_path, "w") as f:
        json.dump(cert, f, indent=2)
    state.security.my_cert = cert
    print_info(f"[OK] Certificate saved for '{cert['username']}'.")
    state.pending_register = None
    await register_ack_queue.put(True)


async def _ev_peer_eph(payload: str):
    await chat_ack_queue.put(payload)


async def _ev_group_created(payload: str):
    asyncio.ensure_future(on_group_created(json.loads(payload)))


async def _ev_group_invite(payload: str):
    asyncio.ensure_future(on_group_invite(json.loads(payload)))


async def _ev_group_member_added(payload: str):
    asyncio.ensure_future(on_group_member_added(json.loads(payload)))


async def _ev_group_member_removed(payload: str):
    asyncio.ensure_future(on_group_member_removed(json.loads(payload)))


async def _ev_group_key(payload: str):
    gid, _, key = payload.split(":", 2)
    await on_sender_key(gid, key)


async def _ev_group_msg(payload: str):
    gid, sender, gpayload = payload.split(":", 2)
    await on_group_msg(gid, sender, gpayload)


async def _ev_msg(payload: str):
    sender, _, actual_payload = payload.partition(":")
    plaintext, _ = state.security.decrypt_message(sender, actual_payload)
    if plaintext == "[REPLAY DETECTED]":
        print_info(f"[!] Replay detected from '{sender}'.")
    elif plaintext is None:
        print_info(f"[ERROR] Failed to decrypt message from '{sender}'.")
    else:
        print_info(plaintext)


async def _ev_server(payload: str):
    print_info(payload)


async def _ev_nonce(payload: str):
    try:
        client_state.server_nonce = base64.b64decode(payload)
    except Exception:
        client_state.server_nonce = None
        return
    client_state.nonce_event.set()


async def _ev_salt(payload: str):
    await salt_queue.put(payload)


_EVENTS = {
    Msg.LOGIN_OK:              _ev_login_ok,
    Msg.NONCE:                 _ev_nonce,
    Msg.SALT:                  _ev_salt,
    Msg.PREKEY_RESP:           _ev_prekey_resp,
    Msg.PREKEY_ERROR:          _ev_prekey_error,
    Msg.CHAT_INCOMING:         _ev_chat_incoming,
    Msg.CHAT_ENDED:            _ev_chat_ended,
    Msg.CHAT_ERROR:            _ev_chat_error,
    Msg.CHAT_OFFLINE:          _ev_chat_offline,
    Msg.OFFLINE_MSG:           _ev_offline_msg,
    Msg.REGISTER_OK:           _ev_register_ok,
    Msg.PEER_EPH:              _ev_peer_eph,
    Msg.EPH_CONFIRM:           on_eph_confirm,
    Msg.GROUP_CREATED:         _ev_group_created,
    Msg.GROUP_INVITE:          _ev_group_invite,
    Msg.GROUP_MEMBER_ADDED:    _ev_group_member_added,
    Msg.GROUP_MEMBER_REMOVED:  _ev_group_member_removed,
    Msg.GROUP_KEY:             _ev_group_key,
    Msg.GROUP_MSG:             _ev_group_msg,
    Msg.MSG:                   _ev_msg,
    Msg.SERVER:                _ev_server,
}


async def receive_messages():
    """Loop de rececao: decifra transporte e faz dispatch por tipo de mensagem."""
    async for line_bytes in client_state.reader_global:
        text = line_bytes.decode().strip()
        if not text:
            continue

        msg_type, _, payload = text.partition(":")

        if msg_type == Msg.ENC and state.security.server_s2c_key:
            decrypted = state.security.decrypt_from_server(payload)
            if decrypted is None:
                continue
            msg_type, _, payload = decrypted.partition(":")

        handler = _EVENTS.get(msg_type)
        if handler:
            await handler(payload)


# ── Input loop (REPL) ─────────────────────────────────────────────────────

async def _iter_stdin_lines():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            yield line.decode().rstrip("\n")
    finally:
        transport.close()


async def send_messages():
    """Loop de input do utilizador e dispatch de comandos."""
    print_info("Welcome to SignalUM.")
    print_info("  /register <username>  — create a new account")
    print_info("  /login <username>     — log in with an existing account")
    print_info("  /quit                 — exit")

    _blocked_in_chat = {Cmd.CHAT, Cmd.LIST, Cmd.REGISTER, Cmd.LOGIN,
                        Cmd.GROUP_CREATE, Cmd.GROUP_LIST, Cmd.GROUP_ENTER,
                        Cmd.GROUP_ADD, Cmd.GROUP_KICK}

    try:
        async for line in _iter_stdin_lines():
            if not line.strip():
                continue

            parts = line.strip().split(" ", 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if state.chatting_with and cmd in _blocked_in_chat:
                print_info("[ERROR] You're in a chat. Use /exit to leave first.")
                continue

            if cmd == Cmd.REGISTER:
                if not args:
                    print_info("[ERROR] Usage: /register <username>")
                    continue
                await handle_register(args.strip())

            elif cmd == Cmd.LOGIN:
                if not args:
                    print_info("[ERROR] Usage: /login <username>")
                    continue
                await handle_login(args.strip())

            elif cmd == Cmd.CHAT:
                if not args:
                    print_info("[ERROR] Usage: /chat <username>")
                    continue
                if state.active_group:
                    print_info("[ERROR] You're in a group. Use /exit first.")
                    continue
                await handle_chat(args.strip())

            elif cmd == Cmd.GROUP_CREATE:
                await handle_group_create(args.strip())

            elif cmd == Cmd.GROUP_ENTER:
                await handle_group_enter(args.strip())

            elif cmd == Cmd.GROUP_LIST:
                await send_cmd(Cmd.GROUP_LIST)

            elif cmd == Cmd.GROUP_ADD:
                gp = args.strip().split(" ", 1)
                if len(gp) < 2:
                    print_info("[ERROR] Usage: /group_add <group_name> <member>")
                    continue
                gname, new_member = gp[0], gp[1].strip()
                found_gid = _find_group_by_name(gname)
                if not found_gid:
                    print_info(f"[ERROR] Group '{gname}' not found locally.")
                    continue
                await send_cmd(f"{Cmd.GROUP_ADD} {found_gid} {new_member}")

            elif cmd == Cmd.GROUP_KICK:
                gp = args.strip().split(" ", 1)
                if len(gp) < 2:
                    print_info("[ERROR] Usage: /group_kick <group_name> <member>")
                    continue
                gname, target_member = gp[0], gp[1].strip()
                found_gid = _find_group_by_name(gname)
                if not found_gid:
                    print_info(f"[ERROR] Group '{gname}' not found locally.")
                    continue
                await send_cmd(f"{Cmd.GROUP_KICK} {found_gid} {target_member}")

            elif cmd == Cmd.EXIT:
                if state.active_group:
                    name = state.groups.get(state.active_group, {}).get("name", "group")
                    state.active_group = None
                    clear()
                    print_info(f"[OK] Left group '{name}'.")
                elif state.chatting_with:
                    await send_cmd(Cmd.EXIT)
                elif state.pending_offline_to:
                    print_info(f"[OK] Cancelled offline messages to '{state.pending_offline_to}'.")
                    state.pending_offline_to = None
                    state.pending_offline_cert = None
                else:
                    print_info("[ERROR] You're not in a chat or group.")

            elif cmd == Cmd.QUIT:
                await send_cmd(Cmd.QUIT)
                break

            elif cmd == Cmd.LIST:
                await send_cmd(Cmd.LIST)

            elif cmd == Cmd.CLEAR:
                clear()

            else:
                line = replace_emojis(line)
                if state.active_group:
                    await send_group_msg(state.active_group, line)
                elif state.chatting_with:
                    target = state.chatting_with
                    encrypted = state.security.encrypt_message(target, f"[{state.username}] {line}")
                    if encrypted is None:
                        print_info(f"[ERROR] No session key for '{target}'.")
                        continue
                    await send(Msg.MSG, encrypted)
                    print_sent_message(f"[{state.username}] {line}")
                elif state.pending_offline_to:
                    await handle_offline_msg_send(line)
                else:
                    print_info("[ERROR] Not in a chat or group. Use /chat <user> or /group <name> first.")
    except asyncio.CancelledError:
        return
