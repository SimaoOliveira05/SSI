import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

import state
from utils import log, send, server_msg, verify_public_key, verify_signature
from persistence import issue_certificate, save_prekeys, save_users
from protocol import Msg


def _fake_salt_for(username: str) -> bytes:
    """Salt determinístico para usernames inexistentes — evita enumeração.

    Estável por username e ligado a um segredo derivado da chave RSA do servidor:
    do ponto de vista do atacante é indistinguível de um salt real.
    """
    priv_der = state.server_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    secret = hashlib.sha256(priv_der + b"signalum-salt-secret-v1").digest()
    return hmac.new(secret, username.encode(), hashlib.sha256).digest()


# ── Helpers ───────────────────────────────────────────────────────────────

async def _validate_group_membership(writer, username: str, group_id: str, client) -> bool:
    if username not in state.groups[group_id]["members"]:
        await server_msg(writer, "[ERROR] You are not a member of this group.", client=client)
        return False
    return True


# ── Auth / registration ──────────────────────────────────────────────────

async def handle_salt_request(writer, args: str, transport_client) -> None:
    """Devolve o salt PBKDF2 para um username.

    - Se o utilizador existir: salt persistido.
    - Caso contrário: salt determinístico-mas-imprevisível (ver `_fake_salt_for`).
      Em ambos os casos a resposta tem a mesma forma e o mesmo tamanho — o
      atacante não consegue enumerar contas registadas.

    Para o /register a seguir, o salt gerado é guardado em
    `transport_client.pending_salt` para coincidir com o que o cliente usar
    no PBKDF2.
    """
    username = args.strip().split(" ", 1)[0]
    if not username:
        await server_msg(writer, "[ERROR] Usage: /salt_request <username>", client=transport_client)
        return

    user = state.registered_users.get(username)
    if user is not None:
        salt = base64.b64decode(user["salt"])
    else:
        salt = _fake_salt_for(username)
        transport_client.pending_salt = salt

    await send(writer, Msg.SALT, base64.b64encode(salt).decode(), client=transport_client)


async def handle_register(writer, args: str, transport_client) -> str | None:
    """Regista identidade: cliente já enviou PBKDF2-hash da password (nunca a password).

    O salt foi entregue antes via SALT_REQUEST e está em `transport_client.pending_salt`.
    """
    parts = args.strip().split(" ", 3)
    if len(parts) < 4:
        await server_msg(writer, "[ERROR] Usage: /register <username> <pw_hash> <pubkey> <sig>", client=transport_client)
        return None

    name, pw_hash_b64, pubkey, sig = parts[0], parts[1], parts[2], parts[3]

    if name in state.registered_users:
        await server_msg(writer, f"[ERROR] Username '{name}' already taken.", client=transport_client)
        return None
    if transport_client.pending_salt is None:
        await server_msg(writer, "[ERROR] No salt issued — call /salt_request first.", client=transport_client)
        return None
    try:
        stored_hash = base64.b64decode(pw_hash_b64)
        if len(stored_hash) != 32:
            raise ValueError
    except Exception:
        await server_msg(writer, "[ERROR] Invalid password hash.", client=transport_client)
        return None
    if not verify_public_key(pubkey):
        await server_msg(writer, "[ERROR] Invalid public key.", client=transport_client)
        return None
    if not verify_signature(pubkey, sig, pubkey.encode()):
        await server_msg(writer, "[ERROR] Proof of possession failed.", client=transport_client)
        return None

    salt = transport_client.pending_salt
    transport_client.pending_salt = None

    cert = issue_certificate(name, pubkey)
    state.registered_users[name] = {
        "cert": cert,
        "salt": base64.b64encode(salt).decode(),
        "password_hash": base64.b64encode(stored_hash).decode(),
    }
    save_users()

    cert_b64 = base64.b64encode(json.dumps(cert).encode()).decode()
    await send(writer, Msg.REGISTER_OK, cert_b64, client=transport_client)
    return name


async def handle_login(writer, args: str, transport_client) -> str | None:
    """Autentica via challenge-response: cliente prova posse do PBKDF2-hash.

    Response esperado = HMAC-SHA256(stored_pw_hash, nonce_da_sessão).
    O nonce é consumido a cada tentativa (sucesso ou falha) para impedir replay.
    """
    parts = args.strip().split(" ", 1)
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /login <username> <response>", client=transport_client)
        return None

    username, response_b64 = parts[0], parts[1]

    nonce = transport_client.nonce
    transport_client.nonce = None  # consome — uma tentativa por nonce
    if nonce is None:
        await server_msg(writer, "[ERROR] No active challenge. Reconnect.", client=transport_client)
        return None

    try:
        response = base64.b64decode(response_b64)
    except Exception:
        await server_msg(writer, "[ERROR] Invalid response.", client=transport_client)
        return None

    user = state.registered_users.get(username)
    # Mantém o tempo de resposta indistinguível entre "utilizador não existe" e "password errada":
    # calcula sempre o HMAC esperado, mesmo com um stored_hash falso.
    if user is None:
        stored_hash = hashlib.sha256(_fake_salt_for(username)).digest()
        expected = hmac.new(stored_hash, nonce, hashlib.sha256).digest()
        hmac.compare_digest(expected, response)  # tempo constante, ignorado
        log("auth", f"login FAILED — unknown user '{username}'")
        await server_msg(writer, "[ERROR] Unknown username or wrong password.", client=transport_client)
        return None

    stored_hash = base64.b64decode(user["password_hash"])
    expected = hmac.new(stored_hash, nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, response):
        log("auth", f"login FAILED — '{username}' wrong response")
        await server_msg(writer, "[ERROR] Unknown username or wrong password.", client=transport_client)
        return None

    return username


async def post_login_init(writer, name: str, transport_client) -> None:
    await send(writer, Msg.LOGIN_OK, name, client=transport_client)
    await server_msg(writer, f"[OK] Logged in as '{name}'.", client=transport_client)
    for line in [
        "Commands:",
        "  /chat <user>                      — start a 1-to-1 chat",
        "  /list                             — list online users",
        "  /group_create <name> <members..>  — create a group",
        "  /group <name>                     — enter a group",
        "  /group_list                       — list your groups",
        "  /group_add <name> <member>        — add a member (creator only)",
        "  /group_kick <name> <member>       — remove a member (creator only)",
        "  /quit                             — disconnect",
    ]:
        await server_msg(writer, line, client=transport_client)

    pending = state.offline_queue.pop(name, [])
    if pending:
        log("offline", f"delivering {len(pending)} queued msg(s) to '{name}'")
    for entry in pending:
        payload = f"{entry['sender']}.{entry['blob']}"
        await send(writer, Msg.OFFLINE_MSG, payload, client=transport_client)


# ── Pre-keys ──────────────────────────────────────────────────────────────

async def handle_prekey_upload(writer, username: str, args: str):
    """Recebe e armazena um lote de pre-keys assinadas para o utilizador."""
    my_client = state.online_users.get(username)
    try:
        prekeys_list = json.loads(base64.b64decode(args.strip()).decode())
    except Exception:
        await server_msg(writer, "[ERROR] Invalid pre-key payload.", client=my_client)
        return

    if username not in state.prekeys:
        state.prekeys[username] = {}

    cert = state.registered_users.get(username, {}).get("cert", {})
    pubkey_b64 = cert.get("pubkey", "")
    accepted = 0
    for pk in prekeys_list:
        pk_id = pk.get("id", "")
        pk_pub = pk.get("pub", "")
        pk_sig = pk.get("sig", "")
        if not pk_id or not pk_pub or not pk_sig:
            continue
        if not verify_signature(pubkey_b64, pk_sig, (pk_id + pk_pub).encode()):
            continue
        state.prekeys[username][pk_id] = {"pub": pk_pub, "sig": pk_sig}
        accepted += 1

    save_prekeys()
    log("recv", f"prekeys: '{username}' uploaded {accepted}/{len(prekeys_list)} signed prekeys (pool={len(state.prekeys.get(username, {}))})")
    await server_msg(writer, f"[OK] {accepted} pre-key(s) uploaded.", client=my_client)


async def handle_prekey_get(writer, username: str, args: str):
    """Entrega uma pre-key do utilizador pedido e remove-a do pool."""
    my_client = state.online_users.get(username)
    target = args.strip()

    if not target:
        await server_msg(writer, "[ERROR] Usage: /prekey_get <username>", client=my_client)
        return
    if target not in state.registered_users:
        await server_msg(writer, f"[ERROR] '{target}' is not registered.", client=my_client)
        return

    pool = state.prekeys.get(target, {})
    if not pool:
        await send(writer, Msg.PREKEY_ERROR, target, client=my_client)
        return

    pk_id, pk_entry = next(iter(pool.items()))
    del state.prekeys[target][pk_id]
    save_prekeys()

    resp = json.dumps({"id": pk_id, "pub": pk_entry["pub"], "sig": pk_entry["sig"]})
    log("recv", f"prekeys: handed out 1 prekey of '{target}' to '{username}' (remaining={len(state.prekeys.get(target, {}))})")
    await send(writer, Msg.PREKEY_RESP, base64.b64encode(resp.encode()).decode(), client=my_client)


# ── Chat 1-to-1 ───────────────────────────────────────────────────────────

async def handle_chat(writer, username: str, args: str):
    parts = args.strip().split(" ", 1)
    my_client = state.online_users.get(username)

    if len(parts) < 2:
        await send(writer, Msg.CHAT_ERROR, client=my_client)
        await server_msg(writer, "[ERROR] Usage: /chat <username>", client=my_client)
        return

    target, eph_payload = parts[0], parts[1]

    if target == username:
        await send(writer, Msg.CHAT_ERROR, client=my_client)
        await server_msg(writer, "[ERROR] You can't chat with yourself.", client=my_client)
        return
    if target not in state.online_users:
        if target not in state.registered_users:
            await send(writer, Msg.CHAT_ERROR, client=my_client)
            await server_msg(writer, f"[ERROR] '{target}' does not exist.", client=my_client)
            return
        cert_b64 = base64.b64encode(json.dumps(state.registered_users[target]["cert"]).encode()).decode()
        await send(writer, Msg.CHAT_OFFLINE, cert_b64, client=my_client)
        return
    if state.online_users[username].chatting_with is not None:
        await send(writer, Msg.CHAT_ERROR, client=my_client)
        await server_msg(writer, "[ERROR] Already in a chat. Use /exit first.", client=my_client)
        return
    if state.online_users[target].chatting_with is not None:
        await send(writer, Msg.CHAT_ERROR, client=my_client)
        await server_msg(writer, f"[ERROR] '{target}' is already in a chat.", client=my_client)
        return

    target_client = state.online_users[target]
    state.online_users[username].chatting_with = target
    state.online_users[target].chatting_with = username

    incoming_payload = f"{username}|{eph_payload}"
    log("relay", f"/chat opened — '{username}' → '{target}' (relaying EPH for STS handshake; server cannot derive session key)")
    await send(target_client.writer, Msg.CHAT_INCOMING, incoming_payload, client=target_client)
    await server_msg(target_client.writer, f"[INFO] '{username}' started a chat with you.", client=target_client)


async def handle_list(writer, username: str):
    my_client = state.online_users.get(username)
    others = [u for u in state.online_users if u != username]
    if others:
        await server_msg(writer, f"[OK] Online: {', '.join(others)}", client=my_client)
    else:
        await server_msg(writer, "[OK] No other users online.", client=my_client)


async def handle_exit(writer, username: str):
    client = state.online_users.get(username)
    if client is None or client.chatting_with is None:
        await server_msg(writer, "[ERROR] You're not in a chat.", client=client)
        return

    target = client.chatting_with
    client.chatting_with = None
    await send(writer, Msg.CHAT_ENDED, target, client=client)
    await server_msg(writer, f"[OK] Left chat with '{target}'.", client=client)

    if target in state.online_users:
        target_client = state.online_users[target]
        target_client.chatting_with = None
        await send(target_client.writer, Msg.CHAT_ENDED, username, client=target_client)
        await server_msg(target_client.writer, f"[INFO] '{username}' left the chat.", client=target_client)


# ── Groups ────────────────────────────────────────────────────────────────

async def handle_group_create(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split()
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /group_create <name> <member1> [member2 ...]", client=my_client)
        return

    name = parts[0]
    requested = parts[1:]

    for m in requested:
        if m not in state.registered_users:
            await server_msg(writer, f"[ERROR] '{m}' is not registered.", client=my_client)
            return
        if m == username:
            await server_msg(writer, "[ERROR] You are already included as creator.", client=my_client)
            return

    # Grupos sao efemeros e so existem com membros online: filtra os offline.
    members = [m for m in requested if m in state.online_users]
    skipped = [m for m in requested if m not in state.online_users]
    if skipped:
        await server_msg(
            writer,
            f"[INFO] Skipped offline member(s): {', '.join(skipped)} (groups are online-only).",
            client=my_client,
        )

    group_id = base64.b64encode(os.urandom(16)).decode()
    all_members = [username] + members

    state.groups[group_id] = {
        "name": name,
        "creator": username,
        "members": all_members,
    }

    member_certs = {m: state.registered_users[m]["cert"] for m in members}
    await send(
        writer,
        Msg.GROUP_CREATED,
        json.dumps({
            "group_id": group_id,
            "name": name,
            "members": all_members,
            "member_certs": member_certs,
        }),
        client=my_client,
    )

    member_certs_all = {m: state.registered_users[m]["cert"] for m in all_members}
    invite = json.dumps({
        "group_id": group_id,
        "name": name,
        "creator": username,
        "members": all_members,
        "member_certs": member_certs_all,
    })
    log("group", f"created '{name}' (id={group_id[:8]}...) by '{username}' with {len(all_members)} members: {', '.join(all_members)}")
    for m in members:
        m_client = state.online_users[m]
        await send(m_client.writer, Msg.GROUP_INVITE, invite, client=m_client)


async def handle_group_msg(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split(" ", 1)
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /group_msg <group_id> <payload>", client=my_client)
        return

    group_id, payload = parts[0], parts[1]

    if not await _validate_group_membership(writer, username, group_id, my_client):
        return

    recipients = [m for m in state.groups[group_id]["members"]
                  if m != username and m in state.online_users]
    log("group", f"MSG fan-out from '{username}' in '{state.groups[group_id]['name']}' → {len(recipients)} recipient(s): {', '.join(recipients) or '(none)'}  (server cannot read body)")
    for m in recipients:
        m_client = state.online_users[m]
        await send(m_client.writer, Msg.GROUP_MSG, f"{group_id}:{username}:{payload}", client=m_client)


async def handle_group_key(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split(" ", 2)
    if len(parts) < 3:
        await server_msg(writer, "[ERROR] Usage: /group_key <group_id> <member> <key>", client=my_client)
        return

    group_id, target, key_payload = parts[0], parts[1], parts[2]

    if not await _validate_group_membership(writer, username, group_id, my_client):
        return
    if target not in state.groups[group_id]["members"]:
        await server_msg(writer, f"[ERROR] '{target}' is not in this group.", client=my_client)
        return
    if target not in state.online_users:
        await server_msg(writer, f"[WARN] '{target}' is not online — key not delivered.", client=my_client)
        return

    target_client = state.online_users[target]
    log("group", f"sender-key delivery '{username}' → '{target}' for group {group_id[:8]}... (RSA-signed, sealed via prekey)")
    await send(target_client.writer, Msg.GROUP_KEY, f"{group_id}:{username}:{key_payload}", client=target_client)


async def handle_group_list(writer, username: str):
    my_client = state.online_users.get(username)
    user_groups = []
    for _, ginfo in state.groups.items():
        if username in ginfo["members"]:
            members_str = ", ".join(ginfo["members"])
            user_groups.append(f"{ginfo['name']} [{members_str}]")

    if user_groups:
        await server_msg(writer, f"[OK] Your groups ({len(user_groups)}):", client=my_client)
        for g in user_groups:
            await server_msg(writer, f"  - {g}", client=my_client)
    else:
        await server_msg(writer, "[OK] You have no groups.", client=my_client)


async def handle_group_add(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split()
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /group_add <group_id> <member>", client=my_client)
        return

    group_id, new_member = parts[0], parts[1]

    if group_id not in state.groups:
        await server_msg(writer, "[ERROR] Group not found.", client=my_client)
        return

    ginfo = state.groups[group_id]

    if ginfo["creator"] != username:
        await server_msg(writer, "[ERROR] Only the group creator can add members.", client=my_client)
        return
    if new_member not in state.registered_users:
        await server_msg(writer, f"[ERROR] '{new_member}' is not registered.", client=my_client)
        return
    if new_member not in state.online_users:
        await server_msg(writer, f"[ERROR] '{new_member}' is offline — groups are online-only.", client=my_client)
        return
    if new_member in ginfo["members"]:
        await server_msg(writer, f"[ERROR] '{new_member}' is already in the group.", client=my_client)
        return

    ginfo["members"].append(new_member)

    new_member_cert = state.registered_users[new_member]["cert"]

    # Notify existing online members so they send their sender key to the new member
    added_payload = json.dumps({
        "group_id": group_id,
        "new_member": new_member,
        "new_member_cert": new_member_cert,
    })
    for m in ginfo["members"]:
        if m != new_member and m in state.online_users:
            m_client = state.online_users[m]
            await send(m_client.writer, Msg.GROUP_MEMBER_ADDED, added_payload, client=m_client)

    # Send invite to new member
    all_certs = {m: state.registered_users[m]["cert"] for m in ginfo["members"] if m in state.registered_users}
    invite = json.dumps({
        "group_id": group_id,
        "name": ginfo["name"],
        "creator": ginfo["creator"],
        "members": ginfo["members"],
        "member_certs": all_certs,
    })
    nm_client = state.online_users[new_member]
    await send(nm_client.writer, Msg.GROUP_INVITE, invite, client=nm_client)

    await server_msg(writer, f"[OK] '{new_member}' added to group '{ginfo['name']}'.", client=my_client)


async def handle_group_kick(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split()
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /group_kick <group_id> <member>", client=my_client)
        return

    group_id, target_member = parts[0], parts[1]

    if group_id not in state.groups:
        await server_msg(writer, "[ERROR] Group not found.", client=my_client)
        return

    ginfo = state.groups[group_id]

    if ginfo["creator"] != username:
        await server_msg(writer, "[ERROR] Only the group creator can remove members.", client=my_client)
        return
    if target_member == username:
        await server_msg(writer, "[ERROR] The creator cannot be removed from the group.", client=my_client)
        return
    if target_member not in ginfo["members"]:
        await server_msg(writer, f"[ERROR] '{target_member}' is not in this group.", client=my_client)
        return

    ginfo["members"].remove(target_member)

    removed_payload = json.dumps({
        "group_id": group_id,
        "group_name": ginfo["name"],
        "kicked_member": target_member,
    })

    # Notify the kicked member
    if target_member in state.online_users:
        kicked_client = state.online_users[target_member]
        await send(kicked_client.writer, Msg.GROUP_MEMBER_REMOVED, removed_payload, client=kicked_client)

    # Notify remaining members so they rotate their sender keys
    for m in ginfo["members"]:
        if m in state.online_users:
            m_client = state.online_users[m]
            await send(m_client.writer, Msg.GROUP_MEMBER_REMOVED, removed_payload, client=m_client)

    await server_msg(writer, f"[OK] '{target_member}' removed from group '{ginfo['name']}'.", client=my_client)


# ── In-chat relay ─────────────────────────────────────────────────────────

async def handle_in_chat(writer, username: str, msg_type: str, payload: str):
    client = state.online_users.get(username)
    if client is None:
        return

    target = client.chatting_with
    if not target or target not in state.online_users:
        client.chatting_with = None
        if target:
            await send(writer, Msg.CHAT_ENDED, target, client=client)
            await server_msg(writer, f"[INFO] '{target}' went offline. Left chat.", client=client)
        return

    target_client = state.online_users[target]
    peer_writer = target_client.writer

    if msg_type == Msg.EPH:
        log("relay", f"EPH '{username}' → '{target}' (signed ephemeral pubkey + cert)")
        await send(peer_writer, Msg.PEER_EPH, payload, client=target_client)
    elif msg_type == Msg.EPH_CONFIRM:
        log("relay", f"EPH_CONFIRM '{username}' → '{target}' (handshake completion)")
        await send(peer_writer, Msg.EPH_CONFIRM, payload, client=target_client)
    elif msg_type == Msg.MSG:
        preview = payload[:48] + ("..." if len(payload) > 48 else "")
        log("relay", f"MSG '{username}' → '{target}' (opaque ciphertext, {len(payload)}B b64): {preview}")
        await send(peer_writer, Msg.MSG, f"{username}:{payload}", client=target_client)
    else:
        log("warn", f"unknown in-chat msg_type='{msg_type}' from '{username}'")


async def handle_offline_msg(writer, username: str, args: str):
    my_client = state.online_users.get(username)
    parts = args.strip().split(" ", 1)
    if len(parts) < 2:
        await server_msg(writer, "[ERROR] Usage: /offline_msg <target> <blob>", client=my_client)
        return

    target, blob = parts[0], parts[1]
    if target not in state.registered_users:
        await server_msg(writer, f"[ERROR] '{target}' does not exist.", client=my_client)
        return
    if target in state.online_users:
        await server_msg(writer, f"[ERROR] '{target}' is online — use /chat instead.", client=my_client)
        return

    state.offline_queue.setdefault(target, []).append({"sender": username, "blob": blob})
    log("offline", f"queued msg '{username}' → '{target}' (pending={len(state.offline_queue[target])}; blob is RSA-signed + sealed)")
    await server_msg(writer, f"[OK] Message queued for '{target}'.", client=my_client)
