"""
SignalUM Protocol Constants
===========================
Tipos de mensagem e comandos partilhados entre cliente e servidor.
Centralizar aqui evita magic strings dispersas e facilita refactoring.

Formato geral das mensagens:  <TYPE>:<payload>\n
Sem payload:                  <TYPE>\n
"""


class Msg:
    """Tipos de mensagem do protocolo SignalUM."""

    # Transporte servidor-cliente
    SERVER_EPH      = "SERVER_EPH"
    CLIENT_EPH      = "CLIENT_EPH"
    ENC             = "ENC"

    # Handshake P2P (STS: EPH -> PEER_EPH -> EPH_CONFIRM)
    EPH          = "EPH"
    PEER_EPH     = "PEER_EPH"
    EPH_CONFIRM  = "EPH_CONFIRM"

    # Mensagens
    MSG          = "MSG"

    # Sistema
    CMD          = "CMD"
    SERVER       = "SERVER"
    REGISTER_OK  = "REGISTER_OK"
    NONCE        = "NONCE"         # servidor → cliente, per-sessão (challenge-response)
    SALT         = "SALT"          # servidor → cliente, em resposta a SALT_REQUEST

    # Grupos
    GROUP_CREATED        = "GROUP_CREATED"
    GROUP_INVITE         = "GROUP_INVITE"
    GROUP_KEY            = "GROUP_KEY"
    GROUP_MSG            = "GROUP_MSG"
    GROUP_MEMBER_ADDED   = "GROUP_MEMBER_ADDED"
    GROUP_MEMBER_REMOVED = "GROUP_MEMBER_REMOVED"

    # Pre-keys
    PREKEY_RESP  = "PREKEY_RESP"
    PREKEY_ERROR = "PREKEY_ERROR"

    # Notificacoes de estado
    LOGIN_OK      = "LOGIN_OK"
    CHAT_INCOMING = "CHAT_INCOMING"
    CHAT_ENDED    = "CHAT_ENDED"
    CHAT_ERROR    = "CHAT_ERROR"
    CHAT_OFFLINE  = "CHAT_OFFLINE"
    OFFLINE_MSG   = "OFFLINE_MSG"


class Cmd:
    """Comandos enviados pelo cliente (payload de MSG.CMD)."""

    # Identidade
    REGISTER     = "/register"
    LOGIN        = "/login"
    SALT_REQUEST = "/salt_request"  # pede ao servidor o salt PBKDF2 para um username

    # Chat 1-a-1
    CHAT         = "/chat"
    MSG          = "/msg"
    EXIT         = "/exit"

    # Grupos
    GROUP_CREATE = "/group_create"
    GROUP_MSG    = "/group_msg"
    GROUP_KEY    = "/group_key"
    GROUP_LIST   = "/group_list"
    GROUP_ADD    = "/group_add"
    GROUP_KICK   = "/group_kick"

    # Pre-keys
    PREKEY_UPLOAD = "/prekey_upload"
    PREKEY_GET    = "/prekey_get"

    # Utilitarios
    LIST         = "/list"
    QUIT         = "/quit"
    OFFLINE_MSG  = "/offline_msg"

    # Locais (so cliente)
    GROUP_ENTER  = "/group"
    CLEAR        = "/clear"
