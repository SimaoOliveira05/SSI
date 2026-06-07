import re
import sys

from state import state

_EMOJIS = {
    "/happy":     "😊",
    "/sad":       "😢",
    "/laugh":     "😂",
    "/love":      "❤️",
    "/wink":      "😉",
    "/cool":      "😎",
    "/think":     "🤔",
    "/surprised": "😮",
    "/angry":     "😠",
    "/cry":       "😭",
    "/fire":      "🔥",
    "/luis":      "👍",
    "/thumbsdown":"👎",
    "/wave":      "👋",
    "/shrug":     "🤷",
    "/clap":      "👏",
    "/skull":     "💀",
    "/party":     "🎉",
    "/eyes":      "👀",
    "/ok":        "✅",
    "/ice":       "❄️",
}

_EMOJI_PATTERN = re.compile(r"(/\w+)")


def replace_emojis(text: str) -> str:
    return _EMOJI_PATTERN.sub(lambda m: _EMOJIS.get(m.group(0), m.group(0)), text)


def clear():
    """Limpa terminal e reposiciona cursor no topo."""
    print("\033[2J\033[H", end="", flush=True)


def prompt() -> str:
    """Constrói prompt contextual conforme modo atual (idle/chat/grupo)."""
    if state.active_group:
        ginfo = state.groups.get(state.active_group)
        name = ginfo["name"] if ginfo else "Group"
        return f"[{state.username} @ {name}] "
    if state.chatting_with:
        return f"[{state.username} -> {state.chatting_with}] "
    if state.username:
        return f"[{state.username}] "
    return "> "


def print_info(msg: str):
    """Imprime mensagem de estado preservando linha de input/prompt."""
    sys.stdout.write(f"\r\033[K{msg}\n{prompt()}")
    sys.stdout.flush()


def print_sent_message(msg: str):
    """Substitui eco da linha enviada por versão formatada da mensagem."""
    sys.stdout.write(f"\033[F\033[K{msg}\n{prompt()}")
    sys.stdout.flush()
