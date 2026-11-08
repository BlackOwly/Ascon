# core/file_utils.py
import os
import json
from pathlib import Path
from datetime import datetime

# Корень проекта — на уровень выше папки core/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = PROJECT_ROOT / "keys"


def read_file(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        return f.read()


def write_file(filepath: str, data: bytes):
    with open(filepath, "wb") as f:
        f.write(data)


def generate_random_key(length: int = 16) -> bytes:
    return os.urandom(length)


def generate_random_nonce(length: int = 16) -> bytes:
    return os.urandom(length)


# ---------- Хранилище ключей ----------

def ensure_keys_dir() -> Path:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    return KEYS_DIR


def save_keypair(key: bytes, nonce: bytes, variant: str = "Ascon-AEAD128") -> Path:
    """
    Сохраняет пару (ключ, nonce) в JSON-файл в <project_root>/keys/.
    Имя: YYYYMMDD_HHMMSS_<первые 8 hex-символов ключа>.json
    Возвращает путь к созданному файлу.
    """
    ensure_keys_dir()
    now = datetime.now()
    filename = f"{now.strftime('%Y%m%d_%H%M%S')}_{key.hex()[:8]}.json"
    path = KEYS_DIR / filename

    payload = {
        "created": now.isoformat(timespec="seconds"),
        "variant": variant,
        "key_hex": key.hex(),
        "nonce_hex": nonce.hex(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def list_saved_keys() -> list[Path]:
    """Возвращает список файлов ключей, отсортированный от новых к старым."""
    if not KEYS_DIR.exists():
        return []
    return sorted(KEYS_DIR.glob("*.json"), reverse=True)


def load_keypair(path: Path) -> tuple[bytes, bytes, str]:
    """Загружает пару (ключ, nonce, вариант) из JSON-файла."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return (
        bytes.fromhex(data["key_hex"]),
        bytes.fromhex(data["nonce_hex"]),
        data.get("variant", "Ascon-AEAD128"),
    )
