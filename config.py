"""
Configuration loader.

How to use:
- The GUI can create .env in the repo root if it does not exist.
- Required keys for auth: SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_REDIRECT_URI
- Optional keys: SPOTIFY_CACHE_PATH, DEBUG_MODE, SPOTIFY_AUTH_CODE, SPOTIFY_CERT_PATH, SPOTIFY_KEY_PATH, SPOTIFY_TEST_MODE
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parent
ENV_PATH = ROOT_DIR / ".env"

load_dotenv(ENV_PATH)


@dataclass(frozen=True)
class AppConfig:
    debug: bool
    spotify_client_id: str | None
    spotify_client_secret: str | None
    spotify_redirect_uri: str | None
    spotify_cache_path: Path
    spotify_auth_code: str | None
    spotify_cert_path: Path
    spotify_key_path: Path
    spotify_test_mode: bool


def _get_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _clean_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.startswith("PUT_"):
        return None
    return cleaned


def load_config() -> AppConfig:
    client_id = _clean_value(os.getenv("SPOTIFY_CLIENT_ID"))
    client_secret = _clean_value(os.getenv("SPOTIFY_CLIENT_SECRET"))
    redirect_uri = _clean_value(os.getenv("SPOTIFY_REDIRECT_URI"))

    cache_path_raw = os.getenv("SPOTIFY_CACHE_PATH", ".spotify_cache")
    if not cache_path_raw.strip():
        cache_path_raw = ".spotify_cache"
    cache_path = Path(cache_path_raw)
    if not cache_path.is_absolute():
        cache_path = ROOT_DIR / cache_path

    debug = _get_bool(os.getenv("DEBUG_MODE"), default=False)
    test_mode = _get_bool(os.getenv("SPOTIFY_TEST_MODE"), default=False)
    auth_code = _clean_value(os.getenv("SPOTIFY_AUTH_CODE"))

    cert_path_raw = _clean_value(os.getenv("SPOTIFY_CERT_PATH")) or ".certs/spotify_localhost.pem"
    key_path_raw = _clean_value(os.getenv("SPOTIFY_KEY_PATH")) or ".certs/spotify_localhost.key"
    cert_path = Path(cert_path_raw)
    if not cert_path.is_absolute():
        cert_path = ROOT_DIR / cert_path
    key_path = Path(key_path_raw)
    if not key_path.is_absolute():
        key_path = ROOT_DIR / key_path

    return AppConfig(
        debug=debug,
        spotify_client_id=client_id,
        spotify_client_secret=client_secret,
        spotify_redirect_uri=redirect_uri,
        spotify_cache_path=cache_path,
        spotify_auth_code=auth_code,
        spotify_cert_path=cert_path,
        spotify_key_path=key_path,
        spotify_test_mode=test_mode,
    )


def save_env_value(key: str, value: str) -> None:
    lines: list[str]
    if ENV_PATH.exists():
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    key_prefix = f"{key}="
    updated = False
    for index, line in enumerate(lines):
        if line.startswith(key_prefix):
            lines[index] = f"{key}={value}"
            updated = True
            break

    if not updated:
        lines.append(f"{key}={value}")

    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
