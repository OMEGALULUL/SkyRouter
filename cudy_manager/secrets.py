import contextlib
import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any


class SecretStoreError(RuntimeError):
    pass


def _fernet_backend() -> tuple[Any, Any]:
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:
        raise SecretStoreError("cryptography is required to store router credentials") from exc
    return Fernet, InvalidToken


class SecretStore:
    def __init__(self, directory: str | Path):
        fernet_cls, invalid_token = _fernet_backend()
        self._fernet_cls = fernet_cls
        self._invalid_token = invalid_token
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._chmod(self.directory, 0o700)
        self.key_path = self.directory / "master.key"
        self.vault_path = self.directory / "secrets.json"
        self._lock = threading.RLock()
        self._fernet = fernet_cls(self._load_or_create_key())
        self._values = self._load_values()

    @staticmethod
    def _chmod(path: Path, mode: int) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, mode)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            self._chmod(self.key_path, 0o600)
            key = self.key_path.read_bytes().strip()
            try:
                self._fernet_cls(key)
            except (ValueError, TypeError) as exc:
                raise SecretStoreError("master key is invalid") from exc
            return key
        key = self._fernet_cls.generate_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(self.key_path, flags, 0o600)
        except FileExistsError:
            return self.key_path.read_bytes().strip()
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
        finally:
            self._chmod(self.key_path, 0o600)
        return key

    def _load_values(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        try:
            data = json.loads(self.vault_path.read_text())
        except (OSError, ValueError) as exc:
            raise SecretStoreError("secret vault is unreadable") from exc
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise SecretStoreError("secret vault has an invalid format")
        return data

    def _save_values(self) -> None:
        payload = json.dumps(self._values, indent=2, sort_keys=True).encode()
        fd, temporary = tempfile.mkstemp(prefix="secrets.", dir=self.directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.vault_path)
            self._chmod(self.vault_path, 0o600)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    @staticmethod
    def _valid_ref(reference: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", reference))

    def put(self, value: str, name: str | None = None) -> str:
        if not isinstance(value, str) or not value:
            raise SecretStoreError("secret value must be a non-empty string")
        reference = name or f"secret-{secrets.token_urlsafe(12)}"
        if not self._valid_ref(reference):
            raise SecretStoreError("secret reference contains unsupported characters")
        with self._lock:
            self._values[reference] = self._fernet.encrypt(value.encode()).decode()
            self._save_values()
        return reference

    def get(self, reference: str) -> str:
        if not reference:
            raise SecretStoreError("secret reference is missing")
        with self._lock:
            ciphertext = self._values.get(reference)
        if ciphertext is None:
            raise SecretStoreError(f"secret reference {reference!r} does not exist")
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except (self._invalid_token, ValueError, UnicodeDecodeError) as exc:
            raise SecretStoreError("stored secret could not be decrypted") from exc

    def delete(self, reference: str) -> bool:
        if not reference:
            return False
        with self._lock:
            existed = reference in self._values
            if existed:
                del self._values[reference]
                self._save_values()
        return existed

    def has(self, reference: str) -> bool:
        with self._lock:
            return reference in self._values

    def references(self) -> list[str]:
        with self._lock:
            return sorted(self._values)
