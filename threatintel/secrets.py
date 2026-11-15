"""API keys: environment variable first, then the desktop keyring.

Keys never go in config files or the repo. `python -m threatintel set-key NAME`
prompts without echo and stores the key in the Secret Service keyring (GNOME
Keyring / KWallet), which is encrypted at rest and unlocked with the login
session. An environment variable of the same name still wins, which suits
containers and CI.
"""
from __future__ import annotations

import os

KNOWN_KEYS = ("ABUSECH_AUTH_KEY", "NVD_API_KEY", "OTX_API_KEY")
_ATTRS = {"project": "seclab-threat-intel"}


def _schema():
    try:
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
    except (ImportError, ValueError):
        return None, None
    schema = Secret.Schema.new("org.seclab.ApiKey", Secret.SchemaFlags.NONE,
                               {"project": Secret.SchemaAttributeType.STRING,
                                "name": Secret.SchemaAttributeType.STRING})
    return Secret, schema


def get(name: str) -> str | None:
    """Return the key from the environment or the keyring, or None."""
    value = os.environ.get(name)
    if value:
        return value
    if os.environ.get("TI_NO_KEYRING"):
        return None
    Secret, schema = _schema()
    if schema is None:
        return None
    try:
        return Secret.password_lookup_sync(schema, {**_ATTRS, "name": name}, None) or None
    except Exception:  # keyring locked or no Secret Service on this machine
        return None


def store(name: str, value: str) -> None:
    Secret, schema = _schema()
    if schema is None:
        raise RuntimeError("no Secret Service keyring available; export the key as an environment variable instead")
    Secret.password_store_sync(schema, {**_ATTRS, "name": name}, Secret.COLLECTION_DEFAULT,
                               f"seclab threat-intel {name}", value, None)


def delete(name: str) -> bool:
    Secret, schema = _schema()
    if schema is None:
        return False
    return bool(Secret.password_clear_sync(schema, {**_ATTRS, "name": name}, None))
