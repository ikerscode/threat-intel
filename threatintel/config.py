"""Configuration loading.

Settings come from config/feeds.toml. Paths are resolved relative to the project
root so the CLI and the server behave the same from any working directory.
The environment variable TI_CONFIG can point at a different file and TI_DB at a
different database (the tests use both).
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESOURCES = Path(__file__).resolve().parent / "resources"
FIXTURES = ROOT / "fixtures"
DEFAULT_CONFIG = ROOT / "config" / "feeds.toml"


@dataclass
class Settings:
    raw: dict
    db_path: Path
    cache_dir: Path
    reports_dir: Path
    user_agent: str = "seclab-ti/0.1"
    default_host_interval_s: float = 1.5
    feeds: dict = field(default_factory=dict)
    scheduler: dict = field(default_factory=dict)

    def feed(self, name: str) -> dict:
        return self.feeds.get(name, {})


def _resolve(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else ROOT / p


def load(path: str | os.PathLike | None = None) -> Settings:
    cfg_path = Path(path or os.environ.get("TI_CONFIG") or DEFAULT_CONFIG)
    with open(cfg_path, "rb") as fh:
        raw = tomllib.load(fh)
    gen = raw.get("general", {})
    db_path = Path(os.environ["TI_DB"]) if os.environ.get("TI_DB") else _resolve(gen.get("db_path", "data/threatintel.db"))
    cache_dir = Path(os.environ["TI_CACHE"]) if os.environ.get("TI_CACHE") else _resolve(gen.get("cache_dir", "data/cache"))
    reports_dir = Path(os.environ["TI_REPORTS"]) if os.environ.get("TI_REPORTS") else _resolve(gen.get("reports_dir", "data/reports"))
    return Settings(
        raw=raw,
        db_path=db_path,
        cache_dir=cache_dir,
        reports_dir=reports_dir,
        user_agent=gen.get("user_agent", "seclab-ti/0.1"),
        default_host_interval_s=float(gen.get("default_host_interval_s", 1.5)),
        feeds=raw.get("feeds", {}),
        scheduler=raw.get("scheduler", {}),
    )


_settings: Settings | None = None


def get() -> Settings:
    """Process-wide settings, loaded once."""
    global _settings
    if _settings is None:
        _settings = load()
    return _settings


def reset() -> None:
    """Forget cached settings (used by tests after changing env vars)."""
    global _settings
    _settings = None
