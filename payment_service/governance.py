"""Runtime side of third-party governance: register loading + @third_party declaration."""
from __future__ import annotations

import contextvars
import fnmatch
import functools
from functools import lru_cache
from pathlib import Path

import yaml

REGISTER_PATH = Path(__file__).resolve().parent.parent / "governance" / "approved-vendors.yaml"
_ctx: contextvars.ContextVar = contextvars.ContextVar("third_party_ctx", default=None)


class GovernanceError(Exception):
    """Declaration is inconsistent with the approved-vendor register."""


@lru_cache(maxsize=4)
def load_register(path: str = str(REGISTER_PATH)) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def get_vendor(vendor_id: str) -> dict | None:
    return next((v for v in load_register()["vendors"] if v["id"] == vendor_id), None)


def host_matches(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(host.lower(), p.lower()) for p in patterns)


def current_context():
    """(vendor_id, data_classes) of the active @third_party function, or None."""
    return _ctx.get()


def third_party(vendor_id: str, data_classes: list[str]):
    """Declare that a function exchanges `data_classes` with `vendor_id`.

    Validated at import time (fail fast) and again at call time by the egress guard.
    The static vendor_guard reads the same declaration from the AST in CI / code review.
    """
    declared = frozenset(data_classes)
    vendor = get_vendor(vendor_id)
    if vendor is None:
        raise GovernanceError(f"{vendor_id} is not in the approved-vendor register")
    extra = declared - set(vendor["data_classes"])
    if extra:
        raise GovernanceError(f"{vendor_id} is not approved for data classes: {sorted(extra)}")

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            token = _ctx.set((vendor_id, declared))
            try:
                return fn(*args, **kwargs)
            finally:
                _ctx.reset(token)

        wrapper.__third_party__ = (vendor_id, declared)
        return wrapper

    return decorator
