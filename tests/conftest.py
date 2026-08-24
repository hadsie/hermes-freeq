"""Test bootstrap for the freeq plugin."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_PKG = "freeq_plugin"


def _load_plugin_package():
    if _PKG in sys.modules:
        return sys.modules[_PKG]
    spec = importlib.util.spec_from_file_location(
        _PKG,
        PLUGIN_ROOT / "__init__.py",
        submodule_search_locations=[str(PLUGIN_ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[_PKG] = module
    spec.loader.exec_module(module)
    return module


_plugin = _load_plugin_package()


def _register_platform_entry():
    """Register 'freeq' so Platform('freeq') resolves via _missing_()."""
    from gateway.platform_registry import PlatformEntry, platform_registry

    if platform_registry.is_registered("freeq"):
        return
    platform_registry.register(
        PlatformEntry(
            name="freeq",
            label="Freeq",
            adapter_factory=lambda cfg: _plugin.adapter.FreeqAdapter(cfg),
            check_fn=lambda: True,
        )
    )


_register_platform_entry()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "FREEQ_SERVER",
        "FREEQ_PORT",
        "FREEQ_NICKNAME",
        "FREEQ_CHANNEL",
        "FREEQ_USE_TLS",
        "FREEQ_ATPROTO_HANDLE",
        "FREEQ_ATPROTO_APP_PASSWORD",
        "FREEQ_ATPROTO_PDS_URL",
        "FREEQ_ALLOWED_USERS",
        "FREEQ_ALLOW_ALL_USERS",
        "FREEQ_HOME_CHANNEL",
        "FREEQ_MEDIA_MAX_BYTES",
        "ATPROTO_HANDLE",
        "ATPROTO_APP_PASSWORD",
        "ATPROTO_PDS_URL",
    ):
        monkeypatch.delenv(var, raising=False)
