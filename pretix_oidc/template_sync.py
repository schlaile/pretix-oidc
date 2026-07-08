from pathlib import Path

from pretix.settings import DATA_DIR

from . import __version__

PLUGIN_LOGIN_TEMPLATE = (
    Path(__file__).parent / "templates" / "pretixcontrol" / "auth" / "login.html"
)
DATA_LOGIN_TEMPLATE = (
    Path(DATA_DIR) / "templates" / "pretixcontrol" / "auth" / "login.html"
)
VERSION_MARKER = DATA_LOGIN_TEMPLATE.with_suffix(".pretix_oidc_version")


def sync_login_template():
    """Install login template override into pretix DATA_DIR (checked before app templates)."""
    if not PLUGIN_LOGIN_TEMPLATE.is_file():
        return

    source = PLUGIN_LOGIN_TEMPLATE.read_bytes()
    installed_version = (
        VERSION_MARKER.read_text(encoding="utf-8") if VERSION_MARKER.is_file() else None
    )
    installed_content = (
        DATA_LOGIN_TEMPLATE.read_bytes() if DATA_LOGIN_TEMPLATE.is_file() else None
    )

    if installed_version == __version__ and installed_content == source:
        return

    DATA_LOGIN_TEMPLATE.parent.mkdir(parents=True, exist_ok=True)
    DATA_LOGIN_TEMPLATE.write_bytes(source)
    VERSION_MARKER.write_text(__version__, encoding="utf-8")
