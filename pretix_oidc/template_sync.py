from pathlib import Path

from pretix.settings import DATA_DIR

from . import __version__

_TEMPLATES_ROOT = Path(__file__).parent / "templates"
_DATA_TEMPLATES_ROOT = Path(DATA_DIR) / "templates"

TEMPLATE_OVERRIDES = (
    "pretixcontrol/auth/login.html",
    "pretixcontrol/users/form.html",
)


def _paths_for(relative_path):
    plugin_path = _TEMPLATES_ROOT / relative_path
    data_path = _DATA_TEMPLATES_ROOT / relative_path
    version_path = data_path.with_suffix(".pretix_oidc_version")
    return plugin_path, data_path, version_path


def sync_template_override(relative_path):
    """Install a template override into pretix DATA_DIR (checked before app templates)."""
    plugin_path, data_path, version_path = _paths_for(relative_path)
    if not plugin_path.is_file():
        return

    source = plugin_path.read_bytes()
    installed_version = (
        version_path.read_text(encoding="utf-8") if version_path.is_file() else None
    )
    installed_content = (
        data_path.read_bytes() if data_path.is_file() else None
    )

    if installed_version == __version__ and installed_content == source:
        return

    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(source)
    version_path.write_text(__version__, encoding="utf-8")


def sync_login_template():
    sync_template_override("pretixcontrol/auth/login.html")


def sync_user_form_template():
    sync_template_override("pretixcontrol/users/form.html")


def sync_templates():
    for relative_path in TEMPLATE_OVERRIDES:
        sync_template_override(relative_path)


# Backwards-compatible aliases used in tests
PLUGIN_LOGIN_TEMPLATE, DATA_LOGIN_TEMPLATE, VERSION_MARKER = _paths_for(
    "pretixcontrol/auth/login.html"
)
