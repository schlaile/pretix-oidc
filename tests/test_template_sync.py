from pathlib import Path

import pretix_oidc.template_sync as template_sync


def test_sync_login_template_installs_to_data_dir(tmp_path, monkeypatch):
    plugin_template = tmp_path / "plugin" / "login.html"
    plugin_template.parent.mkdir(parents=True)
    plugin_template.write_text("login-template", encoding="utf-8")

    data_template = tmp_path / "data" / "templates" / "pretixcontrol" / "auth" / "login.html"
    version_marker = data_template.with_suffix(".pretix_oidc_version")

    monkeypatch.setattr(template_sync, "PLUGIN_LOGIN_TEMPLATE", plugin_template)
    monkeypatch.setattr(template_sync, "DATA_LOGIN_TEMPLATE", data_template)
    monkeypatch.setattr(template_sync, "VERSION_MARKER", version_marker)
    monkeypatch.setattr(template_sync, "__version__", "9.9.9")

    template_sync.sync_login_template()

    assert data_template.read_text(encoding="utf-8") == "login-template"
    assert version_marker.read_text(encoding="utf-8") == "9.9.9"

    plugin_template.write_text("login-template-v2", encoding="utf-8")
    monkeypatch.setattr(template_sync, "__version__", "9.9.10")

    template_sync.sync_login_template()

    assert data_template.read_text(encoding="utf-8") == "login-template-v2"
