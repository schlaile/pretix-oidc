from pathlib import Path

import pretix_oidc.template_sync as template_sync


def test_sync_login_template_installs_to_data_dir(tmp_path, monkeypatch):
    plugin_template = tmp_path / "plugin" / "login.html"
    plugin_template.parent.mkdir(parents=True)
    plugin_template.write_text("login-template", encoding="utf-8")

    data_template = tmp_path / "data" / "templates" / "pretixcontrol" / "auth" / "login.html"
    version_marker = data_template.with_suffix(".pretix_oidc_version")

    monkeypatch.setattr(template_sync, "_TEMPLATES_ROOT", tmp_path / "plugin_root")
    monkeypatch.setattr(template_sync, "_DATA_TEMPLATES_ROOT", tmp_path / "data" / "templates")
    plugin_root = tmp_path / "plugin_root" / "pretixcontrol" / "auth"
    plugin_root.mkdir(parents=True)
    (plugin_root / "login.html").write_text("login-template", encoding="utf-8")
    monkeypatch.setattr(template_sync, "__version__", "9.9.9")

    template_sync.sync_template_override("pretixcontrol/auth/login.html")

    assert data_template.read_text(encoding="utf-8") == "login-template"
    assert version_marker.read_text(encoding="utf-8") == "9.9.9"

    (plugin_root / "login.html").write_text("login-template-v2", encoding="utf-8")
    monkeypatch.setattr(template_sync, "__version__", "9.9.10")

    template_sync.sync_template_override("pretixcontrol/auth/login.html")

    assert data_template.read_text(encoding="utf-8") == "login-template-v2"


def test_sync_templates_installs_user_form_override(tmp_path, monkeypatch):
    plugin_root = tmp_path / "plugin_root"
    data_root = tmp_path / "data" / "templates"
    user_form_plugin = plugin_root / "pretixcontrol" / "users"
    user_form_plugin.mkdir(parents=True)
    (user_form_plugin / "form.html").write_text("user-form-template", encoding="utf-8")

    monkeypatch.setattr(template_sync, "_TEMPLATES_ROOT", plugin_root)
    monkeypatch.setattr(template_sync, "_DATA_TEMPLATES_ROOT", data_root)
    monkeypatch.setattr(template_sync, "__version__", "1.0.0")

    template_sync.sync_template_override("pretixcontrol/users/form.html")

    data_template = data_root / "pretixcontrol" / "users" / "form.html"
    assert data_template.read_text(encoding="utf-8") == "user-form-template"
