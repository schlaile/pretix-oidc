import pytest
from django_scopes import scopes_disabled
from pretix.base.models import User

from pretix_oidc.forms import ConvertNativeUserForm, MergeOidcUserForm, label_oidc_user


@pytest.mark.django_db
def test_merge_oidc_user_form_lists_active_oidc_accounts():
    with scopes_disabled():
        native = User.objects.create_user("native@example.com", "password")
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-picker"
        oidc.fullname = "OIDC User"
        oidc.save()

        inactive = User.objects.create_user("inactive@example.com", "password")
        inactive.auth_backend = "pretix_oidc"
        inactive.auth_backend_identifier = "sub-inactive"
        inactive.is_active = False
        inactive.save()

    form = MergeOidcUserForm(target_user=native)
    choices = list(form.fields["oidc_user"].queryset)

    assert oidc in choices
    assert inactive not in choices
    assert native not in choices


@pytest.mark.django_db
def test_convert_native_user_form_has_password_fields():
    with scopes_disabled():
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-1"
        oidc.save()

    form = ConvertNativeUserForm(source_user=oidc)

    assert "new_pw" in form.fields
    assert "new_pw_repeat" in form.fields
    assert "needs_password_change" in form.fields
    assert "native_user" not in form.fields


@pytest.mark.django_db
def test_label_oidc_user_includes_email_name_and_identifier():
    with scopes_disabled():
        user = User.objects.create_user("oidc2@example.com", "password")
        user.auth_backend = "pretix_oidc"
        user.auth_backend_identifier = "sub-1"
        user.fullname = "Daniel"
        user.save()

    label = label_oidc_user(user)

    assert "oidc2@example.com" in label
    assert "Daniel" in label
    assert "sub-1" in label
