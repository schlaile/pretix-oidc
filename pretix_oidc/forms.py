from django import forms
from django.contrib.auth.password_validation import validate_password
from django.forms import ModelForm
from django.utils.translation import gettext_lazy as _
from django_scopes import scopes_disabled
from pretix.base.models import User

from .linking import BACKEND_IDENTIFIER
from .models import OIDCTeamAssignmentRule


class OIDCAssignmentRuleForm(ModelForm):
    def __init__(self, organizer, *args, **kwargs):
        super(OIDCAssignmentRuleForm, self).__init__(*args, **kwargs)
        self.fields["team"].queryset = self.fields["team"].queryset.filter(
            organizer=organizer
        )

    class Meta:
        model = OIDCTeamAssignmentRule
        fields = ["team", "attribute", "value"]


def label_oidc_user(user):
    parts = [user.email or str(_("(no email)"))]
    if user.fullname:
        parts.append(user.fullname)
    if user.auth_backend_identifier:
        parts.append(user.auth_backend_identifier)
    return " — ".join(parts)


class MergeOidcUserForm(forms.Form):
    oidc_user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label=_("OpenID Connect account"),
        help_text=_(
            "Select the OpenID Connect account to merge into this native account."
        ),
        empty_label=_("Select an account…"),
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    def __init__(self, target_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with scopes_disabled():
            self.fields["oidc_user"].queryset = (
                User.objects.filter(
                    auth_backend=BACKEND_IDENTIFIER,
                    auth_backend_identifier__isnull=False,
                    is_active=True,
                )
                .exclude(pk=target_user.pk)
                .order_by("email")
            )
        self.fields["oidc_user"].label_from_instance = label_oidc_user


class ConvertNativeUserForm(forms.Form):
    error_messages = {
        "pw_mismatch": _("Please enter the same password twice"),
    }

    new_pw = forms.CharField(
        max_length=255,
        label=_("New password"),
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
    )
    new_pw_repeat = forms.CharField(
        max_length=255,
        label=_("Repeat new password"),
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
    )
    needs_password_change = forms.BooleanField(
        required=False,
        label=_("Force password change on next login"),
        help_text=_(
            "The user must choose a new password the next time they sign in."
        ),
    )

    def __init__(self, source_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_user = source_user

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("new_pw")
        password2 = cleaned_data.get("new_pw_repeat")
        if password1 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages["pw_mismatch"],
                code="pw_mismatch",
            )
        if password1:
            validate_password(password1, user=self.source_user)
        return cleaned_data
