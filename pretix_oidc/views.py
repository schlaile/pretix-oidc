from django.contrib import messages
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView, FormView, UpdateView
from django_scopes import scopes_disabled
from pretix.base.models import Team, User
from pretix.base.models.auth import EmailAddressTakenError
from pretix.control.permissions import (
    AdministratorPermissionRequiredMixin,
    StaffMemberRequiredMixin,
)
from pretix.control.views.auth import process_login
from pretix.control.views.organizer import OrganizerDetailViewMixin
from pretix.control.views.user import RecentAuthenticationRequiredMixin
from pretix.helpers.compat import CompatDeleteView
from urllib.parse import quote

from .assignment import add_user_to_staff, add_user_to_teams
from .auth import OIDCAuthBackend  # NOQA
from .forms import ConvertNativeUserForm, MergeOidcUserForm, OIDCAssignmentRuleForm
from .linking import (
    AccountLinkingError,
    allow_account_linking,
    apply_verified_email,
    clear_pending_link,
    ensure_email_verified,
    find_converted_native_user,
    find_native_user_by_email,
    get_pending_link,
    link_native_user_to_oidc,
    persist_session,
    store_pending_link,
)
from .linking import BACKEND_IDENTIFIER
from .merge import (
    UserMergeError,
    merge_oidc_user_into_native,
    convert_oidc_user_to_native,
)
from .models import OIDCTeamAssignmentRule


def _finish_oidc_login(request, user, id_token, userinfo):
    with scopes_disabled():
        add_user_to_teams(user, id_token, userinfo)
        add_user_to_staff(user, id_token, userinfo)
    return process_login(request, user, False)


def _complete_account_link(request, user, pending):
    verification_error = ensure_email_verified(pending)
    if verification_error:
        clear_pending_link(request)
        messages.error(request, verification_error)
        return redirect(reverse("control:auth.login"))

    try:
        with scopes_disabled():
            user = link_native_user_to_oidc(
                user,
                pending["uuid"],
                pending["email"],
                pending.get("fullname"),
                email_verified=pending.get("email_verified"),
            )
    except AccountLinkingError as exc:
        messages.error(request, str(exc))
        return redirect(reverse("control:auth.login"))

    clear_pending_link(request)
    messages.success(
        request,
        _("Your account has been linked to OpenID Connect."),
    )
    return _finish_oidc_login(
        request, user, pending.get("id_token"), pending.get("userinfo")
    )


def _oidc_callback_profile_link(request, user_data, id_token, userinfo, callback_meta):
    if not request.user.is_authenticated:
        messages.error(
            request,
            _("You must be logged in to link your account."),
        )
        return redirect(reverse("control:auth.login"))

    link_user_id = callback_meta.get("link_user_id")
    if link_user_id and request.user.pk != link_user_id:
        messages.error(
            request,
            _("The logged-in account does not match the account that started linking."),
        )
        return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

    if request.user.email.lower() != user_data["email"].lower():
        messages.error(
            request,
            _(
                "The email address from OpenID Connect does not match your pretix account."
            ),
        )
        return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

    if request.user.auth_backend != "native":
        messages.error(
            request,
            _("Only native accounts can be linked to OpenID Connect."),
        )
        return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

    pending = {
        "uuid": user_data["uuid"],
        "email": user_data["email"],
        "fullname": user_data.get("fullname"),
        "email_verified": user_data.get("email_verified"),
        "id_token": id_token,
        "userinfo": userinfo,
    }
    return _complete_account_link(request, request.user, pending)


def _redirect_to_native_login(request, message=None):
    if message:
        messages.error(request, message)
        persist_session(request)
    return redirect(reverse("control:auth.login") + "?backend=native")


def _oidc_callback_error_message(request):
    reason = request.session.pop("oidc_callback_error", None)
    if reason in ("state_missing", "state_mismatch", "state_expired"):
        return _(
            "Your OpenID Connect login session expired or was interrupted. "
            "Please try signing in again."
        )
    if reason in ("token_request", "token_error"):
        return _(
            "OpenID Connect token exchange failed. Please verify the callback URL "
            "and client settings in your identity provider, then try again."
        )
    if reason == "missing_id_token":
        return _(
            "OpenID Connect did not return an ID token. Please verify that the "
            "requested scopes include openid."
        )
    if reason == "missing_claims":
        return _(
            "OpenID Connect did not return the required user identifier or email "
            "address. Please verify the scopes and claims from your identity provider."
        )
    return _(
        "OpenID Connect sign-in failed. Please try again or sign in with your "
        "username and password."
    )


def _redirect_to_link_choice(request, user_data, id_token, userinfo):
    verification_error = ensure_email_verified(user_data)
    if verification_error:
        return _redirect_to_native_login(request, verification_error)
    store_pending_link(request, user_data, id_token, userinfo)
    return redirect(reverse("plugins:pretix_oidc:oidc_link_choice"))


def _handle_native_email_collision(request, user_data, id_token, userinfo):
    if not find_native_user_by_email(user_data["email"]):
        return None
    if allow_account_linking():
        return _redirect_to_link_choice(request, user_data, id_token, userinfo)
    return _redirect_to_native_login(
        request,
        _(
            "An account with the email address %(email)s already exists. "
            "Please sign in with your username and password instead of "
            "OpenID Connect."
        )
        % {"email": user_data["email"]},
    )


def oidc_callback(request):
    auth_backend = OIDCAuthBackend()
    user_data, id_token, userinfo = auth_backend.process_callback(request)
    callback_meta = request.session.pop("oidc_callback_meta", {}) or {}
    purpose = callback_meta.get("purpose", "login")

    if user_data is None:
        return _redirect_to_native_login(
            request,
            _oidc_callback_error_message(request),
        )

    verification_error = ensure_email_verified(user_data)
    if verification_error:
        return _redirect_to_native_login(request, verification_error)

    if purpose == "link":
        return _oidc_callback_profile_link(
            request, user_data, id_token, userinfo, callback_meta
        )

    converted_user = find_converted_native_user(user_data["uuid"])
    if converted_user:
        return _redirect_to_native_login(
            request,
            _(
                "This account uses password login. OpenID Connect sign-in was "
                "disabled for this account. Please sign in with your email and "
                "password."
            ),
        )

    collision_response = _handle_native_email_collision(
        request, user_data, id_token, userinfo
    )
    if collision_response is not None:
        return collision_response

    try:
        with scopes_disabled():
            user = User.objects.get_or_create_for_backend(
                auth_backend.identifier,
                user_data["uuid"],
                user_data["email"],
                set_always={"fullname": user_data["fullname"]},
                set_on_creation={},
            )
            apply_verified_email(user, user_data)
    except EmailAddressTakenError:
        return _redirect_to_native_login(
            request,
            _(
                "An account with the email address %(email)s already exists. "
                "Please sign in with your username and password instead of "
                "OpenID Connect."
            )
            % {"email": user_data["email"]},
        )
    else:
        return _finish_oidc_login(request, user, id_token, userinfo)


class OIDCLinkChoiceView(TemplateView):
    template_name = "pretix_oidc/oidc_link_choice.html"

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if not allow_account_linking():
            return _redirect_to_native_login(request, _("Account linking is disabled."))
        if not get_pending_link(request):
            return _redirect_to_native_login(
                request,
                _(
                    "The account linking request has expired. Please sign in with "
                    "OpenID Connect again."
                ),
            )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        pending = get_pending_link(self.request)
        ctx["pending_email"] = pending["email"] if pending else ""
        ctx["auth_redirect_url"] = reverse("plugins:pretix_oidc:oidc_link_auth")
        ctx["decline_url"] = reverse("plugins:pretix_oidc:oidc_link_decline")
        return ctx


class OIDCLinkAuthRedirectView(View):
    @method_decorator(never_cache)
    def get(self, request, *args, **kwargs):
        if not allow_account_linking() or not get_pending_link(request):
            return _redirect_to_native_login(
                request,
                _(
                    "The account linking request has expired. Please sign in with "
                    "OpenID Connect again."
                ),
            )

        complete_url = reverse("plugins:pretix_oidc:oidc_link_complete")
        login_url = (
            reverse("control:auth.login")
            + "?backend=native&next="
            + quote(complete_url)
        )
        messages.info(
            request,
            _(
                "Please log in with your pretix account to finish linking it to "
                "OpenID Connect."
            ),
        )
        persist_session(request)
        return redirect(login_url)


class OIDCLinkCompleteView(LoginRequiredMixin, View):
    @method_decorator(never_cache)
    def get(self, request, *args, **kwargs):
        if not allow_account_linking():
            messages.error(request, _("Account linking is disabled."))
            return redirect(reverse("control:auth.login"))

        pending = get_pending_link(request)
        if not pending:
            messages.error(
                request,
                _("The account linking request has expired. Please sign in again."),
            )
            return redirect(reverse("control:auth.login"))

        if request.user.auth_backend != "native":
            messages.error(
                request,
                _("Only native accounts can be linked to OpenID Connect."),
            )
            return redirect(reverse("control:auth.login"))

        if request.user.email.lower() != pending["email"].lower():
            messages.error(
                request,
                _(
                    "The email address of the account you logged in with does not match "
                    "the OpenID Connect identity."
                ),
            )
            clear_pending_link(request)
            return redirect(reverse("control:auth.login"))

        return _complete_account_link(request, request.user, pending)


class OIDCLinkDeclineView(TemplateView):
    template_name = "pretix_oidc/oidc_link_decline.html"

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        clear_pending_link(request)
        if getattr(request.user, "is_authenticated", False):
            auth_logout(request)
            request.session["pretix_auth_login_time"] = 0
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["login_url"] = reverse("control:auth.login") + "?backend=native"
        ctx["settings_url"] = reverse("control:user.settings")
        return ctx


class OIDCLinkAccountView(LoginRequiredMixin, TemplateView):
    template_name = "pretix_oidc/oidc_link_account.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["is_native"] = self.request.user.auth_backend == "native"
        ctx["linking_enabled"] = allow_account_linking()
        ctx["start_url"] = reverse("plugins:pretix_oidc:oidc_link_start")
        ctx["provider_name"] = OIDCAuthBackend().verbose_name
        return ctx


class OIDCLinkStartView(LoginRequiredMixin, RecentAuthenticationRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        if not allow_account_linking():
            messages.error(request, _("Account linking is disabled."))
            return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

        if request.user.auth_backend != "native":
            messages.error(
                request,
                _("Your account is already linked to an external login method."),
            )
            return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

        auth_backend = OIDCAuthBackend()
        if not getattr(auth_backend, "client", None):
            messages.error(
                request,
                _("OpenID Connect is not configured correctly."),
            )
            return redirect(reverse("plugins:pretix_oidc:oidc_link_account"))

        url = auth_backend.authentication_url(
            request, purpose="link", link_user_id=request.user.pk
        )
        return redirect(url)


# These views have been adapted from pretix-cas plugin (https://github.com/DataManagementLab/pretix-cas)
class AssignmentRulesList(
    OrganizerDetailViewMixin, StaffMemberRequiredMixin, TemplateView
):
    template_name = "pretix_oidc/oidc_assignment_rules.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organizer = self.request.organizer
        context["teams"] = Team.objects.filter(organizer=organizer)
        context["assignmentRules"] = OIDCTeamAssignmentRule.objects.filter(
            team__organizer=organizer
        )
        return context


class AssignmentRuleEditMixin(OrganizerDetailViewMixin, StaffMemberRequiredMixin):
    model = OIDCTeamAssignmentRule

    def get_queryset(self):
        return self.model.objects.filter(team__organizer=self.request.organizer)

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.kwargs["pk"])

    def get_success_url(self):
        return reverse(
            "plugins:pretix_oidc:team_assignment_rules",
            kwargs={"organizer": self.request.organizer.slug},
        )


class AssignmentRuleFormMixin(AssignmentRuleEditMixin):
    fields = ["team", "attribute", "value"]
    template_name = "pretix_oidc/oidc_assignment_rule_edit.html"

    def get_form(self, form_class=None):
        return OIDCAssignmentRuleForm(
            organizer=self.request.organizer, **self.get_form_kwargs()
        )


class AssignmentRuleCreate(AssignmentRuleFormMixin, CreateView):
    def form_valid(self, form):
        messages.success(self.request, _("The new assignment rule has been created."))
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, _("The assignment rule could not be created."))
        return super().form_invalid(form)


class AssignmentRuleEdit(AssignmentRuleFormMixin, UpdateView):
    context_object_name = "rule"

    def form_valid(self, form):
        messages.success(self.request, _("Your changes have been saved."))
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, _("Your changes could not be saved."))
        return super().form_invalid(form)


class AssignmentRuleDelete(AssignmentRuleEditMixin, CompatDeleteView):
    template_name = "pretix_oidc/oidc_assignment_rule_delete.html"


class UserMergeOidcView(
    AdministratorPermissionRequiredMixin,
    RecentAuthenticationRequiredMixin,
    FormView,
):
    form_class = MergeOidcUserForm
    template_name = "pretix_oidc/user_merge_oidc.html"

    def get_target_user(self):
        user = get_object_or_404(User, pk=self.kwargs.get("id"))
        if user.auth_backend != "native":
            raise UserMergeError(
                _("The target account must use the native login backend.")
            )
        return user

    def dispatch(self, request, *args, **kwargs):
        try:
            self.get_target_user()
        except UserMergeError as exc:
            messages.error(request, str(exc))
            return redirect(reverse("control:users.index"))
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["target_user"] = self.get_target_user()
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["target_user"] = self.get_target_user()
        return ctx

    def form_valid(self, form):
        target_user = self.get_target_user()
        oidc_user = form.cleaned_data["oidc_user"]
        try:
            with scopes_disabled():
                merge_oidc_user_into_native(
                    target_user, oidc_user, acting_user=self.request.user
                )
        except UserMergeError as exc:
            messages.error(self.request, str(exc))
            return self.form_invalid(form)

        messages.success(
            self.request,
            _("The OpenID Connect account has been merged into the native account."),
        )
        return redirect(reverse("control:users.edit", kwargs={"id": target_user.pk}))


class UserConvertNativeView(
    AdministratorPermissionRequiredMixin,
    RecentAuthenticationRequiredMixin,
    FormView,
):
    form_class = ConvertNativeUserForm
    template_name = "pretix_oidc/user_convert_native.html"

    def get_source_user(self):
        user = get_object_or_404(User, pk=self.kwargs.get("id"))
        if user.auth_backend != BACKEND_IDENTIFIER:
            raise UserMergeError(_("The source account must use OpenID Connect."))
        if not user.auth_backend_identifier:
            raise UserMergeError(_("The OpenID Connect account has no external identifier."))
        return user

    def dispatch(self, request, *args, **kwargs):
        try:
            self.get_source_user()
        except UserMergeError as exc:
            messages.error(request, str(exc))
            return redirect(reverse("control:users.index"))
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["source_user"] = self.get_source_user()
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["source_user"] = self.get_source_user()
        return ctx

    def form_valid(self, form):
        source_user = self.get_source_user()
        try:
            with scopes_disabled():
                convert_oidc_user_to_native(
                    source_user,
                    password=form.cleaned_data["new_pw"],
                    needs_password_change=form.cleaned_data["needs_password_change"],
                    acting_user=self.request.user,
                )
        except UserMergeError as exc:
            messages.error(self.request, str(exc))
            return self.form_invalid(form)

        messages.success(
            self.request,
            _(
                "This user now signs in with email and password. "
                "OpenID Connect login has been disabled for this account."
            ),
        )
        return redirect(reverse("control:users.edit", kwargs={"id": source_user.pk}))
