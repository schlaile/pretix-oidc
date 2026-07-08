from django import template

register = template.Library()


@register.simple_tag
def external_auth_backends(backends):
    return [
        backend
        for backend in backends
        if backend.visible and backend.url and backend.identifier != "native"
    ]


@register.simple_tag
def show_native_external_auth(request, backend, external_backends):
    if backend.identifier != "native" or not external_backends:
        return False
    return request.GET.get("backend") != "native"
