from django import template

register = template.Library()


@register.simple_tag
def external_auth_backends(backends):
    return [
        backend
        for backend in backends
        if backend.visible and backend.url and backend.identifier != "native"
    ]
