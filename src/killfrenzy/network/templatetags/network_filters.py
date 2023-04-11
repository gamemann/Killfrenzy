from django import template

register = template.Library()

@register.filter
def get_key(value, arg):
    return value.get(arg, None)