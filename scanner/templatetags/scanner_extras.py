from django import template

register = template.Library()

@register.filter
def status_color(status_code):
    """Return appropriate badge color based on HTTP status code"""
    if not status_code:
        return 'secondary'
    if 100 <= status_code < 200:
        return 'info'
    elif 200 <= status_code < 300:
        return 'success'
    elif 300 <= status_code < 400:
        return 'warning'
    elif 400 <= status_code < 500:
        return 'danger'
    elif 500 <= status_code < 600:
        return 'danger'
    else:
        return 'secondary' 