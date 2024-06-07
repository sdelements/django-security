from django.conf import settings

from .models import PasswordExpiry


def password_is_expired(user):

    password_expiry, _ = PasswordExpiry.objects.get_or_create(user=user)

    password_settings = getattr(settings, "MANDATORY_PASSWORD_CHANGE", {})
    include_superusers = password_settings.get("INCLUDE_SUPERUSERS", False)

    if include_superusers:
        return password_expiry.is_expired()
    else:
        return not user.is_superuser and password_expiry.is_expired()


def never_expire_password(user):
    password_expiry, _ = PasswordExpiry.objects.get_or_create(user=user)
    password_expiry.never_expire()
