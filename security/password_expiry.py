# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from .models import PasswordExpiry


def password_is_expired(user):
    password_expiry, _ = PasswordExpiry.objects.get_or_create(user=user)
    return (
        not user.is_superuser
        and (password_expiry.is_expired())
    )


def never_expire_password(user):
    password_expiry, _ = PasswordExpiry.objects.get_or_create(user=user)
    password_expiry.never_expire()
