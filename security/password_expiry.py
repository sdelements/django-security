# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from models import PasswordExpiry


def password_is_expired(user):
    return (not user.is_superuser and
             (PasswordExpiry.objects.get_or_create(user=user)[0].is_expired()))

def never_expire_password(user):
    PasswordExpiry.objects.get_or_create(user=user)[0].never_expire()

