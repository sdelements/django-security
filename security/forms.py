# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from django import forms
import django.contrib.auth.forms

from django.utils.translation import ugettext_lazy as _

import auth
from password_expiry import password_is_expired, never_expire_password


class PasswordChangeForm(django.contrib.auth.forms.PasswordChangeForm):
    new_password1 = forms.CharField(label=_("New password"),
                                    widget=forms.PasswordInput,
                                    validators=[auth.min_length(6),
                                                auth.uppercase,
                                                auth.lowercase,
                                                auth.digit])

    def __init__(self, *args, **kwargs):
        super(PasswordChangeForm, self).__init__(*args, **kwargs)
        self.user_is_new = password_is_expired(self.user)

    def save(self, *args, **kwargs):
        super(PasswordChangeForm, self).save(*args, **kwargs)
        never_expire_password(self.user)

