import django.contrib.auth.forms
from django import forms
from django.utils.translation import gettext_lazy as _

from . import auth
from .password_expiry import never_expire_password, password_is_expired


class PasswordChangeForm(django.contrib.auth.forms.PasswordChangeForm):
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        validators=[
            auth.min_length(6),
            auth.uppercase,
            auth.lowercase,
            auth.digit,
        ],
    )

    def __init__(self, *args, **kwargs):
        super(PasswordChangeForm, self).__init__(*args, **kwargs)
        self.user_is_new = password_is_expired(self.user)

    def save(self, *args, **kwargs):
        super(PasswordChangeForm, self).save(*args, **kwargs)
        never_expire_password(self.user)
