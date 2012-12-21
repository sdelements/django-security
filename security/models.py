# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class PasswordExpiry(models.Model):
    """
    Associate a password expiry date with a user. For now, this date is
    effectively just a flag to tell us whether the user has ever changed
    their password, used to force users to change their initial passwords
    when they log in for the first time. Instances are created by
    security.RequirePasswordChangeMiddleware.
    """

    user = models.ForeignKey(User, unique=True) # Not one-to-one because some
                                                # users may never receive an
                                                # expiry date.
    password_expiry_date = models.DateTimeField(auto_now_add=True,
                                                null=True,
                                                help_text="The date and time "
                                                          "when the user's "
                                                          "password expires. If "
                                                          "this is empty, the "
                                                          "password never "
                                                          "expires.")

    def is_expired(self):
        if self.password_expiry_date is None:
            return False
        else:
            return self.password_expiry_date <= timezone.now()

    def never_expire(self):
        self.password_expiry_date = None
        self.save()

    class Meta:
        verbose_name_plural = "PasswordExpiries"

