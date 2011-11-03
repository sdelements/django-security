# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from datetime import datetime, MINYEAR, MAXYEAR

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import models


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
    password_expiry_date = models.DateTimeField(default=
                                                 datetime(MINYEAR, 1, 1))

    def is_expired(self):
        return self.password_expiry_date <= datetime.utcnow()

    def never_expire(self):
        self.password_expiry_date = datetime(MAXYEAR, 12, 31)
        self.save()

    class Meta:
        verbose_name_plural = "PasswordExpiries"

