# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import re

from django.core.validators import RegexValidator
from django.forms import ValidationError as VE
from django.utils.translation import gettext as _


def min_length(n):
    """
    Returns a validator that fails on finding too few characters. Necessary
    because django.core.validators.MinLengthValidator doesn't take a message
    argument.
    """
    def validate(password):
        if len(password) < n:
            raise VE(_("It must contain at least %d characters.") % n)
    return validate

# The error messages from the RegexValidators don't display properly unless we
# explicitly supply an empty error code.

lowercase = RegexValidator(r"[a-z]",
                           _("It must contain at least one lowercase letter."),
                           '')

uppercase = RegexValidator(r"[A-Z]",
                           _("It must contain at least one uppercase letter."),
                           '')

digit = RegexValidator(r"[0-9]",
                       _("It must contain at least one decimal digit."),
                       '')

