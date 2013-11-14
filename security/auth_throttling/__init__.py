# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

import hashlib
import logging
from math import ceil
import time # Monkeypatched by the tests.

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.sites.models import get_current_site
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_protect

from security import BaseMiddleware

logger = logging.getLogger(__name__)

def delay_message(remainder):
    """
    A natural-language description of a delay period.
    """
    # TODO: There's probably a library for this.
    minutes = round(float(remainder) / 60)
    return (_("1 minute")             if minutes == 1 else
            _("%d minutes") % minutes if minutes > 1 else
            _("1 second")             if ceil(remainder) == 1 else
            _("%d seconds") % ceil(remainder))


def _key(counter_type, counter_name):
    """
    We store a hashed version of the key because what we generate can be
    too long, and it's possible the POST data we get could contain characters
    that memcache doesn't like.
    """
    k = "security.authentication_throttling.%s:%s" % (counter_type, counter_name)
    return hashlib.sha1(k).hexdigest()


def reset_counters(**counters):
    cache.delete_many([_key(*pair) for pair in counters.items()])


def increment_counters(**counters):
    """
    Each keyword is a counter type (e.g. "username", "ip") and each argument
    is an identifier of that type. Increments (creating if not already present)
    each counter.
    """
    t = time.time()
    keys = [_key(*pair) for pair in counters.items()]
    existing = cache.get_many(keys)
    for key in keys:
        existing[key] = (existing.get(key, (0,))[0] + 1, t)
    cache.set_many(existing)


def attempt_count(attempt_type, id):
    """
    Only used by tests.
    """
    return cache.get(_key(attempt_type, id), (0,))[0]


def register_authentication_attempt(request):
    """
    The given request is a login attempt that has already passed through the
    authentication middleware. Adjusts the throttling counters based on whether
    it succeeded or failed.
    """
    (reset_counters if request.user.is_authenticated() else increment_counters
     )(username=request.POST["username"], ip=request.META["REMOTE_ADDR"])


class _ThrottlingForm(AuthenticationForm):
    def __init__(self, throttling_delay, *args, **kwargs):
        super(_ThrottlingForm, self).__init__(*args, **kwargs)
        self._errors = {"__all__":
                          self.error_class(["Due to the failure of previous "
                                              "attempts, your login request "
                                              "has been denied as a security "
                                              "precaution. Please try again "
                                              "in at least %s. " %
                                              delay_message(throttling_delay)
                                            ])}


class Middleware(BaseMiddleware):
    """
    Performs authentication throttling by username and IP.

    Any POST request to one of the supplied login URLs is assumed to be a login
    attempt. The Django cache is used to store failure counts and timestamps:
    If it is found that there is a throttling delay applicable to the attempt
    that has not yet elapsed, a response is returned using the template for
    that URL, with an error informing the user of the situation. Otherwise,
    the request is allowed to continue, and a response handler checks
    request.user to determine whether the login attempt succeeded.
    """

    REQUIRED_SETTINGS = ("AUTHENTICATION_THROTTLING",)

    def load_setting(self, setting, value):
        """
        There is only one required setting, AUTHENTICATION_THROTTLING, which
        should contain the following information:

            DELAY_FUNCTION - a function of two arguments, called when a request
                             is being considered for throttling: The first
                             argument is the number of failed attempts that
                             have been made on the username being supplied
                             since the last success, and the second argument is
                             the number of attempts from the IP. The function
                             should return a pair: The number of seconds to
                             delay the next attempt on that username, and the
                             number of seconds to delay the next attempt from
                             that IP.
            LOGIN_URLS_WITH_TEMPLATES - a list of pairs of URL and template path
            REDIRECT_FIELD_NAME - used to override the default REDIRECT_FIELD_NAME

        REDIRECT_FIELD_NAME is optional, the other fields are required.
        """
        value = value or {}
        self.redirect_field_name = value.get("REDIRECT_FIELD_NAME", REDIRECT_FIELD_NAME)
        try:
            self.delay_function = value["DELAY_FUNCTION"]
            self.logins = list(value["LOGIN_URLS_WITH_TEMPLATES"])
        except KeyError:
            raise ImproperlyConfigured("Bad AUTHENTICATION_THROTTLING dictionary. "
                                       "AuthenticationThrottlingMiddleware disabled.")

    def _throttling_delay(self, request):
        """
        Return the greater of the delay periods called for by the username and
        the IP of this login request.
        """
        t = time.time()
        acc_n, acc_t = cache.get(_key("username", request.POST["username"]),
                                 (0, t))
        ip_n, ip_t = cache.get(_key("ip", request.META["REMOTE_ADDR"]), (0, t))
        acc_delay, ip_delay = self.delay_function(acc_n, ip_n)
        return max(acc_t + acc_delay - t, ip_t + ip_delay - t)

    def process_request(self, request):
        """
        Block the request if it is a login attempt to which a throttling delay
        is applicable.
        """
        if request.method != "POST": return
        for url, template_name in self.logins:
            if request.path[1:] != url: continue
            delay = self._throttling_delay(request)
            if delay <= 0:
                request.META["login_request_permitted"] = True
                return
            form = _ThrottlingForm(delay, request)
            redirect_url = request.REQUEST.get(self.redirect_field_name, "")
            current_site = get_current_site(request)
            # Template-compatible with 'django.contrib.auth.views.login'.
            return csrf_protect(lambda request:
                                  render_to_response(template_name,
                                                     {"form":
                                                        form,
                                                      self.redirect_field_name:
                                                        redirect_url,
                                                      "site":
                                                        current_site,
                                                      "site_name":
                                                        current_site.name},
                                                     context_instance=
                                                      RequestContext(request))
                                )(request)

    def process_response(self, request, response):
        if request.META.get("login_request_permitted", False):
            register_authentication_attempt(request)
        return response

__all__ = [delay_message, increment_counters, attempt_count, reset_counters]
