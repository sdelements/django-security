import hashlib
import logging
import time
import typing
import urllib.parse
from math import ceil

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect

from security.middleware import BaseMiddleware

logger = logging.getLogger(__name__)


class HttpResponseTooManyRequests(HttpResponse):
    status_code = 429


def delay_message(remainder):
    """
    A natural-language description of a delay period.

    Note: Python 3 uses unbiased rounding, so produces slightly different
    numbers than Python 2, but this is for human readability only, so does not
    need to be the same.
    """
    # TODO: There's probably a library for this.
    minutes = round(float(remainder) / 60)

    if minutes == 1:
        return _("1 minute")
    elif minutes > 1:
        return _("%d minutes") % minutes
    elif ceil(remainder) == 1:
        return _("1 second")
    else:
        return _("%d seconds") % ceil(remainder)


def _to_ascii_compatible(value: typing.Any):
    if isinstance(value, str) and not value.isascii():
        value = urllib.parse.quote(value)

    return value


def _key(counter_type, counter_name):
    """
    We store a hashed version of the key because what we generate can be
    too long, and it's possible the POST data we get could contain characters
    that memcache doesn't like.
    """
    key = "security.authentication_throttling.%s:%s" % (
        _to_ascii_compatible(counter_type),
        _to_ascii_compatible(counter_name),
    )
    return hashlib.sha256(key.encode("ascii")).hexdigest()


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
    cache.set_many(existing, timeout=48 * 60 * 60)  # 48 hours


def _extract_username(request):
    """
    Look for the "username" in a request. If there is no valid username we
    will simply be throttling on IP alone.
    """
    return request.POST.get("username", "notfound").lower()


def register_authentication_attempt(request):
    """
    The given request is a login attempt that has already passed through the
    authentication middleware. Adjusts the throttling counters based on whether
    it succeeded or failed.
    """
    username = _extract_username(request)
    ip = request.META["REMOTE_ADDR"]
    if request.user.is_authenticated:
        reset_counters(username=username, ip=ip)
    else:
        increment_counters(username=username, ip=ip)


def default_delay_function(account_attempt_count, ip_attempt_count):
    """
    We throttle based on how many times we have seen a request from a
    particular IP or username. This function will delay the third attempt on an
    account for five seconds, and double that delay on every additional
    failure, to a maximum of twenty-four hours. We do NOT delay based on IP.
    Popular opinion is that IP based throttling doesn't belong in the
    application layer.
    """
    if account_attempt_count < 3:
        return (0, 0)

    twentyfour_hours = 60 * 60 * 24
    account_delay = min(5 * 2 ** (account_attempt_count - 3), twentyfour_hours)

    return (account_delay, 0)


def throttling_delay(username, ip, delay_function=default_delay_function):
    """
    Return the greater of the delay periods called for by the username and
    the IP of this login request.
    """
    t = time.time()
    acc_n, acc_t = cache.get(_key("username", username), (0, t))
    ip_n, ip_t = cache.get(_key("ip", ip), (0, t))
    acc_delay, ip_delay = delay_function(acc_n, ip_n)
    return max(acc_t + acc_delay - t, ip_t + ip_delay - t)


def attempt_count(attempt_type, id):
    """
    Only used by tests.
    """
    return cache.get(_key(attempt_type, id), (0,))[0]


class _ThrottlingForm(AuthenticationForm):
    def __init__(self, delay, *args, **kwargs):
        super(_ThrottlingForm, self).__init__(*args, **kwargs)
        message = (
            "Due to the failure of previous attempts, your login request has "
            "been denied as a security precaution. Please try again in at "
            "least %s." % delay_message(delay)
        )
        self._errors = {"__all__": self.error_class([message])}


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

    There is only one required setting, AUTHENTICATION_THROTTLING, which
    should contain the following information:

        LOGIN_URLS_WITH_TEMPLATES - a list of pairs of URL and django
                                    template paths.  If the supplied template
                                    in LOGIN_URLS_WITH_TEMPLATES is None we
                                    simply return a HTTP 429 error.
        DELAY_FUNCTION -            a function of two arguments, called when a
                                    request is being considered for throttling:
                                    The first argument is the number of failed
                                    attempts that have been made on the
                                    username being supplied since the last
                                    success, and the second argument is the
                                    number of attempts from the IP. The
                                    function should return a pair: The number
                                    of seconds to delay the next attempt on
                                    that username, and the number of seconds to
                                    delay the next attempt from that IP.
        REDIRECT_FIELD_NAME       - used to override the default
                                    REDIRECT_FIELD_NAME.

    LOGIN_URLS_WITH_TEMPLATES is required. The other parameters are optional.
    """

    REQUIRED_SETTINGS = ("AUTHENTICATION_THROTTLING",)

    def load_setting(self, setting, value):
        """ """
        value = value or {}

        try:
            self.logins = list(value["LOGIN_URLS_WITH_TEMPLATES"])
        except KeyError:
            raise ImproperlyConfigured(
                "Bad AUTHENTICATION_THROTTLING dictionary. "
                "AuthenticationThrottlingMiddleware disabled."
            )

        self.delay_function = value.get(
            "DELAY_FUNCTION",
            default_delay_function,
        )
        self.redirect_field_name = value.get(
            "REDIRECT_FIELD_NAME",
            REDIRECT_FIELD_NAME,
        )

    def process_request(self, request):
        """
        Block the request if it is a login attempt to which a throttling delay
        is applicable. We don't process requests that are not PUTs or POSTs.
        """
        if not (request.method == "POST" or request.method == "PUT"):
            return

        for url, template_name in self.logins:
            if request.path[1:] != url:
                continue

            username = _extract_username(request)
            ip = request.META["REMOTE_ADDR"]

            delay = throttling_delay(username, ip, self.delay_function)

            if delay <= 0:
                request.META["login_request_permitted"] = True
                return
            # else: throttle the request

            if not template_name:
                # we simply return HTTP 429 Too Many Requests
                return HttpResponseTooManyRequests()

            # update the login form to indicate the throttling error, which
            # will be displayed to the user.
            form = _ThrottlingForm(delay, request)
            redirect_url = request.GET.get(self.redirect_field_name, "")
            current_site = get_current_site(request)
            # Template-compatible with 'django.contrib.auth.views.login'.
            return csrf_protect(
                lambda request, template_name=template_name, form=form, redirect_url=redirect_url, current_site=current_site: render(
                    request,
                    template_name,
                    {
                        "form": form,
                        self.redirect_field_name: redirect_url,
                        "site": current_site,
                        "site_name": current_site.name,
                    },
                ),
            )(request)

    def process_response(self, request, response):
        if request.META.get("login_request_permitted", False):
            register_authentication_attempt(request)
        return response


__all__ = [
    delay_message,
    increment_counters,
    reset_counters,
    attempt_count,
    default_delay_function,
    throttling_delay,
]
