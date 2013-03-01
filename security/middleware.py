# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import logging
from re import compile

import django.conf
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse, NoReverseMatch
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseServerError
from django.test.signals import setting_changed
from django.utils import simplejson as json, timezone
import django.views.static

from password_expiry import password_is_expired


logger = logging.getLogger(__name__)

class BaseMiddleware(object):
    """
    Abstract class containing some functionality common to all middleware.
    """

    REQUIRED_SETTINGS = ()
    OPTIONAL_SETTINGS = ()

    def load_setting(self, setting, value):
        """
        Called initially for each of the keys in REQUIRED_SETTINGS and OPTIONAL_SETTINGS,
        and again whenever any of these settings change (from the setting_changed signal).
        Passed the setting key and the new value, which may be None for the keys in
        OPTIONAL_SETTINGS. If no setting keys are defined then this method is never called.
        """

    def _on_setting_changed(self, signal, sender, setting, value):
        if setting in self.REQUIRED_SETTINGS or setting in self.OPTIONAL_SETTINGS:
            self.load_setting(setting, value)

    def __init__(self):
        if self.REQUIRED_SETTINGS or self.OPTIONAL_SETTINGS:
            for key in self.REQUIRED_SETTINGS:
                if hasattr(django.conf.settings, key):
                    self.load_setting(key, getattr(django.conf.settings, key))
                else:
                    raise django.core.exceptions.ImproperlyConfigured(
                        self.__class__.__name__ + " requires setting " + key)

            for key in self.OPTIONAL_SETTINGS:
                self.load_setting(key, getattr(django.conf.settings, key, None))

            setting_changed.connect(self._on_setting_changed)



class MandatoryPasswordChangeMiddleware(BaseMiddleware):
    """
    Redirects any request from an authenticated user to the password change
    form if that user's password has expired. Must be placed after
    AuthenticationMiddleware in the middleware list.
    """

    OPTIONAL_SETTINGS = ("MANDATORY_PASSWORD_CHANGE",)

    def load_setting(self, setting, value):
        if value and not value.has_key("URL_NAME"):
            raise ImproperlyConfigured(MandatoryPasswordChangeMiddleware.__name__+" requires the URL_NAME setting")
        self.settings = value
        self.exempt_urls = [compile(url) for url in self.settings.get("EXEMPT_URLS", ())]

    def process_view(self, request, view, *args, **kwargs):
        if self.settings:
            path = request.path_info.lstrip('/')

            # Check for an exempt URL before trying to resolve URL_NAME,
            # because the reason the URL is exempt may be because a special
            # URL config is in use (i.e. during a test) that doesn't have URL_NAME.
            if (not request.user.is_authenticated() or
                view == django.views.static.serve or # Mostly for testing, since
                                                     # Django shouldn't be serving
                                                     # media in production.
                any(m.match(path) for m in self.exempt_urls) or
                request.path in map(reverse, self.settings.get("EXEMPT_URL_NAMES", ()))):
                return

            password_change_url = reverse(self.settings["URL_NAME"])

            if request.path == password_change_url:
                return

            if password_is_expired(request.user):
                return HttpResponseRedirect(password_change_url)


class NoConfidentialCachingMiddleware(BaseMiddleware):
    """
    Adds No-Cache and No-Store Headers to Confidential pages
    """

    OPTIONAL_SETTINGS = ("NO_CONFIDENTIAL_CACHING",)

    def load_setting(self, setting, value):
        value = value or {}
        self.whitelist = value.get("WHITELIST_ON", False)
        if self.whitelist:
            self.whitelist_url_regexes = map(compile, value['WHITELIST_REGEXES'])
        self.blacklist = value.get("BLACKLIST_ON", False)
        if self.blacklist:
            self.blacklist_url_regexes = map(compile, value['BLACKLIST_REGEXES'])

    def process_response(self, request, response):
        """
        Add the Cache control no-store to anything confidential. You can either
        Whitelist non-confidential pages and treat all others as non-confidential,
        or specifically blacklist pages as confidential
        """
        def match(path, match_list):
            path = path.lstrip('/')
            return any(re.match(path) for re in match_list)
        def remove_response_caching(response):
            response['Cache-control'] = 'no-cache, no-store, max-age=0, must-revalidate'
            response['Pragma'] = "no-cache"
            response['Expires'] = -1

        if self.whitelist:
            if not match(request.path, self.whitelist_url_regexes):
                remove_response_caching(response)
        if self.blacklist:
            if match(request.path, self.blacklist_url_regexes):
                remove_response_caching(response)
        return response


class HttpOnlySessionCookieMiddleware(BaseMiddleware):
    """
    Middleware that tags the sessionid cookie 'HttpOnly'.
    This should get handled by Django starting in v1.3.
    """
    def process_response(self, request, response):
        if response.cookies.has_key('sessionid'):
            response.cookies['sessionid']['httponly'] = True
        return response


class XFrameOptionsDenyMiddleware(BaseMiddleware):
    """
    This middleware will append the http header attribute
    'x-frame-options: deny' to the any http response header.
    """

    def process_response(self, request, response):
        """
        And x-frame-options to the response header.
        """
        response['X-FRAME-OPTIONS'] = 'DENY'
        return response


class P3PPolicyMiddleware(BaseMiddleware):
    """
    This middleware will append the http header attribute
    specifying your P3P policy as set out in your settings
    """

    OPTIONAL_SETTINGS = ("P3P_COMPACT_POLICY",)

    def load_setting(self, setting, value):
        self.policy = value

    def process_response(self, request, response):
        """
        And P3P policy to the response header.
        """
        if self.policy:
            response['P3P'] = 'policyref="/w3c/p3p.xml" CP="%s"' % self.policy
        return response


class SessionExpiryPolicyMiddleware(BaseMiddleware):
    """
    The session expiry middleware will let you expire sessions on
    browser close, and on expiry times stored in the cookie itself.
    (Expiring a cookie on browser close means you don't set the expiry
    value of the cookie.) The middleware will read SESSION_COOKIE_AGE
    and SESSION_INACTIVITY_TIMEOUT from the settings.py file to determine
    how long to keep a session alive.

    We will purge a session that has expired. This middleware should be run
    before the LoginRequired middelware if you want to redirect the expired
    session to the login page (if required).
    """

    OPTIONAL_SETTINGS = ('SESSION_COOKIE_AGE', 'SESSION_INACTIVITY_TIMEOUT')

    # Session keys
    START_TIME_KEY = 'starttime'
    LAST_ACTIVITY_KEY = 'lastactivity'

    def load_setting(self, setting, value):
        if setting == 'SESSION_COOKIE_AGE':
            self.SESSION_COOKIE_AGE = value or 86400  # one day in seconds
            logger.debug("Max Session Cookie Age is %d seconds" % self.SESSION_COOKIE_AGE)
        elif setting == 'SESSION_INACTIVITY_TIMEOUT':
            self.SESSION_INACTIVITY_TIMEOUT = value or 1800  # half an hour in seconds
            logger.debug("Session Inactivity Timeout is %d seconds" % self.SESSION_INACTIVITY_TIMEOUT)

    def process_request(self, request):
        """
        Verify that the session should be considered active. We check
        the start time and the last activity time to determine if this
        is the case. We set the last activity time to now() if the session
        is still active.
        """
        now = timezone.now()

        # If the session has no start time or last activity time, set those
        # two values. We assume we have a brand new session.
        if (self.START_TIME_KEY not in request.session or
            self.LAST_ACTIVITY_KEY not in request.session or
            timezone.is_naive(request.session[self.START_TIME_KEY]) or
            timezone.is_naive(request.session[self.LAST_ACTIVITY_KEY])):

            logger.debug("New session %s started: %s" % (request.session.session_key, now))
            request.session[self.START_TIME_KEY] = now
            request.session[self.LAST_ACTIVITY_KEY] = now
        else:
            start_time = request.session[self.START_TIME_KEY]
            last_activity_time = request.session[self.LAST_ACTIVITY_KEY]
            logger.debug("Session %s started: %s" % (request.session.session_key, start_time))
            logger.debug("Session %s last active: %s" % (request.session.session_key, last_activity_time))

            # Is this session older than SESSION_COOKIE_AGE?
            # We don't wory about microseconds.
            SECONDS_PER_DAY = 86400
            start_time_diff = now - start_time
            last_activity_diff = now - last_activity_time
            session_too_old = (start_time_diff.days * SECONDS_PER_DAY + start_time_diff.seconds >
                    self.SESSION_COOKIE_AGE)
            session_inactive = (last_activity_diff.days * SECONDS_PER_DAY + last_activity_diff.seconds >
                    self.SESSION_INACTIVITY_TIMEOUT)

            if session_too_old or session_inactive:
                logger.debug("Session %s is inactive." % request.session.session_key)
                request.session.clear()
            else:
                # The session is good, update the last activity value
                logger.debug("Session %s is still active." % request.session.session_key)
                request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY] = now


# Modified a little bit by us.

# Copyright (c) 2008, Ryan Witt
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the organization nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


class LoginRequiredMiddleware(BaseMiddleware):
    """
    Middleware that requires a user to be authenticated to view any page on
    the site that hasn't been white listed. (The middleware also ensures the
    user is 'active'. Disabled users are also redirected to the login page.

    Exemptions to this requirement can optionally be specified in settings via
    a list of regular expressions in LOGIN_EXEMPT_URLS (which you can copy from
    your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    REQUIRED_SETTINGS = ('LOGIN_URL',)
    OPTIONAL_SETTINGS = ('LOGIN_EXEMPT_URLS',)

    def load_setting(self, setting, value):
        if setting == 'LOGIN_URL':
            self.login_url = value
        elif setting == 'LOGIN_EXEMPT_URLS':
            self.exempt_urls = [compile(expr) for expr in (value or ())]

    def process_request(self, request):
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured("The Login Required middleware"
                "requires authentication middleware to be installed.")
        if request.user.is_authenticated() and not request.user.is_active:
            logout(request)
        if not request.user.is_authenticated():
            if hasattr(request, 'login_url'):
                login_url = request.login_url
                next_url = None
            else:
                login_url = self.login_url
                next_url = request.path
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in self.exempt_urls):
                if request.is_ajax():
                    response = {"login_url": login_url}
                    return HttpResponse(json.dumps(response), status=401,
                            mimetype="application/json")
                else:
                    if next_url:
                        login_url = login_url + '?next=' + next_url
                    return HttpResponseRedirect(login_url)

