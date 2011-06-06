# Copyright (c) 2011, SD Elements. See LICENSE file for details.

import logging
from re import compile, escape
import simplejson as json
import time

from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import NoReverseMatch, reverse
import django.views.static

from password_expiry import password_is_expired


logger = logging.getLogger(__name__)


class MandatoryPasswordChangeMiddleware:
    """
    Redirects any request from an authenticated user to the password change
    form if that user's password has expired. Must be placed after
    AuthenticationMiddleware in the middleware list.
    """

    def __init__(self):
        """
        Looks for a valid configuration in settings.MANDATORY_PASSWORD_CHANGE.
        If there is any problem, the view handler is not installed.
        """
        try:
            conf = settings.MANDATORY_PASSWORD_CHANGE
            self.password_change_url = (conf["URL"]
                                          if conf.has_key("URL")
                                          else reverse(conf["URL_NAME"])
                                        ).lstrip("/")
            self.exempt_urls = [compile(escape(self.password_change_url))
                                ] + [compile(s.lstrip("/"))
                                     for s
                                     in conf.get("EXEMPT_URLS", []) +
                                          [escape(reverse(name))
                                           for name
                                           in conf.get("EXEMPT_URL_NAMES",
                                                       [])]]
            self.process_view = self._process_view_if_configured
        except Exception:
            logger.error("Bad MANDATORY_PASSWORD_CHANGE dictionary, "
                           "MandatoryPasswordChangeMiddleware disabled.")

    def _process_view_if_configured(self, request, view, *args, **kwargs):
        if (not request.user.is_authenticated() or
              view == django.views.static.serve or # Mostly for testing, since
                                                   # Django shouldn't serve
                                                   # media in production.
              any(url.match(request.path_info.lstrip("/"))
                  for url in self.exempt_urls)):
            return
        if password_is_expired(request.user):
            return HttpResponseRedirect("/" + self.password_change_url)


class XFrameOptionsDenyMiddleware:
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


class SessionExpiryPolicyMiddleware:
    """
    Expire sessions based on time elapsed since authentication and time elapsed
    since last authenticated request. By storing the timestamps in the session
    rather than by setting the expiry date of the session cookie, we retain the
    ability to expire on browser close.
    """

    START_TIME_KEY = 'starttime'
    LAST_ACTIVITY_KEY = 'lastactivity'

    def __init__(self):
        self.SESSION_COOKIE_AGE = getattr(settings,
                                          "SESSION_COOKIE_AGE",
                                          60 * 60 * 24)
        self.SESSION_INACTIVITY_TIMEOUT = getattr(settings,
                                                  "SESSION_INACTIVITY_TIMEOUT",
                                                  60 * 30)

    def process_request(self, request):
        """
        Flush the session if it has expired. Otherwise, update the activity
        timestamp.
        """
        now = time.time()
        try:
            start_time = request.session[SessionExpiryPolicyMiddleware.START_TIME_KEY]
            last_activity_time = request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY]
        except KeyError:
            request.session[SessionExpiryPolicyMiddleware.START_TIME_KEY] = now
            request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY] = now
            return
        too_old = (now - start_time > self.SESSION_COOKIE_AGE)
        inactive = (now - last_activity_time > self.SESSION_INACTIVITY_TIMEOUT)
        if (too_old or inactive):
            request.session.flush()
        else:
            request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY] = now
        return


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


class LoginRequiredMiddleware:
    """
    Middleware that requires a user to be authenticated to view any page on
    the site that hasn't been white listed. Exemptions to this requirement
    can optionally be specified in settings via a list of regular expressions
    in LOGIN_EXEMPT_URLS (which you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    def __init__(self):
        self.EXEMPT_URLS = [compile(regex)
                            for regex
                            in getattr(settings, "LOGIN_EXEMPT_URLS", [])]

    def process_request(self, request):
        assert hasattr(request, 'user'), ("The Login Required middleware "
                                            "requires authentication "
                                            "middleware to be installed.")
        if not request.user.is_authenticated():
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in self.EXEMPT_URLS):
                if request.is_ajax():
                    response = {"login_url": settings.LOGIN_URL}
                    return HttpResponse(json.dumps(response), status=403,
                                        mimetype="application/json")
                else:
                    login_url = "%s?next=%s" % (settings.LOGIN_URL, request.path)
                    return HttpResponseRedirect(login_url)

