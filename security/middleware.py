# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from datetime import datetime
import logging
from re import compile

from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import NoReverseMatch, reverse
from django.utils import simplejson as json
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
            config = settings.MANDATORY_PASSWORD_CHANGE
            self.password_change_url = reverse(config["URL_NAME"])
            self.exempt_urls = [self.password_change_url
                                ] + map(reverse, config["EXEMPT_URL_NAMES"])
            self.process_view = self._process_view_if_configured
        except:
            logger.error("Bad MANDATORY_PASSWORD_CHANGE dictionary. "
                         "MandatoryPasswordChangeMiddleware disabled.")

    def _process_view_if_configured(self, request, view, *args, **kwargs):
        if (not request.user.is_authenticated() or
             view == django.views.static.serve or # Mostly for testing, since
                                                  # Django shouldn't be serving
                                                  # media in production.
             request.path in self.exempt_urls):
            return
        if password_is_expired(request.user):
            return HttpResponseRedirect(self.password_change_url)


class HttpOnlySessionCookieMiddleware:
    """
    Middleware that tags the sessionid cookie 'HttpOnly'.
    This should get handled by Django starting in v1.3.
    """
    def process_response(self, request, response):
        if response.cookies.has_key('sessionid'):
            response.cookies['sessionid']['httponly'] = True
        return response


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

    # Session keys
    START_TIME_KEY = 'starttime'
    LAST_ACTIVITY_KEY = 'lastactivity'

    # Get session expiry settings if available
    if hasattr(settings, 'SESSION_COOKIE_AGE'):
        SESSION_COOKIE_AGE = settings.SESSION_COOKIE_AGE
    else:
        SESSION_COOKIE_AGE = 86400  # one day in seconds
    if hasattr(settings, 'SESSION_INACTIVITY_TIMEOUT'):
        SESSION_INACTIVITY_TIMEOUT = settings.SESSION_INACTIVITY_TIMEOUT
    else:
        SESSION_INACTIVITY_TIMEOUT = 1800  # half an hour in seconds
    logger.debug("Max Session Cookie Age is %d seconds" % SESSION_COOKIE_AGE)
    logger.debug("Session Inactivity Timeout is %d seconds" % SESSION_INACTIVITY_TIMEOUT)

    def process_request(self, request):
        """
        Verify that the session should be considered active. We check
        the start time and the last activity time to determine if this
        is the case. We set the last activity time to now() if the session
        is still active.
        """
        now = datetime.now()

        # If the session has no start time or last activity time, set those
        # two values. We assume we have a brand new session.
        if (SessionExpiryPolicyMiddleware.START_TIME_KEY not in request.session
                or SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY not in request.session):
            logger.debug("New session %s started: %s" % (request.session.session_key, now))
            request.session[SessionExpiryPolicyMiddleware.START_TIME_KEY] = now
            request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY] = now
            return

        start_time = request.session[SessionExpiryPolicyMiddleware.START_TIME_KEY]
        last_activity_time = request.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY]
        logger.debug("Session %s started: %s" % (request.session.session_key, start_time))
        logger.debug("Session %s last active: %s" % (request.session.session_key, last_activity_time))

        # Is this session older than SESSION_COOKIE_AGE?
        # We don't wory about microseconds.
        SECONDS_PER_DAY = 86400
        start_time_diff = now - start_time
        last_activity_diff = now - last_activity_time
        session_too_old = (start_time_diff.days * SECONDS_PER_DAY + start_time_diff.seconds >
                SessionExpiryPolicyMiddleware.SESSION_COOKIE_AGE)
        session_inactive = (last_activity_diff.days * SECONDS_PER_DAY + last_activity_diff.seconds >
                SessionExpiryPolicyMiddleware.SESSION_INACTIVITY_TIMEOUT)

        if (session_too_old or session_inactive):
            logger.debug("Session %s is inactive." % request.session.session_key)
            request.session.clear()
        else:
            # The session is good, update the last activity value
            logger.debug("Session %s is still active." % request.session.session_key)
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

    EXEMPT_URLS = []
    if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
        EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

    def process_request(self, request):
        assert hasattr(request, 'user'), ("The Login Required middleware"
                "requires authentication middleware to be installed.")
        if not request.user.is_authenticated():
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in LoginRequiredMiddleware.EXEMPT_URLS):
                if request.is_ajax():
                    response = {"login_url": settings.LOGIN_URL}
                    return HttpResponse(json.dumps(response), status=403,
                            mimetype="application/json")
                else:
                    login_url = "%s?next=%s" % (settings.LOGIN_URL, request.path)
                    return HttpResponseRedirect(login_url)

