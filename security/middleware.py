# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from datetime import datetime
import logging
from re import compile

from django.conf import settings
from django.contrib.auth import logout
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from django.utils import simplejson as json
import django.views.static

from password_expiry import password_is_expired


logger = logging.getLogger(__name__)

# https://developer.mozilla.org/en-US/docs/The_Do_Not_Track_Field_Guide/Introduction
class DoNotTrackMiddleware:
    """
    Sets request.dnt to True or False based on the presence of the
    Do Not Track HTTP header. It's up to application to determine how
    to respond to this information, but usually this should result in
    tracking cookies or web beacons *not* being set for this particular
    request.
    """
    def process_request(self, request):
        if 'HTTP_DNT' in request.META and request.META['HTTP_DNT'] == '1':
            request.dnt = True
        else:
            request.dnt = False

# http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx
class XssProtectMiddleware:
    """
    Sends X-XSS-Protection HTTP header that controls Cross-Site Scripting filter
    on MSIE. Uses XSS_PROTECT setting with the following values:

        on -- enable full XSS filter blocking XSS requests (default)
        sanitize -- enable XSS filter that tries to sanitize requests instead of blocking (less effective)
        off -- completely distable XSS filter
    """
    def __init__(self):
        self.options = { 'on' : '1; mode=block', 'off' : '0', 'sanitize' : '1', }
        try:
            self.option = settings.XSS_PROTECT.lower()
            assert(self.option in options.keys())
        except AttributeError:
            self.option = 'on'

    def process_response(self, request, response):
        """
        Add X-XSS-Protection to the reponse header.
        """
        response['X-XSS-Protection'] = self.options[self.option]
        return response

# http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
class ContentNoSniff:
    """
    Sends X-Content-Options HTTP header to disable autodetection of MIME type of files returned by the server.
    """

    def process_response(self, request, response):
        """
        And X-Content-Options: nosniff to the response header.
        """
        response['X-Content-Options'] = 'nosniff'
        return response


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
        except:
            logger.error("Bad MANDATORY_PASSWORD_CHANGE dictionary. "
                         "MandatoryPasswordChangeMiddleware disabled.")
            raise django.core.exceptions.MiddlewareNotUsed

    def process_view(self, request, view, *args, **kwargs):
        if (not request.user.is_authenticated() or
             view == django.views.static.serve or # Mostly for testing, since
                                                  # Django shouldn't be serving
                                                  # media in production.
             request.path in self.exempt_urls):
            return
        if password_is_expired(request.user):
            return HttpResponseRedirect(self.password_change_url)


class NoConfidentialCachingMiddleware:
    """
    Adds No-Cache and No-Store Headers to Confidential pages
    """

    def __init__(self):
        """
        Looks for a valid configuration in settings.MANDATORY_PASSWORD_CHANGE.
        If there is any problem, the view handler is not installed.
        """
        try:
            config = settings.NO_CONFIDENTIAL_CACHING
            self.whitelist = config.get("WHITELIST_ON", False)
            if self.whitelist:
                self.whitelist_url_regexes = map(compile, config["WHITELIST_REGEXES"])
            self.blacklist = config.get("BLACKLIST_ON", False)
            if self.blacklist:
                self.blacklist_url_regexes = map(compile, config["BLACKLIST_REGEXES"])
        except Exception:
            logger.error("Bad NO_CONFIDENTIAL_CACHING dictionary. "
                         "NoConfidentialCachingMiddleware disabled.")
            raise django.core.exceptions.MiddlewareNotUsed

    def process_response(self, request, response):
        """
        Add the Cache control no-store to anything confidential. You can either
        Whitelist non-confidential pages and treat all others as non-confidential,
        or specifically blacklist pages as confidential
        """
        def match(path, match_list):
            path = path.lstrip('/')
            return any(re.match(path) for re in match_list)
        cache_control = 'no-cache, no-store'

        if self.whitelist:
            if not match(request.path, self.whitelist_url_regexes):
                response['Cache-Control'] = cache_control
        if self.blacklist:
            if match(request.path, self.blacklist_url_regexes):
                response['Cache-Control'] = cache_control
        return response

class HttpOnlySessionCookieMiddleware:
    """
    Middleware that tags the sessionid cookie 'HttpOnly'.
    This should get handled by Django starting in v1.3.
    """
    def process_response(self, request, response):
        if response.cookies.has_key('sessionid'):
            response.cookies['sessionid']['httponly'] = True
        return response

# http://tools.ietf.org/html/draft-ietf-websec-x-frame-options-01
# http://tools.ietf.org/html/draft-ietf-websec-frame-options-00
class XFrameOptionsMiddleware:
    """
    This middleware appends X-Frame-Options and Frame-Options headers
    to HTTP response. Value is set from X_FRAME_OPTIONS option
    in settings file. Possible values are "sameorigin", "deny"
    and "allow-from: URL". Default is "deny".
    """

    def __init__(self):
        try:
            self.option = settings.X_FRAME_OPTIONS.lower()
            assert(self.option == 'sameorigin' or self.option == 'deny'
                    or self.option.startswith('allow-from:'))
        except AttributeError:
            self.option = 'deny'

    def process_response(self, request, response):
        """
        And X-Frame-Options and Frame-Options to the response header. 
        """
        response['X-Frame-Options'] = self.option
        response['Frame-Options']   = self.option
        return response

# preserve older django-security API
# new API uses "deny" as default to maintain compatibility
XFrameOptionsDenyMiddleware = XFrameOptionsMiddleware

# http://www.w3.org/TR/2012/CR-CSP-20121115/
class ContentSecurityPolicyMiddleware:
    """
    This middleware adds Content Security Policy header
    to HTTP response. Mandatory setting CONTENT_SECURITY_POLICY contains
    the policy string, as defined by draft published
    at http://www.w3.org/TR/CSP/ Example:

    CONTENT_SECURITY_POLICY="allow 'self'; script-src *.google.com"

    This middleware supports CSP header syntax for MSIE 10, Firefox
    (Content-Security-Policy) and Chrome (X-WebKit-CSP).

    Warning: enabling CSP has signification impact on browser
    behavior - for example inline JavaScript is disabled. Read
    http://developer.chrome.com/extensions/contentSecurityPolicy.html
    to see how pages need to be adapted to work under CSP.

    If CONTENT_SECURITY_POLICY_REPORT_ONLY is set to True, CSP will
    be enabled in Report Only mode (no enforcement).
    """
    def __init__(self):
        try:
            self.policy = settings.CONTENT_SECURITY_POLICY
        except AttributeError:
            raise django.core.exceptions.MiddlewareNotUsed
        try:
            self.report_only = settings.CONTENT_SECURITY_POLICY_REPORT_ONLY
        except:
            self.report_only = False

    def process_response(self, request, response):
        """
        And Content Security Policy policy to the response header.
        """
        if not report_only:
            response['Content-Security-Policy'] = self.policy
            response['X-WebKit-CSP'] = self.policy
        else:
            response['Content-Security-Policy-Report-Only'] = self.policy
        return response

# http://tools.ietf.org/html/rfc6797
class StrictTransportSecurityMiddleware:
    """
    This middleware adds Strict-Transport-Security header to HTTP
    response, enforcing SSL connections on compliant browsers. Two
    parameters can be set in settings file:

    STS_MAX_AGE = time in seconds to preserve host's STS policy
                  (default: 1 year)
    STS_INCLUDE_SUBDOMAINS = whether subdomains should be covered
                             by the policy as well (default: True)
    """

    def __init__(self):
        try:
            self.max_age = settings.STS_MAX_AGE
            self.subdomains = settings.STS_INCLUDE_SUBDOMAINS
        except AttributeError:
            self.max_age = 3600*24*365 # one year
            self.subdomains = True
        self.value = 'max-age={1}'.format(self.max_age)
        if self.subdomains:
            self.value += ' ; includeSubDomains'

    def process_response(self, request, response):
        """
        Add Strict-Transport-Security header.
        """
        response['Strict-Transport-Security'] = self.value
        return response

class P3PPolicyMiddleware:
    """
    This middleware will append the http header attribute
    specifying your P3P policy as set out in your settings
    """
    def __init__(self):
        try:
            self.policy = settings.P3P_COMPACT_POLICY
        except AttributeError:
            raise django.core.exceptions.MiddlewareNotUsed

    def process_response(self, request, response):
        """
        And P3P policy to the response header.
        """
        response['P3P'] = 'policyref="/w3c/p3p.xml" CP="%s"' % self.policy
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
    the site that hasn't been white listed. (The middleware also ensures the
    user is 'active'. Disabled users are also redirected to the login page.

    Exemptions to this requirement can optionally be specified in settings via
    a list of regular expressions in LOGIN_EXEMPT_URLS (which you can copy from
    your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    EXEMPT_URLS = []
    if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
        EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

    def process_request(self, request):
        assert hasattr(request, 'user'), ("The Login Required middleware"
                "requires authentication middleware to be installed.")
        if request.user.is_authenticated() and not request.user.is_active:
            logout(request)
        if not request.user.is_authenticated():
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in LoginRequiredMiddleware.EXEMPT_URLS):
                if request.is_ajax():
                    response = {"login_url": settings.LOGIN_URL}
                    return HttpResponse(json.dumps(response), status=401,
                            mimetype="application/json")
                else:
                    login_url = "%s?next=%s" % (settings.LOGIN_URL, request.path)
                    return HttpResponseRedirect(login_url)

