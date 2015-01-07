# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import logging
from re import compile

import django  # for VERSION
import django.conf
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse, resolve
from django.http import HttpResponseRedirect, HttpResponse
from django.test.signals import setting_changed
from django.utils import timezone
import json
import django.views.static

from password_expiry import password_is_expired

logger = logging.getLogger(__name__)


class BaseMiddleware(object):
    """
    Abstract class containing some functionality common to all middleware that
    require configuration.
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

    def _on_setting_changed(self, sender, setting, value, **kwargs):
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


class DoNotTrackMiddleware:
    """
    When this middleware is installed Django views can access a new ``request.dnt``
    parameter to check client's preference on user tracking as expressed by their
    browser configuration settings.

    The parameter can take True, False or None values based on the presence of
    the ``DNT`` (do not track) HTTP header in client's request. The header indicates
    client's general preference to opt-out from behavioral profiling and third-party tracking.

    The parameter does **not** change behaviour of Django in any way as its sole
    purpose is to pass the user's preference to application. It's then up to the owner
    to implement a particular policy based on this information. Compliant website should
    adapt its behaviour depending on one of user's preferences:

    - Explicit opt-out (``request.dnt`` is ``True``): Disable third party tracking for
      this request and delete all previously stored tracking data.
    - Explicit opt-in (``request.dnt`` is ``False``): Website may track user.
    - Header not present (``request.dnt`` is ``None``): Website may track user, but should
      not draw any definite conclusions on user's preferences as the user has not expressed it.

    For example, if ``request.dnt`` is `` True`` the website might respond by disabling
    template parts responsible for personalized statistics, targeted advertisements
    or switching to DNT aware ones.

    Examples:

    - `Do Not Track (DNT) tutorial for Django <http://ipsec.pl/node/1101>`_
    - `Do Not Track - Web Application Templates <http://donottrack.us/application>`_
    - `Opt-out of tailoring Twitter <https://dev.twitter.com/docs/tweet-button#optout>`_

    References:

    - `Web Tracking Protection <http://www.w3.org/Submission/web-tracking-protection/>`_
    - `Do Not Track: A Universal Third-Party Web Tracking Opt Out <http://tools.ietf.org/html/draft-mayer-do-not-track-00>`_
    """

    def process_request(self, request):
        """ Read DNT header from browser request and create request attribute """
        if 'HTTP_DNT' in request.META:
            if request.META['HTTP_DNT'] == '1':
                request.dnt = True
            else:
                request.dnt = False
        else:
            request.dnt = None
            # returns None in normal conditions

    def process_response(self, request, response):
        """ Echo DNT header in response per section 8.4 of draft-mayer-do-not-track-00 """
        if 'HTTP_DNT' in request.META:
            response['DNT'] = '1'
        return response


class XssProtectMiddleware(BaseMiddleware):
    """
    Sends X-XSS-Protection HTTP header that controls Cross-Site Scripting filter
    on MSIE. Use XSS_PROTECT option in settings file with the following values:

      ``sanitize``   enable XSS filter that tries to sanitize requests instead of blocking (*default*)
      ``on``         enable full XSS filter blocking XSS requests (may `leak document.referrer <http://homakov.blogspot.com/2013/02/hacking-with-xss-auditor.html>_`)
      ``off``        completely disable XSS filter

    Reference: 

    - `Controlling the XSS Filter <http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx>`_
    """

    OPTIONAL_SETTINGS = ("XSS_PROTECT",)

    OPTIONS = {'on': '1; mode=block', 'off': '0', 'sanitize': '1', }

    DEFAULT = 'sanitize'

    def load_setting(self, setting, value):
        if not value:
            self.option = XssProtectMiddleware.DEFAULT
            return
        value = value.lower()
        if value not in XssProtectMiddleware.OPTIONS.keys():
            raise ImproperlyConfigured(XssProtectMiddleware.__name__ + " invalid option for XSS_PROTECT.")
        self.option = value

    def process_response(self, request, response):
        """
        Add X-XSS-Protection to the reponse header.
        """
        response['X-XSS-Protection'] = XssProtectMiddleware.OPTIONS[self.option]
        return response


# http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
class ContentNoSniff:
    """
    Sends X-Content-Options HTTP header to disable autodetection of MIME type
    of files returned by the server in Microsoft Internet Explorer. Specifically
    if this flag is enabled, MSIE will not load external CSS and JavaScript files
    unless server correctly declares their MIME type. This mitigates attacks
    where web page would for example load a script that was disguised as an user-
    supplied image.

    Reference: 
    
    - `MIME-Handling Change: X-Content-Type-Options: nosniff <http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx>`_
    """

    def process_response(self, request, response):
        """
        And ``X-Content-Options: nosniff`` to the response header.
        """
        response['X-Content-Options'] = 'nosniff'
        return response


class MandatoryPasswordChangeMiddleware(BaseMiddleware):
    """
    Redirects any request from an authenticated user to the password change
    form if that user's password has expired. Must be placed after
    ``AuthenticationMiddleware`` in the middleware list.

    Configured by dictionary ``MANDATORY_PASSWORD_CHANGE`` with the following
    keys:

        ``URL_NAME``            name of of the password change view
        ``EXEMPT_URL_NAMES``    list of URLs that do not trigger password change request
    """

    OPTIONAL_SETTINGS = ("MANDATORY_PASSWORD_CHANGE",)

    def load_setting(self, setting, value):
        if value and not value.has_key("URL_NAME"):
            raise ImproperlyConfigured(MandatoryPasswordChangeMiddleware.__name__ + " requires the URL_NAME setting")
        self.settings = value
        self.exempt_urls = [compile(url) for url in self.settings.get("EXEMPT_URLS", ())]

    def process_view(self, request, view, *args, **kwargs):
        if self.settings:
            path = request.path_info.lstrip('/')
            url_name = resolve(request.path_info).url_name

            # Check for an exempt URL before trying to resolve URL_NAME,
            # because the reason the URL is exempt may be because a special
            # URL config is in use (i.e. during a test) that doesn't have URL_NAME.
            if (not request.user.is_authenticated() or
                        view == django.views.static.serve or  # Mostly for testing, since
                # Django shouldn't be serving
                # media in production.
                    any(m.match(path) for m in self.exempt_urls) or
                        url_name in self.settings.get("EXEMPT_URL_NAMES", ())):
                return

            password_change_url = reverse(self.settings["URL_NAME"])

            if request.path == password_change_url:
                return

            if password_is_expired(request.user):
                return HttpResponseRedirect(password_change_url)


class NoConfidentialCachingMiddleware(BaseMiddleware):
    """
    Adds No-Cache and No-Store headers to confidential pages. You can either
    whitelist non-confidential pages and treat all others as non-confidential,
    or specifically blacklist pages as confidential. The behaviouri is configured
    in ``NO_CONFIDENTIAL_CACHING`` dictionary in settings file with the
    following keys:

        ``WHITELIST_ON``        all pages are confifendialt, except for
                                pages explicitly whitelisted in ``WHITELIST_REGEXES``
        ``WHITELIST_REGEXES``   list of regular expressions defining pages exempt
                                from the no caching policy
        ``BLACKLIST_ON``        only pages defined in ``BLACKLIST_REGEXES`` will
                                have caching disabled
        ``BLACKLIST_REGEXES``   list of regular expressions defining confidential
                                pages for which caching should be prohibited

    **Note:** Django cache_control_ decorator allows more granular control
    of caching on individual view level.

    .. _cache_control: https://docs.djangoproject.com/en/dev/topics/cache/#controlling-cache-using-other-headers

    Reference: 

    - `HTTP/1.1 Header definitions - What is Cacheable <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1>`_
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
        whitelist non-confidential pages and treat all others as non-confidential,
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


# http://tools.ietf.org/html/draft-ietf-websec-x-frame-options-01
# http://tools.ietf.org/html/draft-ietf-websec-frame-options-00
class XFrameOptionsMiddleware(BaseMiddleware):
    """
    Emits ``X-Frame-Options headers`` in HTTP response. These
    headers will instruct the browser to limit ability of this web page
    to be framed, or displayed within a FRAME or IFRAME tag. This mitigates
    password stealing attacks like Clickjacking and similar.

    Use ``X_FRAME_OPTIONS`` in settings file with the following values:

      - ``deny``              prohibit any framing of this page
      - ``sameorigin``        allow frames from the same domain (*default*)
      - ``allow-from URL``  allow frames from specified *URL*

    **Note:** Frames and inline frames are frequently used by ads, social media
    plugins and similar widgets so test these features after setting this flag. For
    more granular control use ContentSecurityPolicyMiddleware_.

    References: 
    
    - `RFC 7034: HTTP Header Field X-Frame-Options <http://tools.ietf.org/html/rfc7034>`_
    """

    OPTIONAL_SETTINGS = ('X_FRAME_OPTIONS',)

    DEFAULT = 'deny'

    def load_setting(self, setting, value):
        if not value:
            self.option = XFrameOptionsMiddleware.DEFAULT
            return
        value = value.lower()
        if value not in ['sameorigin', 'deny'] and not value.startswith('allow-from:'):
            raise ImproperlyConfigured(XFrameOptionsMiddleware.__name__ + " invalid option for X_FRAME_OPTIONS.")
        self.option = value

    def process_response(self, request, response):
        """
        And X-Frame-Options and Frame-Options to the response header.
        """
        response['X-Frame-Options'] = self.option
        return response

# preserve older django-security API
# new API uses "deny" as default to maintain compatibility
XFrameOptionsDenyMiddleware = XFrameOptionsMiddleware


class ContentSecurityPolicyMiddleware:
    """
    .. _ContentSecurityPolicyMiddleware:
    Adds Content Security Policy (CSP) header to HTTP response.
    CSP provides fine grained instructions to the browser on
    location of allowed resources loaded by the page, thus mitigating
    attacks based on loading of untrusted JavaScript code such
    as Cross-Site Scripting.

    The policy can be set in two modes, controlled by ``CSP_MODE`` options:

        ``CSP_MODE='enforce'``        browser will enforce policy settings and
                                      log violations (*default*)
        ``CSP_MODE='report-only'``    browser will not enforce policy, only report
                                      violations

    The policy itself is a dictionary of content type keys and values containing
    list of allowed locations. For example, ``img-src`` specifies locations
    of images allowed to be loaded by this page:

        ``'img-src' : [ 'img.example.com' ]``

    Content types and special location types (such as ``none`` or ``self``)
    are defined in CSP draft (see References_).

    Example of policy dictionary (suitable for long, complex policies), with
    all supported content types (but not listing all supported locations):

    ::

        CSP_DICT = {
            # arrays of allowed locations
            "default-src" : ["self", "https:" ],
            "script-src" : ["self", "http://js.example.com" ],
            "style-src" : ["self", "http://css.example.com" ],
            "img-src" : ["self", "https://img.example.com" ],
            "connect-src" : ["self" ],
            "font-src" : ["https://*.example.com" ],
            "object-src" : ["none" ],
            "media-src" : ["http://media.example.com" ],
            "frame-src" : ["self" ],

            # array of allowed sandbox features
            "sandbox" : [ "" ],

            # array of allowed MIME types
            "plugin-types" : [ "application/pdf" ],

            # these are **not** arrays
            "reflected-xss" : 'filter',
            "report-uri" : "http://example.com/csp-report",
        }

    You can also supply a raw policy string, which is more suitable for short policies:

        ``CSP_STRING="default-src 'self'; script-src *.google.com"``

    If both ``CSP_DICT`` and ``CSP_STRING`` are set the middleware will throw an exception.

    **Notes:**

    - The special locations ('self', 'none', 'unsafe-eval', 'unsafe-inline')
      come **without** the additional single quotes in `CSP_DICT` and they
      will be automatically quoted by the middleware in the HTTP header.
    - The ``CSP_STRING`` on the other hand should be a verbatim copy of the HTTP header
      contents. It's not going the be processed in any way.
    - This middleware only sets the standard HTTP header variants (``Content-Security-Policy``).
      The experimental ones (``X-WebKit-CSP`` and ``Content-Security-Policy``) are now obsolete.
    - Enabling CSP has significant impact on browser behaviour - for example inline
      JavaScript is disabled. Read `Default Policy Restrictions <http://developer.chrome.com/extensions/contentSecurityPolicy.html>`_ to see how pages need to be adapted to work under CSP.
    - Browsers will log CSP violations in JavaScript console and to a remote server
      configured by ``report-uri`` option. This package provides a view (csp_report_)
      to collect these alerts in your application. They can be then viewed using Django
      admin interface. For more advanced analytics try `CspBuilder <https://cspbuilder.info/>`_.
    - The middleware partially supports CSP 1.1 draft syntax.

    .. _References:

    **References:**

    - `Content Security Policy Level 2 <http://www.w3.org/TR/CSP11/>`_,
    - `HTML5.1 - Sandboxing <http://www.w3.org/html/wg/drafts/html/master/single-page.html#sandboxing>`_
    """
    # these types accept CSP string array as arguments
    _CSP_LOC_TYPES = ['default-src', 'connect-src', 'child-src', 'font-src', 'form-action', 'frame-ancestors',
                      'frame-src', 'img-src', 'media-src', 'object-src', 'script-src', 'style-src', 'plugin-types']

    # special location types, as they appear in the CSP_DICT; they will
    # be placed in single quotes in the HTTP header automatically
    _CSP_LOCATIONS = ['self', 'none', 'unsafe-eval', 'unsafe-inline']

    # sandbox allowed arguments
    # http://www.w3.org/TR/CSP11/#directive-sandbox
    _CSP_SANDBOX_ARGS = ['', 'allow-forms', 'allow-same-origin', 'allow-scripts',
                         'allow-top-navigation']

    # reflected-xss allowed arguments
    # http://www.w3.org/TR/CSP11/#directive-reflected-xss
    _CSP_XSS_ARGS = ['allow', 'block', 'filter']

    # referrer allowed arguments
    # http://www.w3.org/TR/CSP11/#directive-referrer
    _CSP_REF_ARGS = ["none", "none-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url"]

    # operational variables
    _csp_string = None
    _csp_mode = None

    def _csp_builder(self, csp_dict):
        csp_string = ""

        for k, v in csp_dict.items():

            # check if the directive is on the list of those requiring an array argument
            if k in self._CSP_LOC_TYPES:

                if type(v) is not list:
                    logger.warning('Arguments to {0} must be given as an array, found {1} instead ({2}) - ignoring'.format(k, type(v), v))
                    raise django.core.exceptions.MiddlewareNotUsed

                # contents taking location
                csp_string += " {0}".format(k);
                for loc in v:
                    if loc in self._CSP_LOCATIONS:
                        csp_string += " '{0}'".format(loc)  # quoted
                    elif loc == '*':
                        csp_string += ' *'  # not quoted
                    else:
                        csp_string += " {0}".format(loc)  # not quoted
                csp_string += ';'

            elif k == 'sandbox':

                if type(v) is not list:
                    logger.warning('Arguments to {0} must be given as an array, found {1} instead ({2}) - ignoring'.format(k, type(v), v))
                    raise django.core.exceptions.MiddlewareNotUsed

                csp_string += " {0}".format(k);
                for opt in v:
                    if opt in self._CSP_SANDBOX_ARGS:
                        csp_string += " {0}".format(opt)
                    else:
                        logger.warning('Invalid CSP sandbox argument {0}'.format(opt))
                        raise django.core.exceptions.MiddlewareNotUsed
                csp_string += ';'

            elif k == 'report-uri':

                csp_string += " {0} {1};".format(k, v);

            elif k == 'referrer':

                if v in self._CSP_REF_ARGS:
                    csp_string += " {0} {1};".format(k, v)
                else:
                    logger.warning('Invalid CSP {0} value {1}'.format(k, v))
                    raise django.core.exceptions.MiddlewareNotUsed

            elif k == 'reflected-xss':

                if v in self._CSP_XSS_ARGS:
                    csp_string += " {0} {1};".format(k, v)
                else:
                    logger.warning('Invalid CSP {0} value {1}'.format(k, v))
                    raise django.core.exceptions.MiddlewareNotUsed

            else:
                logger.warning('Invalid CSP type {0}'.format(k))
                raise django.core.exceptions.MiddlewareNotUsed

        return csp_string

    def __init__(self):
        # sanity checks
        has_csp_string = hasattr(django.conf.settings, 'CSP_STRING')
        has_csp_dict = hasattr(django.conf.settings, 'CSP_DICT')
        err_msg = 'Middleware requires either CSP_STRING or CSP_DICT setting'

        if not hasattr(django.conf.settings, 'CSP_MODE'):
            self._enforce = True
        else:
            mode = django.conf.settings.CSP_MODE
            if mode == 'enforce':
                self._enforce = True
            elif mode == 'report-only':
                self._enforce = False
            else:
                logger.warn('Invalid CSP_MODE {0}, only "enforce" or "report-only" is valid'.format(mode))
                raise django.core.exceptions.MiddlewareNotUsed

        if not (has_csp_string or has_csp_dict):
            logger.warning('{0}, none found'.format(err_msg))
            raise django.core.exceptions.MiddlewareNotUsed

        if has_csp_dict and has_csp_string:
            logger.warning('{0}, not both'.format(err_msg))
            raise django.core.exceptions.MiddlewareNotUsed

        # build or copy CSP as string
        if has_csp_string:
            self._csp_string = django.conf.settings.CSP_STRING

        if has_csp_dict:
            self._csp_string = self._csp_builder(django.conf.settings.CSP_DICT)

    def process_response(self, request, response):
        """
        And Content Security Policy policy to the response header. Use either
        enforcement or report-only headers in all currently used variants.
        """
        # choose headers based enforcement mode
        if self._enforce:
            header = 'Content-Security-Policy'
        else:
            header = 'Content-Security-Policy-Report-Only'

        # actually add appropriate headers
        response[header] = self._csp_string

        return response


class StrictTransportSecurityMiddleware:
    """
    Adds Strict-Transport-Security header to HTTP
    response that enforces SSL connections on compliant browsers. Two
    parameters can be set in settings file, otherwise reasonable
    defaults will be used:

      - ``STS_MAX_AGE``               time in seconds to preserve host's STS policy (default: 1 year)
      - ``STS_INCLUDE_SUBDOMAINS``    True if subdomains should be covered by the policy as well (default: True)
      - ``STS_PRELOAD``               add ``preload`` flag to the STS header  so that your website can be
                                      added to preloaded websites list

    Reference: 
    
    - `HTTP Strict Transport Security (HSTS) <https://datatracker.ietf.org/doc/rfc6797/>`_
    _ `Preloaded HSTS sites <http://www.chromium.org/sts>`_
    """

    def __init__(self):
        try:
            self.max_age = django.conf.settings.STS_MAX_AGE
        except AttributeError:
            self.max_age = 3600 * 24 * 365  # one year
        try:
            self.subdomains = django.conf.settings.STS_INCLUDE_SUBDOMAINS
        except AttributeError:
            self.subdomains = True
        try:
            self.preload = django.conf.settings.STS_PRELOAD
        except AttributeError:
            self.preload = True

        self.value = 'max-age={0}'.format(self.max_age)

        if self.subdomains:
            self.value += ' ; includeSubDomains'

        if self.preload:
            self.value += ' ; preload'

    def process_response(self, request, response):
        """
        Add Strict-Transport-Security header.
        """
        response['Strict-Transport-Security'] = self.value
        return response


class P3PPolicyMiddleware(BaseMiddleware):
    """
    Adds the HTTP header attribute specifying compact P3P policy
    defined in P3P_COMPACT_POLICY setting and location of full
    policy defined in P3P_POLICY_URL. If the latter is not defined,
    a default value is used (/w3c/p3p.xml). The policy file needs to
    be created by website owner.

    **Note:** P3P work stopped in 2002 and the only popular
    browser with **limited** P3P support is MSIE.

    Reference: 

    - `The Platform for Privacy Preferences 1.0 (P3P1.0) Specification - The Compact Policies <http://www.w3.org/TR/P3P/#compact_policies>`_
    """

    REQUIRED_SETTINGS = ("P3P_COMPACT_POLICY",)
    OPTIONAL_SETTINGS = ("P3P_POLICY_URL",)

    def load_setting(self, setting, value):
        if setting == 'P3P_COMPACT_POLICY':
            self.policy = value
        elif setting == 'P3P_POLICY_URL':
            self.policy_url = value if value else '/w3c/p3p.xml'

    def process_response(self, request, response):
        """
        And P3P policy to the response header.
        """
        response['P3P'] = 'policyref="{0}" CP="{1}"'.format(self.policy_url, self.policy)
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
            # We don't worry about microseconds.
            SECONDS_PER_DAY = 86400
            start_time_diff = now - start_time
            last_activity_diff = now - last_activity_time
            session_too_old = (start_time_diff.days * SECONDS_PER_DAY + start_time_diff.seconds >
                               self.SESSION_COOKIE_AGE)
            session_inactive = (last_activity_diff.days * SECONDS_PER_DAY + last_activity_diff.seconds >
                                self.SESSION_INACTIVITY_TIMEOUT)

            if session_too_old or session_inactive:
                logger.debug("Session %s is inactive." % request.session.session_key)
                logout(request)
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
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
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

