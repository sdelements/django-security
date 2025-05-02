import cProfile
import importlib
import json
import logging
import pstats
from urllib.parse import quote_plus
import warnings
from io import StringIO
from re import compile

import dateutil.parser
import django.conf
import django.views.static
import sqlparse
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed
from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect
from django.test.signals import setting_changed
from django.urls import resolve, reverse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from ua_parser import user_agent_parser

logger = logging.getLogger(__name__)
profiling_logger = logging.getLogger("profiling")

DJANGO_CLICKJACKING_MIDDLEWARE_URL = (
    "https://docs.djangoproject.com/en/4.2/ref/clickjacking/"
)


class CustomLogoutMixin(object):
    """
    If the CUSTOM_LOGOUT_MODULE is set in Django config, import
    and use that when performing a logout.
    """

    class Messages(object):
        NOT_A_MODULE_PATH = (
            "Invalid CUSTOM_LOGOUT_MODULE setting '{0}'. "
            "Expected module path to a function"
        )
        FAILED_TO_LOAD = (
            "Invalid CUSTOM_LOGOUT_MODULE setting. " "Failed to load module '{0}': {1}"
        )
        MISSING_FUNCTION = (
            "Invalid CUSTOM_LOGOUT_MODULE setting. "
            "Could not find function '{0}' in module '{1}'"
        )

    def perform_logout(self, request):
        if not getattr(self, "CUSTOM_LOGOUT_MODULE", None):
            logout(request)
            return

        try:
            module_path, func_name = self.CUSTOM_LOGOUT_MODULE.rsplit(".", 1)
        except ValueError:
            err = self.Messages.NOT_A_MODULE_PATH
            raise Exception(err.format(self.CUSTOM_LOGOUT_MODULE))

        if not module_path or not func_name:
            err = self.Messages.NOT_A_MODULE_PATH
            raise Exception(err.format(self.CUSTOM_LOGOUT_MODULE))

        try:
            module = importlib.import_module(module_path)
        except Exception as e:
            err = self.Messages.FAILED_TO_LOAD
            raise Exception(err.format(module_path, e))

        try:
            func = getattr(module, func_name)
        except AttributeError:
            err = self.Messages.MISSING_FUNCTION
            raise Exception(err.format(func_name, module_path))

        return func(request)


class BaseMiddleware(MiddlewareMixin):
    """
    Abstract class containing some functionality common to all middleware that
    require configuration.
    """

    REQUIRED_SETTINGS = ()
    OPTIONAL_SETTINGS = ()

    def load_setting(self, setting, value):
        """
        Called initially for each of the keys in REQUIRED_SETTINGS and
        OPTIONAL_SETTINGS, and again whenever any of these settings change
        (from the setting_changed signal). Passed the setting key and the new
        value, which may be None for the keys in OPTIONAL_SETTINGS. If no
        setting keys are defined then this method is never called.
        """
        raise NotImplementedError()

    def _on_setting_changed(self, sender, setting, value, **kwargs):
        required = setting in self.REQUIRED_SETTINGS
        optional = setting in self.OPTIONAL_SETTINGS
        if required or optional:
            self.load_setting(setting, value)

    def __init__(self, get_response=None):
        self.get_response = get_response

        if not self.REQUIRED_SETTINGS and not self.OPTIONAL_SETTINGS:
            return

        for key in self.REQUIRED_SETTINGS:
            if hasattr(django.conf.settings, key):
                self.load_setting(key, getattr(django.conf.settings, key))
            else:
                raise ImproperlyConfigured(
                    self.__class__.__name__ + " requires setting " + key
                )

        for key in self.OPTIONAL_SETTINGS:
            self.load_setting(key, getattr(django.conf.settings, key, None))

        setting_changed.connect(self._on_setting_changed)


class DoNotTrackMiddleware(MiddlewareMixin):
    """
    When this middleware is installed Django views can access a new
    ``request.dnt`` parameter to check client's preference on user tracking as
    expressed by their browser configuration settings.

    The parameter can take True, False or None values based on the presence of
    the ``Do Not Track`` HTTP header in client's request, which in turn depends
    on browser's configuration. The header indicates client's general
    preference to opt-out from behavioral profiling and third-party tracking.

    The parameter does **not** change behaviour of Django in any way as its
    sole purpose is to pass the user's preference to application. It's then up
    to the owner to implement a particular policy based on this information.
    Compliant website should adapt its behaviour depending on one of user's
    preferences:

    - Explicit opt-out (``request.dnt`` is ``True``): Disable third party
      tracking for this request and delete all previously stored tracking data.
    - Explicit opt-in (``request.dnt`` is ``False``): Website may track user.
    - Header not present (``request.dnt`` is ``None``): Website may track user,
      but should not draw any definite conclusions on user's preferences as the
      user has not expressed it.

    For example, if ``request.dnt`` is `` True`` the website might respond by
    disabling template parts responsible for personalized statistics, targeted
    advertisements or switching to DNT aware ones.

    Examples:

    - `Do Not Track (DNT) tutorial for Django <http://ipsec.pl/node/1101>`_
    - `Do Not Track - Web Application Templates
      <http://donottrack.us/application>`_
    - `Opt-out of tailoring Twitter <https://dev.twitter.com/docs/tweet-
      button#optout>`_

    References:

    - `Web Tracking Protection <http://www.w3.org/Submission/web-tracking-
      protection/>`_
    - `Do Not Track: A Universal Third-Party Web Tracking Opt Out
      <http://tools.ietf.org/html/draft-mayer-do-not-track-00>`_
    """

    def process_request(self, request):
        """
        Read DNT header from browser request and create request attribute
        """
        request.dnt = None
        if "HTTP_DNT" in request.META:
            request.dnt = request.META["HTTP_DNT"] == "1"
            # returns None in normal conditions

    def process_response(self, request, response):
        """
        Echo DNT header in response per section 8.4 of draft-mayer-do-not-
        track-00
        """
        if "HTTP_DNT" in request.META:
            response["DNT"] = request.META["HTTP_DNT"]
        return response


class ClearSiteDataMiddleware(BaseMiddleware):
    """
    Sends Clear-Site-Data HTTP response header on requests that match
    CLEAR_SITE_DATA_URL_WHITELIST.

    Clears browsing data (cookies, storage, cache) associated with the
    requesting website. Allows web developers to have more control over the
    data stored locally by a browser for their origins.

    Reference:

    - Clear-Site-Data: "cache", "cookies", "storage", "executionContexts", "*"
      <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data>`_
    """

    REQUIRED_SETTINGS = ("CLEAR_SITE_DATA_URL_WHITELIST",)
    OPTIONAL_SETTINGS = "CLEAR_SITE_DATA_DIRECTIVES"

    DEFAULT_DIRECTIVES = ["cookies", "storage"]
    ALLOWED_DIRECTIVES = ("cache", "cookies", "storage", "executionContexts", "*")

    def load_setting(self, setting, value):
        if setting == "CLEAR_SITE_DATA_URL_WHITELIST":
            self.clear_site_urls = value

        directives = getattr(
            django.conf.settings, "CLEAR_SITE_DATA_DIRECTIVES", self.DEFAULT_DIRECTIVES
        )

        directives = [
            directive.strip()
            for directive in directives
            if directive.strip() in self.ALLOWED_DIRECTIVES
        ]

        self.clear_site_directives = ", ".join(
            '"{0}"'.format(directive) for directive in directives
        )

    def process_response(self, request, response):
        """
        Add ``Clear-Site-Data`` response header if request in
        CLEAR_SITE_DATA_URLS.
        """

        if request.path in self.clear_site_urls:
            response["Clear-Site-Data"] = self.clear_site_directives

        return response


class MandatoryPasswordChangeMiddleware(BaseMiddleware):
    """
    Redirects any request from an authenticated user to the password change
    form if that user's password has expired. Must be placed after
    ``AuthenticationMiddleware`` in the middleware list.

    Configured by dictionary ``MANDATORY_PASSWORD_CHANGE`` with the following
    keys:

        ``URL_NAME``            name of of the password change view

        ``EXEMPT_URL_NAMES``    list of URLs that do not trigger password
        change request

        ``INCLUDE_SUPERUSERS``  also check superusers for password change,
        default False
    """

    OPTIONAL_SETTINGS = ("MANDATORY_PASSWORD_CHANGE",)

    def load_setting(self, setting, value):
        if value and "URL_NAME" not in value:
            raise ImproperlyConfigured(
                self.__class__.__name__ + " requires the URL_NAME setting"
            )

        self.settings = value
        self.exempt_urls = [
            compile(url) for url in self.settings.get("EXEMPT_URLS", ())
        ]

    def process_view(self, request, view, *args, **kwargs):
        if not self.settings:
            return

        if not request.user.is_authenticated:
            return

        if view == django.views.static.serve:
            return

        # Check for an exempt URL before trying to resolve URL_NAME,
        # because the reason the URL is exempt may be because a special URL
        # config is in use (i.e. during a test) that doesn't have URL_NAME.

        path = request.path_info.lstrip("/")

        if any(m.match(path) for m in self.exempt_urls):
            return

        url_name = resolve(request.path_info).url_name

        if url_name in self.settings.get("EXEMPT_URL_NAMES", ()):
            return

        password_change_url = reverse(self.settings["URL_NAME"])

        if request.path == password_change_url:
            return

        from .password_expiry import password_is_expired

        if password_is_expired(request.user):
            return HttpResponseRedirect(password_change_url)


class NoConfidentialCachingMiddleware(BaseMiddleware):
    """
    Adds No-Cache and No-Store headers to confidential pages. You can either
    whitelist non-confidential pages and treat all others as non-confidential,
    or specifically blacklist pages as confidential. The behaviour is
    configured in ``NO_CONFIDENTIAL_CACHING`` dictionary in settings file with
    the following keys:

        ``WHITELIST_ON``        all pages are confidential, except for pages
                                explicitly whitelisted in ``WHITELIST_REGEXES``

        ``WHITELIST_REGEXES``   list of regular expressions defining pages
                                exempt from the no caching policy

        ``BLACKLIST_ON``        only pages defined in ``BLACKLIST_REGEXES``
                                will have caching disabled

        ``BLACKLIST_REGEXES``   list of regular expressions defining
                                confidential pages for which caching should be
                                prohibited

    **Note:** Django's `cache_control
    <https://docs.djangoproject.com/en/dev/topics/cache/#controlling-cache-
    using-other-headers>`_ decorator allows more granular control of caching on
    individual view level.

    Reference:

    - `HTTP/1.1 Header definitions - What is Cacheable
      <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1>`_
    """

    OPTIONAL_SETTINGS = ("NO_CONFIDENTIAL_CACHING",)

    def load_setting(self, setting, value):
        value = value or {}
        self.whitelist = value.get("WHITELIST_ON", False)
        if self.whitelist:
            self.whitelist_url_regexes = [
                compile(x) for x in value["WHITELIST_REGEXES"]
            ]
        self.blacklist = value.get("BLACKLIST_ON", False)
        if self.blacklist:
            self.blacklist_url_regexes = [
                compile(x) for x in value["BLACKLIST_REGEXES"]
            ]

    def process_response(self, request, response):
        """
        Add the Cache control no-store to anything confidential. You can either
        whitelist non-confidential pages and treat all others as non-
        confidential, or specifically blacklist pages as confidential
        """
        path = request.path.lstrip("/")
        if self.whitelist:
            if not any(re.match(path) for re in self.whitelist_url_regexes):
                self._remove_response_caching(response)
                return response
        if self.blacklist:
            if any(re.match(path) for re in self.blacklist_url_regexes):
                self._remove_response_caching(response)
        return response

    def _remove_response_caching(self, response):
        """
        Overwrites specific headers to make the HTTP response confidential.
        """
        response["Cache-control"] = "no-cache, no-store, max-age=0, must-revalidate"
        response["Pragma"] = "no-cache"
        response["Expires"] = -1


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
    plugins and similar widgets so test these features after setting this flag.

    You can exclude certain URLs from this header by setting
    ``X_FRAME_OPTIONS_EXCLUDE_URLS`` to a list of URL regexes like so::

        X_FRAME_OPTIONS_EXCLUDE_URLS = (
            r'^/some/url/here$',        # Note the initial slash
            r'^/another/to/exclude$',
        )

    The header will be sent unless ``request.path`` matches any of the above
    list. For more granular control, use ContentSecurityPolicyMiddleware_.

    References:

      - `RFC 7034: HTTP Header Field X-Frame-Options
        <http://tools.ietf.org/html/rfc7034>`_
    """

    OPTIONAL_SETTINGS = ("X_FRAME_OPTIONS", "X_FRAME_OPTIONS_EXCLUDE_URLS")

    DEFAULT = "deny"

    def __init__(self, get_response=None):
        super().__init__(get_response)
        warnings.warn(
            (
                'An official middleware "{name}" is supported by Django. '
                "Refer to {url} to see if its approach fits the use case."
            ).format(
                name="XFrameOptionsMiddleware", url=DJANGO_CLICKJACKING_MIDDLEWARE_URL
            ),
            stacklevel=2,
        )

    def load_setting(self, setting, value):
        if setting == "X_FRAME_OPTIONS":
            if not value:
                self.option = XFrameOptionsMiddleware.DEFAULT
                return

            value = value.lower()
            options = ["sameorigin", "deny"]

            if value in options or value.startswith("allow-from:"):
                self.option = value
                return

            raise ImproperlyConfigured(
                self.__class__.__name__ + " invalid option for X_FRAME_OPTIONS"
            )

        elif setting == "X_FRAME_OPTIONS_EXCLUDE_URLS":
            if not value:
                self.exclude_urls = []
                return

            try:
                self.exclude_urls = [compile(url) for url in value]
            except TypeError:
                raise ImproperlyConfigured(
                    "{0} invalid option for X_FRAME_OPTIONS_EXCLUDE_URLS".format(
                        self.__class__.__name__
                    )
                )

    def process_response(self, request, response):
        """
        Add X-Frame-Options and Frame-Options to the response header.
        """
        for url in self.exclude_urls:
            if url.match(request.path):
                break
        else:
            response["X-Frame-Options"] = self.option

        return response


# preserve older django-security API
# new API uses "deny" as default to maintain compatibility
XFrameOptionsDenyMiddleware = XFrameOptionsMiddleware


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
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

        ``CSP_MODE='report-only'``    browser will not enforce policy, only
                                      report violations

    The policy itself is a dictionary of content type keys and values
    containing list of allowed locations. For example, ``img-src`` specifies
    locations of images allowed to be loaded by this page:

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

    You can also supply a raw policy string, which is more suitable for short
    policies:

        ``CSP_STRING="default-src 'self'; script-src *.google.com"``

    If both ``CSP_DICT`` and ``CSP_STRING`` are set the middleware will throw
    an exception.

    **Notes:**

    - The special locations ('self', 'none', 'unsafe-eval', 'unsafe-inline')
      come **without** the additional single quotes in `CSP_DICT` and they
      will be automatically quoted by the middleware in the HTTP header.
    - The ``CSP_STRING`` on the other hand should be a verbatim copy of the
      HTTP header contents. It's not going the be processed in any way.
    - This middleware only sets the standard HTTP header variants
      (``Content-Security-Policy``). The experimental ones (``X-WebKit-CSP``
      and ``Content-Security-Policy``) are now obsolete.
    - Enabling CSP has significant impact on browser behaviour - for example
      inline JavaScript is disabled. Read `Default Policy Restrictions
      <http://developer.chrome.com/extensions/contentSecurityPolicy.html>`_ to
      see how pages need to be adapted to work under CSP.
    - Browsers will log CSP violations in JavaScript console and to a remote
      server configured by ``report-uri`` option. This package provides a view
      (csp_report_) to collect these alerts in your application. They can be
      then viewed using Django admin interface. For more advanced analytics try
      `CspBuilder <https://cspbuilder.info/>`_.
    - The middleware partially supports CSP 1.1 draft syntax.

    .. _References:

    **References:**

    - `Content Security Policy Level 2 <http://www.w3.org/TR/CSP11/>`_,
    - `HTML5.1 - Sandboxing <http://www.w3.org/html/wg/drafts/html/master
      /single-page.html#sandboxing>`_
    """

    # these types accept CSP locations as arguments
    _CSP_LOC_TYPES = [
        "default-src",
        "connect-src",
        "child-src",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "media-src",
        "object-src",
        "script-src",
        "style-src",
        "plugin-types",
        "worker-src",
    ]

    # arguments to location types
    _CSP_LOCATIONS = ["self", "none", "unsafe-eval", "unsafe-inline"]

    # sandbox allowed arguments
    # http://www.w3.org/html/wg/drafts/html/master/single-page.html#sandboxing
    # https://www.w3.org/TR/CSP2/
    _CSP_SANDBOX_ARGS = [
        "",
        "allow-forms",
        "allow-pointer-lock",
        "allow-popups",
        "allow-same-origin",
        "allow-scripts",
        "allow-top-navigation",
    ]

    # reflected-xss allowed arguments
    # http://www.w3.org/TR/CSP11/#directive-reflected-xss
    _CSP_XSS_ARGS = ["allow", "block", "filter"]

    # referrer allowed arguments
    # http://www.w3.org/TR/CSP11/#directive-referrer
    _CSP_REF_ARGS = [
        "none",
        "none-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "unsafe-url",
    ]

    # operational variables
    _csp_string = None
    _csp_mode = None

    def _csp_loc_builder(self, key, value):
        if not isinstance(value, (list, tuple)):
            logger.warn("Arguments to %s must be given as list or tuple", key)
            raise django.core.exceptions.MiddlewareNotUsed

        csp_loc_string = "{0}".format(key)
        for loc in value:
            if loc in self._CSP_LOCATIONS:
                csp_loc_string += " '{0}'".format(loc)  # quoted
            elif loc == "*":
                csp_loc_string += " *"  # not quoted
            else:
                # XXX: check for valid hostname or URL
                csp_loc_string += " {0}".format(loc)  # not quoted

        return csp_loc_string

    def _csp_sandbox_builder(self, key, value):
        if not isinstance(value, (list, tuple)):
            logger.warn("Arguments to %s must be given as list or tuple", key)
            raise django.core.exceptions.MiddlewareNotUsed

        csp_sandbox_string = "{0}".format(key)
        for opt in value:
            if opt in self._CSP_SANDBOX_ARGS:
                csp_sandbox_string += " {0}".format(opt)
            else:
                logger.warn("Invalid CSP sandbox argument %s", opt)
                raise django.core.exceptions.MiddlewareNotUsed

        return csp_sandbox_string

    def _csp_report_uri_builder(self, key, value):
        # XXX: add valid URL check
        return "{0} {1}".format(key, value)

    def _csp_referrer_builder(self, key, value):
        if value not in self._CSP_REF_ARGS:
            logger.warning("Invalid CSP %s value %s", key, value)
            raise django.core.exceptions.MiddlewareNotUsed

        return "{0} {1}".format(key, value)

    def _csp_reflected_xss_builder(self, key, value):
        if value not in self._CSP_XSS_ARGS:
            logger.warning("Invalid CSP %s value %s", key, value)
            raise django.core.exceptions.MiddlewareNotUsed

        return "{0} {1}".format(key, value)

    def _csp_builder(self, csp_dict):
        csp_components = []

        for key, value in csp_dict.items():

            if key in self._CSP_LOC_TYPES:
                csp_components.append(self._csp_loc_builder(key, value))

            elif key == "sandbox":
                csp_components.append(self._csp_sandbox_builder(key, value))

            elif key == "report-uri":
                csp_components.append(self._csp_report_uri_builder(key, value))

            elif key == "referrer":
                csp_components.append(self._csp_referrer_builder(key, value))

            elif key == "reflected-xss":
                csp_components.append(
                    self._csp_reflected_xss_builder(key, value),
                )

            else:
                logger.warning("Invalid CSP type %s", key)
                raise django.core.exceptions.MiddlewareNotUsed

        return "; ".join(csp_components)

    def __init__(self, get_response=None):
        # sanity checks
        self.get_response = get_response

        conf_csp_mode = getattr(django.conf.settings, "CSP_MODE", None)
        self._csp_mode = conf_csp_mode or "enforce"
        csp_string = getattr(django.conf.settings, "CSP_STRING", None)
        csp_dict = getattr(django.conf.settings, "CSP_DICT", None)
        csp_report_string = getattr(django.conf.settings, "CSP_REPORT_STRING", None)
        csp_report_dict = getattr(django.conf.settings, "CSP_REPORT_DICT", None)

        set_csp_str = self._csp_mode in ["enforce", "enforce-and-report-only"]
        set_csp_report_str = self._csp_mode in [
            "report-only",
            "enforce-and-report-only",
        ]

        if not (set_csp_str or set_csp_report_str):
            logger.error(
                'Invalid CSP_MODE %s, "enforce", "report-only" '
                'or "enforce-and-report-only" allowed',
                self._csp_mode,
            )
            raise django.core.exceptions.MiddlewareNotUsed

        if set_csp_str:
            self._set_csp_str(csp_dict, csp_string)

        if set_csp_report_str:
            self._set_csp_report_str(csp_report_dict, csp_report_string)

    def _set_csp_str(self, csp_dict, csp_string):
        err_msg = "Middleware requires either CSP_STRING or CSP_DICT setting"
        if not (csp_dict or csp_string):
            logger.error("%s, none found", err_msg)
            raise django.core.exceptions.MiddlewareNotUsed

        self._csp_string = self._choose_csp_str(
            csp_dict, csp_string, err_msg + ", not both"
        )

    def _set_csp_report_str(self, csp_report_dict, csp_report_string):
        report_err_msg = (
            "Middleware requires either CSP_REPORT_STRING, "
            "CSP_REPORT_DICT setting, or neither. If neither, "
            "middleware requires CSP_STRING or CSP_DICT, "
            "but not both."
        )

        # Default to the regular CSP string if report string not configured
        if not (csp_report_dict or csp_report_string):
            self._csp_report_string = self._csp_string
        else:
            self._csp_report_string = self._choose_csp_str(
                csp_report_dict, csp_report_string, report_err_msg
            )

    def _choose_csp_str(self, csp_dict, csp_str, err_msg):
        """
        Choose the Content-Security-Policy string to return.

        Args:
            csp_dict: a dictionary of values for building a CSP string
            csp_str: the fallback CSP string if no dictionary is provided
            err_msg: the message to log if both a dict and string are provided

        Returns:
        The Content-Security-Policy string by either building it from a
        dictionary or using the provided string.
        Log an error message if both are provided.
        """
        if csp_dict and csp_str:
            logger.error("%s", err_msg)
            raise django.core.exceptions.MiddlewareNotUsed

        if csp_dict:
            return self._csp_builder(csp_dict)
        elif csp_str:
            return csp_str
        else:
            return ""

    def process_response(self, request, response):
        """
        Add Content Security Policy policy to the response header. Use either
        enforcement or report-only headers in all currently used variants.
        """
        # choose headers based enforcement mode
        is_ie = False
        if "HTTP_USER_AGENT" in request.META:
            parsed_ua = user_agent_parser.ParseUserAgent(
                request.META["HTTP_USER_AGENT"]
            )
            is_ie = parsed_ua["family"] == "IE"

        csp_header = "Content-Security-Policy"
        if is_ie:
            csp_header = "X-Content-Security-Policy"
        report_only_header = "Content-Security-Policy-Report-Only"

        # actually add appropriate headers
        if self._csp_mode == "enforce":
            response[csp_header] = self._csp_string
        elif self._csp_mode == "report-only":
            response[report_only_header] = self._csp_report_string
        elif self._csp_mode == "enforce-and-report-only":
            response[csp_header] = self._csp_string
            response[report_only_header] = self._csp_report_string

        return response


class SessionExpiryPolicyMiddleware(CustomLogoutMixin, BaseMiddleware):
    """
    The session expiry middleware will let you expire sessions on
    browser close, and on expiry times stored in the cookie itself.
    (Expiring a cookie on browser close means you don't set the expiry
    value of the cookie.) The middleware will read SESSION_COOKIE_AGE
    and SESSION_INACTIVITY_TIMEOUT from the settings.py file to determine
    how long to keep a session alive.

    We will purge a session that has expired. This middleware should be run
    before the LoginRequired middleware if you want to redirect the expired
    session to the login page (if required).

    Exemptions to this requirement can optionally be specified in settings via
    a list of regular expressions in SESSION_EXPIRY_EXEMPT_URLS (which you can
    copy from your urls.py).

    By default this middleware will call the builtin Django logout function to
    perform the logout. You can customize which logout function will be called
    by specifying it in your django settings using the CUSTOM_LOGOUT_MODULE
    variable. The value should be the module path to the function,
    e.g. 'django.contrib.auth.logout'.
    """

    OPTIONAL_SETTINGS = (
        "SESSION_COOKIE_AGE",
        "SESSION_INACTIVITY_TIMEOUT",
        "SESSION_EXPIRY_EXEMPT_URLS",
        "CUSTOM_LOGOUT_MODULE",
    )

    SECONDS_PER_DAY = 86400
    SECONDS_PER_30MINS = 1800

    # Session keys
    START_TIME_KEY = "starttime"
    LAST_ACTIVITY_KEY = "lastactivity"

    @classmethod
    def _get_datetime_in_session(cls, key, session):
        return dateutil.parser.parse(session[key])

    @classmethod
    def _set_datetime_in_session(cls, key, value, session):
        session[key] = str(value)

    @classmethod
    def get_start_time(cls, request):
        return cls._get_datetime_in_session(cls.START_TIME_KEY, request.session)

    @classmethod
    def set_start_time(cls, request, date):
        cls._set_datetime_in_session(cls.START_TIME_KEY, date, request.session)

    @classmethod
    def get_last_activity(cls, request):
        return cls._get_datetime_in_session(cls.LAST_ACTIVITY_KEY, request.session)

    @classmethod
    def set_last_activity(cls, request, date):
        cls._set_datetime_in_session(cls.LAST_ACTIVITY_KEY, date, request.session)

    def load_setting(self, setting, value):
        if setting == "SESSION_COOKIE_AGE":
            self.SESSION_COOKIE_AGE = value or self.SECONDS_PER_DAY
            logger.debug(
                "Max Session Cookie Age is %d seconds", self.SESSION_COOKIE_AGE
            )
        elif setting == "SESSION_INACTIVITY_TIMEOUT":
            # half an hour in seconds
            self.SESSION_INACTIVITY_TIMEOUT = value or self.SECONDS_PER_30MINS
            logger.debug(
                "Session Inactivity Timeout is %d seconds",
                self.SESSION_INACTIVITY_TIMEOUT,
            )
        elif setting == "SESSION_EXPIRY_EXEMPT_URLS":
            self.exempt_urls = [compile(expr) for expr in (value or ())]
        else:
            setattr(self, setting, value)

    def process_request(self, request):
        """
        Verify that the session should be considered active. We check
        the start time and the last activity time to determine if this
        is the case. We set the last activity time to now() if the session
        is still active.
        """
        if not hasattr(request, "user"):
            raise ImproperlyConfigured(
                "The Login Required middleware "
                "requires authentication middleware to be installed."
            )

        path = request.path_info.lstrip("/")

        if any(m.match(path) for m in self.exempt_urls):
            return

        if (
            self.START_TIME_KEY not in request.session
            or self.LAST_ACTIVITY_KEY not in request.session
            or timezone.is_naive(self.get_start_time(request))
            or timezone.is_naive(self.get_last_activity(request))
        ):
            response = self.process_new_session(request)
        else:
            response = self.process_existing_session(request)

        if response:
            return response

    def process_new_session(self, request):
        now = timezone.now()
        session = request.session

        logger.debug("New session %s started: %s", session.session_key, now)
        self.set_start_time(request, now)
        self.set_last_activity(request, now)

    def process_existing_session(self, request):
        now = timezone.now()
        session = request.session
        start_time = self.get_start_time(request)
        last_activity_time = self.get_last_activity(request)

        logger.debug("Session %s started: %s", session.session_key, start_time)
        logger.debug(
            "Session %s last active: %s", session.session_key, last_activity_time
        )

        session_age = self.get_diff_in_seconds(now, start_time)
        session_too_old = session_age > self.SESSION_COOKIE_AGE

        session_lastactive = self.get_diff_in_seconds(now, last_activity_time)
        session_inactive = session_lastactive > self.SESSION_INACTIVITY_TIMEOUT

        if session_too_old or session_inactive:
            logger.debug("Session %s is inactive.", session.session_key)
            response = None

            if request.user.is_authenticated:
                # Store the current path in the session
                # so we can redirect the user after the logout
                response = self.perform_logout(request)
            else:
                request.session.flush()

            return response

        logger.debug("Session %s is still active.", session.session_key)
        self.set_last_activity(request, now)

    def get_diff_in_seconds(self, now, time):
        diff = now - time
        age = diff.days * self.SECONDS_PER_DAY + diff.seconds
        return age


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


class LoginRequiredMiddleware(BaseMiddleware, CustomLogoutMixin):
    """
    Middleware that requires a user to be authenticated to view any page on
    the site that hasn't been white listed. (The middleware also ensures the
    user is 'active'. Disabled users will be logged out and redirected to
    the login page.

    Exemptions to this requirement can optionally be specified in settings via
    a list of regular expressions in LOGIN_EXEMPT_URLS (which you can copy from
    your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.

    By default this middleware will call the builtin Django logout function to
    perform the logout. You can customize which logout function will be called
    by specifying it in your django settings using the CUSTOM_LOGOUT_MODULE
    variable. The value should be the module path to the function,
    e.g. 'django.contrib.auth.logout'.
    """

    REQUIRED_SETTINGS = ("LOGIN_URL",)
    OPTIONAL_SETTINGS = ("LOGIN_EXEMPT_URLS", "CUSTOM_LOGOUT_MODULE")

    def load_setting(self, setting, value):
        if setting == "LOGIN_URL":
            self.login_url = value
        elif setting == "LOGIN_EXEMPT_URLS":
            self.exempt_urls = [compile(expr) for expr in (value or ())]
        else:
            setattr(self, setting, value)

    def assert_authentication_middleware_installed(self, request):
        if not hasattr(request, "user"):
            raise ImproperlyConfigured(
                "The Login Required middleware "
                "requires authentication middleware to be installed."
            )

    def process_request(self, request):
        self.assert_authentication_middleware_installed(request)

        if request.user.is_authenticated and not request.user.is_active:
            response = self.perform_logout(request)

            if response:
                return response

        if request.user.is_authenticated:
            return

        path = request.path_info.lstrip("/")

        if any(m.match(path) for m in self.exempt_urls):
            return

        if hasattr(request, "login_url"):
            login_url = request.login_url
            next_url = None
        else:
            login_url = self.login_url
            next_url = request.path
            if len(request.META["QUERY_STRING"]):
                next_url += quote_plus("?" + request.META["QUERY_STRING"])

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return HttpResponse(
                json.dumps({"login_url": login_url}),
                status=401,
                content_type="application/json",
            )

        if next_url:
            login_url = login_url + "?next=" + next_url

        return HttpResponseRedirect(login_url)


class ReferrerPolicyMiddleware(BaseMiddleware):
    """
    Sends Referrer-Policy HTTP header that controls when the browser will set
    the `Referer` header. Use REFERRER_POLICY option in settings file
    with the following values:
    - ``no-referrer``
    - ``no-referrer-when-downgrade``
    - ``origin``
    - ``origin-when-cross-origin``
    - ``same-origin`` (*default*)
    - ``strict-origin``
    - ``strict-origin-when-cross-origin``
    - ``unsafe-url``
    - ``off``

    Reference:
    - `Referrer-Policy from Mozilla Developer Network
    <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`
    """

    OPTIONAL_SETTINGS = ("REFERRER_POLICY",)

    OPTIONS = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
        "off",
    ]

    DEFAULT = "same-origin"

    def load_setting(self, setting, value):
        if not value:
            self.option = self.DEFAULT
            return

        value = value.lower()

        if value in self.OPTIONS:
            self.option = value
            return

        raise ImproperlyConfigured(
            self.__class__.__name__ + " invalid option for REFERRER_POLICY."
        )

    def process_response(self, request, response):
        """
        Add Referrer-Policy to the response header.
        """
        if self.option != "off":
            header = self.option
            response["Referrer-Policy"] = header
        return response


class ProfilingMiddleware(BaseMiddleware):
    """
    Adds the ability to profile requests via a header.

    Usage:
    Add the middleware to the MIDDLEWARE list. New boolean setting
    "ENABLE_PROFILING" will be required to be set in the settings file. When
    set to False, the middleware will deactivate itself. When set to True, the
    middleware will be active.

    When the middleware is active, it will log the data for any request that
    supplies the X-Profile header in the HTTP request. This data will be logged
    to the 'profiling' logger, so in order to see the results of this profiling
    the Django logging will need to configure handlers for the 'profiling'
    logger. Profiling will be configured at the DEBUG level.
    """

    REQUIRED_SETTINGS = ("ENABLE_PROFILING", "DEBUG")
    request_separator = f"\n{'=' * 80}\n"
    query_separator = f"\n{'*' * 80}\n"

    def __init__(self, get_response=None):
        super().__init__(get_response)
        if not self.enable_profiling:
            raise MiddlewareNotUsed()

    def load_setting(self, setting, value):
        setattr(self, setting.lower(), value)

    def format_queries_and_time_for_logs(self, queries):
        formatted_queries = []
        total_time = 0
        for query in queries:
            formatted_sql = sqlparse.format(
                query["sql"], reindent=True, keyword_case="upper"
            )

            formatted_queries.append("{}:\n{}".format(query["time"], formatted_sql))
            total_time += float(query["time"])

        log_messages = [
            f"\n{len(queries)} Queries\nTotal time for queries: {total_time}"
        ] + formatted_queries
        return self.query_separator.join(log_messages)

    def __call__(self, request):
        # Only profile requests that have a 'X-Profile' HTTP header
        if "HTTP_X_PROFILE" not in request.META:
            return self.get_response(request)

        out = StringIO()
        out.write(self.request_separator)

        # Add method & path info to differentiate requests
        out.write(f"{request.method} {request.path}\n\n")

        # We can only profile queries in debug mode
        if self.debug:
            num_previous_queries = len(connection.queries)

        # Begin collecting time profiling data
        profile = cProfile.Profile()
        profile.enable()

        # Continue down the middleware chain
        response = self.get_response(request)

        # Get the profile stats & pull out the top cumulative & total time
        # data
        profile_stats = pstats.Stats(profile, stream=out)
        profile_stats = profile_stats.sort_stats("cumulative")
        profile_stats.print_stats(128)
        profile_stats.sort_stats("tottime")
        profile_stats.print_stats(15)

        # Print out our queries
        if self.debug:
            queries = connection.queries[num_previous_queries:]
            out.write(self.format_queries_and_time_for_logs(queries))

        out.write(self.request_separator)
        profiling_logger.debug(out.getvalue())

        return response
