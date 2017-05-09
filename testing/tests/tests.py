# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import datetime
import json
import time  # We monkeypatch this.

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed
from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.http import HttpResponseForbidden, HttpRequest, HttpResponse
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from security.auth import min_length
from security.auth_throttling import (
    attempt_count, default_delay_function, delay_message, increment_counters,
    reset_counters, Middleware as AuthThrottlingMiddleware
)
from security.middleware import (
    BaseMiddleware, ContentSecurityPolicyMiddleware, DoNotTrackMiddleware,
    SessionExpiryPolicyMiddleware, MandatoryPasswordChangeMiddleware,
    XssProtectMiddleware, XFrameOptionsMiddleware, ReferrerPolicyMiddleware
)
from security.models import PasswordExpiry
from security.password_expiry import never_expire_password
from security.views import require_ajax, csp_report

from django.conf import settings


def login_user(func):
    """
    A decorator that will create a valid user in the database and
    then log that user in. We expect self to be a DjangoTestCase,
    or some object with a similar interface.
    """
    def wrapper(self, *args, **kwargs):
        username_local = 'a2fcf54f63993b7'
        password_local = 'd8327deb882cf90'
        email_local = 'testuser@example.com'
        user = User.objects.create_user(
            username=username_local,
            email=email_local,
            password=password_local,
        )
        user.is_superuser = True
        user.save()
        PasswordExpiry.objects.create(user=user).never_expire()
        self.client.login(username=username_local, password=password_local)
        func(self, *args, **kwargs)
        self.client.logout()
        user.delete()
    return wrapper


class CustomLoginURLMiddleware(object):
    """Used to test the custom url support in the login required middleware."""
    def process_request(self, request):
        request.login_url = '/custom-login/'


class BaseMiddlewareTestMiddleware(BaseMiddleware):
    REQUIRED_SETTINGS = ('R1', 'R2')
    OPTIONAL_SETTINGS = ('O1', 'O2')

    def load_setting(self, setting, value):
        if not hasattr(self, 'loaded_settings'):
            self.loaded_settings = {}
        self.loaded_settings[setting] = value

    def process_response(self, request, response):
        response.loaded_settings = self.loaded_settings
        return response

    def process_exception(self, request, exception):
        return self.process_response(request, HttpResponse())


class BaseMiddlewareTests(TestCase):
    def __init__(self, *args, **kwargs):
        super(BaseMiddlewareTests, self).__init__(*args, **kwargs)
        module_name = BaseMiddlewareTests.__module__
        self.MIDDLEWARE_NAME = module_name + '.BaseMiddlewareTestMiddleware'

    def test_settings_initially_loaded(self):
        expected_settings = {'R1': 1, 'R2': 2, 'O1': 3, 'O2': 4}
        with self.settings(
            MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), **expected_settings
        ):
            response = self.client.get('/home/')
            self.assertEqual(expected_settings, response.loaded_settings)

    def test_required_settings(self):
        with self.settings(MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,)):
            self.assertRaises(ImproperlyConfigured, self.client.get, '/home/')

    def test_optional_settings(self):
        with self.settings(
            MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), R1=True, R2=True
        ):
            response = self.client.get('/home/')
            self.assertEqual(None, response.loaded_settings['O1'])
            self.assertEqual(None, response.loaded_settings['O2'])

    def test_setting_change(self):
        with self.settings(
            MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), R1=123, R2=True
        ):
            response = self.client.get('/home/')
            self.assertEqual(123, response.loaded_settings['R1'])

            with override_settings(R1=456):
                response = self.client.get('/home/')
                self.assertEqual(456, response.loaded_settings['R1'])

            response = self.client.get('/home/')
            self.assertEqual(123, response.loaded_settings['R1'])

    def test_load_setting_abstract_method(self):
        base = BaseMiddleware()
        self.assertRaises(NotImplementedError, base.load_setting, None, None)


class LoginRequiredMiddlewareTests(TestCase):
    def setUp(self):
        self.login_url = reverse("django.contrib.auth.views.login")

    def test_aborts_if_auth_middleware_missing(self):
        middleware_classes = settings.MIDDLEWARE_CLASSES
        auth_mw = 'django.contrib.auth.middleware.AuthenticationMiddleware'
        middleware_classes = [
            m for m in middleware_classes if m != auth_mw
        ]
        with self.settings(MIDDLEWARE_CLASSES=middleware_classes):
            self.assertRaises(ImproperlyConfigured, self.client.get, '/home/')

    def test_redirects_unauthenticated_request(self):
        response = self.client.get('/home/')
        self.assertRedirects(response, self.login_url + "?next=/home/")

    def test_redirects_unauthenticated_ajax_request(self):
        response = self.client.get(
            '/home/',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            json.loads(response.content.decode('utf-8')),
            {"login_url": self.login_url},
        )

    def test_redirects_to_custom_login_url(self):
        middlware_classes = list(settings.MIDDLEWARE_CLASSES)
        custom_login_middleware = 'tests.tests.CustomLoginURLMiddleware'
        with self.settings(
            MIDDLEWARE_CLASSES=[custom_login_middleware] + middlware_classes,
        ):
            response = self.client.get('/home/')
            self.assertRedirects(response, '/custom-login/')
            response = self.client.get(
                '/home/',
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(
                json.loads(response.content.decode('utf-8')),
                {"login_url": '/custom-login/'},
            )

    def test_logs_out_inactive_users(self):
        user = User.objects.create_user(
            username="foo",
            password="foo",
            email="a@foo.org",
        )
        never_expire_password(user)
        self.client.login(username="foo", password="foo")
        resp = self.client.get('/home/')
        self.assertEqual(resp.status_code, 200)  # check we are logged in
        user.is_active = False
        user.save()
        resp = self.client.get('/home/')
        self.assertRedirects(resp, self.login_url + "?next=/home/")


class RequirePasswordChangeTests(TestCase):
    def test_require_password_change(self):
        """
        A brand-new user should have an already-expired password, and therefore
        be redirected to the password change form on any request.
        """
        user = User.objects.create_user(username="foo",
                                        password="foo",
                                        email="foo@foo.com")
        self.client.login(username="foo", password="foo")
        try:
            with self.settings(
                MANDATORY_PASSWORD_CHANGE={"URL_NAME": "change_password"}
            ):
                self.assertRedirects(
                    self.client.get("/home/"),
                    reverse("change_password"),
                )
                never_expire_password(user)
                self.assertEqual(self.client.get("/home/").status_code, 200)
        finally:
            self.client.logout()
            user.delete()

    def test_superuser_password_change(self):
        """
        A superuser can be forced to change their password via settings.
        """
        user = User.objects.create_superuser(username="foo",
                                             password="foo",
                                             email="foo@foo.com")
        self.client.login(username="foo", password="foo")
        with self.settings(MANDATORY_PASSWORD_CHANGE={
                           "URL_NAME": "change_password"}):
            self.assertEqual(self.client.get("/home/").status_code, 200)

        try:
            with self.settings(MANDATORY_PASSWORD_CHANGE={
                "URL_NAME": "change_password",
                "INCLUDE_SUPERUSERS": True
            }):
                self.assertRedirects(
                    self.client.get("/home/"),
                    reverse("change_password"),
                )
        finally:
            self.client.logout()
            user.delete()

    def test_dont_redirect_exempt_urls(self):
        user = User.objects.create_user(
            username="foo",
            password="foo",
            email="foo@foo.com"
        )
        self.client.login(username="foo", password="foo")

        try:
            with self.settings(MANDATORY_PASSWORD_CHANGE={
                "URL_NAME": "change_password",
                "EXEMPT_URLS": (r'^test1/$', r'^test2/$'),
                "EXEMPT_URL_NAMES": ("test3", "test4"),
            }):
                # Redirect pages in general
                self.assertRedirects(
                    self.client.get("/home/"),
                    reverse("change_password"),
                )

                # Don't redirect the password change page itself
                self.assertEqual(
                    self.client.get(reverse("change_password")).status_code,
                    200,
                )

                # Don't redirect exempt urls
                self.assertEqual(self.client.get("/test1/").status_code, 200)
                self.assertEqual(self.client.get("/test2/").status_code, 200)
                self.assertEqual(self.client.get("/test3/").status_code, 200)
                self.assertEqual(self.client.get("/test4/").status_code, 200)
        finally:
            self.client.logout()
            user.delete()

    def test_dont_choke_on_exempt_urls_that_dont_resolve(self):
        user = User.objects.create_user(username="foo",
                                        password="foo",
                                        email="foo@foo.com")
        self.client.login(username="foo", password="foo")

        try:
            with self.settings(MANDATORY_PASSWORD_CHANGE={
                "URL_NAME": "change_password",
                "EXEMPT_URL_NAMES": ("fake1", "fake2"),
            }):
                # Redirect pages in general
                self.assertRedirects(
                    self.client.get("/home/"),
                    reverse("change_password"),
                )
        finally:
            self.client.logout()
            user.delete()

    def test_raises_improperly_configured(self):
        change = MandatoryPasswordChangeMiddleware()
        self.assertRaises(
            ImproperlyConfigured,
            change.load_setting,
            'MANDATORY_PASSWORD_CHANGE',
            {'EXEMPT_URLS': []},
        )


class DecoratorTest(TestCase):
    """
    Testing the AJAXView decorator.
    """

    def require_ajax_test(self):
        @require_ajax
        def ajax_only_view(request):
            self.assertTrue(request.is_ajax())

        request = HttpRequest()
        response = ajax_only_view(request)
        self.assertTrue(isinstance(response, HttpResponseForbidden))
        request.META['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest'
        response = ajax_only_view(request)
        self.assertFalse(isinstance(response, HttpResponseForbidden))


class SessionExpiryTests(TestCase):

    def test_session_variables_are_set(self):
        """
        Verify the session cookie stores the start time and last active time.
        """
        self.client.get('/home/')
        now = timezone.now()

        start_time = self.client.session[
            SessionExpiryPolicyMiddleware.START_TIME_KEY
        ]
        last_activity = self.client.session[
            SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY
        ]

        self.assertTrue(now - start_time < datetime.timedelta(seconds=10))
        self.assertTrue(now - last_activity < datetime.timedelta(seconds=10))

    def session_expiry_test(self, key, expired):
        """
        Verify that expired sessions are cleared from the system. (And that we
        redirect to the login page.)
        """
        self.assertTrue(self.client.get('/home/').status_code, 200)
        session = self.client.session
        session[key] = expired
        session.save()
        response = self.client.get('/home/')
        self.assertRedirects(response,
                             'http://testserver/accounts/login/?next=/home/')

    @login_user
    def test_session_too_old(self):
        """
        Pretend we are 1 second passed the session age time and make sure out
        session is cleared.
        """
        delta = SessionExpiryPolicyMiddleware().SESSION_COOKIE_AGE + 1
        expired = timezone.now() - datetime.timedelta(seconds=delta)
        self.session_expiry_test(SessionExpiryPolicyMiddleware.START_TIME_KEY,
                                 expired)

    @login_user
    def test_session_inactive_too_long(self):
        """
        Pretend we are 1 second passed the session inactivity timeout and make
        sure the session is cleared.
        """
        delta = SessionExpiryPolicyMiddleware().SESSION_INACTIVITY_TIMEOUT + 1
        expired = timezone.now() - datetime.timedelta(seconds=delta)
        self.session_expiry_test(
            SessionExpiryPolicyMiddleware().LAST_ACTIVITY_KEY,
            expired,
        )


class ConfidentialCachingTests(TestCase):
    def setUp(self):
        self.old_config = getattr(settings, "NO_CONFIDENTIAL_CACHING", None)
        settings.NO_CONFIDENTIAL_CACHING = {
            "WHITELIST_ON": False,
            "BLACKLIST_ON": False,
            "WHITELIST_REGEXES": ["accounts/login/$"],
            "BLACKLIST_REGEXES": ["accounts/logout/$"]
        }
        self.header_values = {
            "Cache-Control": 'no-cache, no-store, max-age=0, must-revalidate',
            "Pragma": "no-cache",
            "Expires": '-1'
        }

    def tearDown(self):
        if self.old_config:
            settings.NO_CONFIDENTIAL_CACHING = self.old_config
        else:
            del(settings.NO_CONFIDENTIAL_CACHING)

    def test_whitelisting(self):
        settings.NO_CONFIDENTIAL_CACHING["WHITELIST_ON"] = True
        # Get Non Confidential Page
        response = self.client.get('/accounts/login/')
        for header, value in self.header_values.items():
            self.assertNotEqual(response.get(header, None), value)
        # Get Confidential Page
        response = self.client.get("/accounts/logout")
        for header, value in self.header_values.items():
            self.assertEqual(response.get(header, None), value)

    def test_blacklisting(self):
        settings.NO_CONFIDENTIAL_CACHING["BLACKLIST_ON"] = True
        # Get Non Confidential Page
        response = self.client.get('/accounts/login/')
        for header, value in self.header_values.items():
            self.assertNotEqual(response.get(header, None), value)
        # Get Confidential Page
        response = self.client.get("/accounts/logout/")
        for header, value in self.header_values.items():
            self.assertEqual(response.get(header, None), value)


class XFrameOptionsDenyTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertEqual(response['X-Frame-Options'], settings.X_FRAME_OPTIONS)

    def test_exclude_urls(self):
        """
        Verify that pages can be excluded from the X-Frame-Options header.
        """
        response = self.client.get('/home/')
        self.assertEqual(response['X-Frame-Options'], settings.X_FRAME_OPTIONS)
        response = self.client.get('/test1/')
        self.assertNotIn('X-Frame-Options', response)

    def test_improperly_configured(self):
        xframe = XFrameOptionsMiddleware()
        self.assertRaises(
            ImproperlyConfigured,
            xframe.load_setting,
            'X_FRAME_OPTIONS',
            'invalid',
        )

        self.assertRaises(
            ImproperlyConfigured,
            xframe.load_setting,
            'X_FRAME_OPTIONS_EXCLUDE_URLS',
            1,
        )

    def test_default_exclude_urls(self):
        with self.settings(X_FRAME_OPTIONS_EXCLUDE_URLS=None):
            # This URL is excluded in other tests, see settings.py
            response = self.client.get('/test1/')
            self.assertEqual(
                response['X-Frame-Options'],
                settings.X_FRAME_OPTIONS,
            )

    def test_default_xframe_option(self):
        with self.settings(X_FRAME_OPTIONS=None):
            response = self.client.get('/home/')
            self.assertEqual(
                response['X-Frame-Options'],
                'deny',
            )


class XXssProtectTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertNotEqual(response['X-XSS-Protection'], None)

    def test_default_setting(self):
        with self.settings(XSS_PROTECT=None):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['X-XSS-Protection'], '1')  # sanitize

    def test_option_off(self):
        with self.settings(XSS_PROTECT='off'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['X-XSS-Protection'], '0')  # off

    def test_improper_configuration_raises(self):
        xss = XssProtectMiddleware()
        self.assertRaises(
            ImproperlyConfigured,
            xss.load_setting,
            'XSS_PROTECT',
            'invalid',
        )


class ContentNoSniffTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertEqual(response['X-Content-Options'], 'nosniff')


class StrictTransportSecurityTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertNotEqual(response['Strict-Transport-Security'], None)


@override_settings(AUTHENTICATION_THROTTLING={
    "DELAY_FUNCTION": lambda x, _: (2 ** (x - 1) if x else 0, 0),
    "LOGIN_URLS_WITH_TEMPLATES": [
        ("accounts/login/", "registration/login.html")
    ]
})
class AuthenticationThrottlingTests(TestCase):
    def setUp(self):
        # monkey patch time
        self.old_time = time.time
        self.time = 0
        time.time = lambda: self.time
        self.user = User.objects.create_user(username="foo", password="foo",
                                             email="a@foo.org")

    def tearDown(self):
        time.time = self.old_time

    def attempt(self, password):
        return self.client.post("/accounts/login/",
                                {"username": "foo",
                                 "password": password},
                                follow=True)

    def reset(self):
        self.client.logout()
        cache.clear()

    def typo(self):
        self.assertTemplateUsed(self.attempt("bar"), "registration/login.html")

    def _succeed(self):
        self.assertTemplateNotUsed(self.attempt("foo"),
                                   "registration/login.html")
        self.reset()

    def _fail(self):
        self.assertTemplateUsed(self.attempt("foo"), "registration/login.html")
        self.reset()

    def set_time(self, t):
        self.time = t

    def test_delay_message(self):
        self.assertEqual("0 seconds", delay_message(0))
        self.assertEqual("1 second", delay_message(0.1))
        self.assertEqual("1 second", delay_message(1))
        self.assertEqual("1 minute", delay_message(31))
        self.assertEqual("1 minute", delay_message(60))
        self.assertEqual("1 minute", delay_message(61))
        self.assertEqual("2 minutes", delay_message(90))
        self.assertEqual("2 minutes", delay_message(120))

    def test_counters(self):
        cache.clear()
        increment_counters(username="foo", ip="127.0.0.1")
        increment_counters(username="foo")
        self.assertEqual(attempt_count("username", "foo"), 2)
        self.assertEqual(attempt_count("ip", "127.0.0.1"), 1)
        self.assertEqual(attempt_count("username", "baz"), 0)
        reset_counters(username="foo", ip="127.0.0.1")
        self.assertEqual(attempt_count("username", "foo"), 0)
        self.assertEqual(attempt_count("ip", "127.0.0.1"), 0)
        cache.clear()

    def test_default_delay_function(self):
        """
        The default function will only delay by looking at the username,
        and shouldn't care about ip.
        """
        delay = default_delay_function

        # 100 repeated IPs doesn't result in a delay.
        self.assertEqual(delay(0, 100), (0, 0))

        # first 3 incorrect attempts with a username will not be delayed.
        for i in range(3):
            self.assertEqual(delay(i, 0), (0, 0))

        # forth, fifth, sixth attempts are throttled
        for i in range(4, 7):
            self.assertEqual(delay(i, 0), (5 * 2 ** (i - 3), 0))

        # we max out at 24 hours
        self.assertEqual(delay(100, 0), (24 * 60 * 60, 0))

    def test_per_account_throttling(self):
        """
        Tests that multiple attempts on the same account are throttled
        according to settings.AUTHENTICATION_THROTTLING.
        """
        self.set_time(0)
        self._succeed()

        self.set_time(0)
        self.typo()
        self._fail()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self._succeed()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self.typo()
        self.set_time(2)
        self._fail()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self.typo()
        self.set_time(3)
        self._succeed()

    @override_settings(AUTHENTICATION_THROTTLING={
        "DELAY_FUNCTION": lambda x, y: (x, y),
        "LOGIN_URLS_WITH_TEMPLATES": [
            ("accounts/login/", None)
        ]
    })
    def test_too_many_requests_error_when_no_template_provided(self):
        """
        Verify we simply return a 429 error when there is no login template
        provided for us to report an error within.
        """
        cache.clear()

        # first bad attempt
        self.typo()

        # second attempt is throttled as per our delay function
        response = self.attempt("bar")
        self.assertEqual(
            response.status_code,
            429,
            "Expected TooManyRequests Error.",
        )

        cache.clear()

    def test_reset_button(self):
        """
        Tests that the account lockout reset button in the admin interface
        actually works.
        """
        self.set_time(0)
        self.typo()
        admin = User.objects.create_user(username="bar", password="bar",
                                         email="a@bar.org")
        admin.is_superuser = True
        admin.save()
        self.client.login(username="bar", password="bar")
        self.client.post(
            reverse("reset_username_throttle", args=[self.user.id]),
        )
        self.client.logout()
        self._succeed()

    @override_settings(AUTHENTICATION_THROTTLING={
        "DELAY_FUNCTION": lambda x, y: (x, y),
    })
    def test_improperly_configured_middleware(self):
        self.assertRaises(ImproperlyConfigured, AuthThrottlingMiddleware)

    def test_throttle_reset_404_on_unauthorized(self):
        resp = self.client.post(
            reverse("reset_username_throttle", args=[self.user.id]),
        )

        self.assertEqual(resp.status_code, 404)

    def test_throttle_reset_404_on_not_found(self):
        admin = User.objects.create_user(
            username="bar",
            password="bar",
            email="a@bar.org",
        )
        admin.is_superuser = True
        admin.save()
        self.client.login(username="bar", password="bar")
        resp = self.client.post(
            reverse("reset_username_throttle", args=[999]),
        )

        self.assertEqual(resp.status_code, 404)


class P3PPolicyTests(TestCase):

    def setUp(self):
        self.policy = "NN AD BLAH"
        settings.P3P_COMPACT_POLICY = self.policy

    def test_p3p_header(self):
        expected_header = 'policyref="/w3c/p3p.xml" CP="%s"' % self.policy
        response = self.client.get('/accounts/login/')
        self.assertEqual(response["P3P"], expected_header)


class AuthTests(TestCase):

    def test_min_length(self):
        self.assertRaises(ValidationError, min_length(6), "abcde")
        min_length(6)("abcdef")


class ContentSecurityPolicyTests(TestCase):

    class FakeHttpRequest(object):
        method = 'POST'
        body = """{
          "csp-report": {
            "document-uri": "http://example.org/page.html",
            "referrer": "http://evil.example.com/haxor.html",
            "blocked-uri": "http://evil.example.com/image.png",
            "violated-directive": "default-src 'self'",
            "original-policy": "%s"
          }
        }
        """ % settings.CSP_STRING
        META = {
            'CONTENT_TYPE': 'application/json',
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_USER_AGENT': 'FakeHTTPRequest'
        }

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertEqual(
            response['Content-Security-Policy'],
            settings.CSP_STRING,
        )

    def test_json(self):

        req = ContentSecurityPolicyTests.FakeHttpRequest()

        parsed = json.loads(req.body)

        self.assertNotEqual(len(parsed), 0)

    # http://www.w3.org/TR/CSP/#sample-violation-report
    def test_csp_view(self):

        req = ContentSecurityPolicyTests.FakeHttpRequest()

        # call the view
        resp = csp_report(req)

        self.assertEqual(resp.status_code, 204)

    def test_csp_gen_1(self):

        csp_dict = {
            'default-src': ['self', 'cdn.example.com'],
            'script-src': ['self', 'js.example.com'],
            'style-src': ['self', 'css.example.com'],
            'img-src': ['self', 'img.example.com'],
            'connect-src': ['self', ],
            'font-src': ['fonts.example.com', ],
            'object-src': ['self'],
            'media-src': ['media.example.com', ],
            'frame-src': ['*', ],
            'sandbox': ['', ],
            'reflected-xss': 'filter',
            'referrer': 'origin',
            'report-uri': 'http://example.com/csp-report',
        }

        expected = (
            "script-src 'self' js.example.com;"
            "default-src 'self' cdn.example.com;"
            "img-src 'self' img.example.com;"
            "connect-src 'self';"
            "reflected-xss filter;"
            "style-src 'self' css.example.com;"
            "report-uri http://example.com/csp-report;"
            "frame-src *;"
            "sandbox ;"
            "object-src 'self';"
            "media-src media.example.com;"
            "referrer origin;"
            "font-src fonts.example.com"
        )

        csp = ContentSecurityPolicyMiddleware()
        generated = csp._csp_builder(csp_dict)

        # We can't assume the iteration order on the csp_dict, so we split the
        # output, sort, and ensure we got all the results back, regardless of
        # the order.
        expected_list = sorted(x.strip() for x in expected.split(';'))
        generated_list = sorted(x.strip() for x in generated.split(';'))

        self.assertEqual(generated_list, expected_list)

    def test_csp_gen_2(self):
        csp_dict = {'default-src': ('none',), 'script-src': ['none']}
        expected = "default-src 'none'; script-src 'none'"

        csp = ContentSecurityPolicyMiddleware()
        generated = csp._csp_builder(csp_dict)

        expected_list = sorted(x.strip() for x in expected.split(';'))
        generated_list = sorted(x.strip() for x in generated.split(';'))

        self.assertEqual(generated_list, expected_list)

    def test_csp_gen_3(self):
        csp_dict = {
            'script-src': [
                'self',
                'www.google-analytics.com',
                'ajax.googleapis.com',
            ],
        }

        expected = (
            "script-src "
            "'self' www.google-analytics.com ajax.googleapis.com"
        )

        csp = ContentSecurityPolicyMiddleware()
        generated = csp._csp_builder(csp_dict)

        self.assertEqual(generated, expected)

    def test_csp_gen_err(self):
        # argument not passed as array, expect failure
        csp_dict = {'default-src': 'self'}

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_csp_gen_err2(self):
        csp_dict = {'invalid': 'self'}  # invalid directive

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_csp_gen_err3(self):
        csp_dict = {'sandbox': 'none'}  # not a list or tuple, expect failure

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_csp_gen_err4(self):
        # Not an allowed directive, expect failure
        csp_dict = {'sandbox': ('invalid', )}

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_csp_gen_err5(self):
        # Not an allowed directive, expect failure
        csp_dict = {'referrer': 'invalid'}

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_csp_gen_err6(self):
        # Not an allowed directive, expect failure
        csp_dict = {'reflected-xss': 'invalid'}

        csp = ContentSecurityPolicyMiddleware()
        self.assertRaises(MiddlewareNotUsed, csp._csp_builder, csp_dict)

    def test_enforced_by_default(self):
        with self.settings(CSP_MODE=None):
            response = self.client.get('/accounts/login/')
            self.assertIn('Content-Security-Policy', response)
            self.assertNotIn('Content-Security-Policy-Report-Only', response)

    def test_enforced_when_on(self):
        with self.settings(CSP_MODE='enforce'):
            response = self.client.get('/accounts/login/')
            self.assertIn('Content-Security-Policy', response)
            self.assertNotIn('Content-Security-Policy-Report-Only', response)

    def test_report_only_set(self):
        with self.settings(CSP_MODE='report-only'):
            response = self.client.get('/accounts/login/')
            self.assertNotIn('Content-Security-Policy', response)
            self.assertIn('Content-Security-Policy-Report-Only', response)

    def test_invalid_csp_mode(self):
        with self.settings(CSP_MODE='invalid'):
            self.assertRaises(
                MiddlewareNotUsed,
                ContentSecurityPolicyMiddleware,
            )

    def test_no_csp_options_set(self):
        with self.settings(CSP_DICT=None, CSP_STRING=None):
            self.assertRaises(
                MiddlewareNotUsed,
                ContentSecurityPolicyMiddleware,
            )

    def test_both_csp_options_set(self):
        with self.settings(CSP_DICT={'x': 'y'}, CSP_STRING='x y;'):
            self.assertRaises(
                MiddlewareNotUsed,
                ContentSecurityPolicyMiddleware,
            )

    def test_sets_from_csp_dict(self):
        with self.settings(
            CSP_DICT={'default-src': ('self',)},
            CSP_STRING=None,
        ):
            response = self.client.get('/accounts/login/')
            self.assertEqual(
                response['Content-Security-Policy'],
                "default-src 'self'",
            )


class DoNotTrackTests(TestCase):

    def setUp(self):
        self.dnt = DoNotTrackMiddleware()
        self.request = HttpRequest()
        self.response = HttpResponse()

    def test_set_DNT_on(self):
        self.request.META['HTTP_DNT'] = '1'
        self.dnt.process_request(self.request)
        self.assertTrue(self.request.dnt)

    def test_set_DNT_off(self):
        self.request.META['HTTP_DNT'] = 'off'
        self.dnt.process_request(self.request)
        self.assertFalse(self.request.dnt)

    def test_default_DNT(self):
        self.dnt.process_request(self.request)
        self.assertFalse(self.request.dnt)

    def test_DNT_echo_on(self):
        self.request.META['HTTP_DNT'] = '1'
        self.dnt.process_response(self.request, self.response)
        self.assertIn('DNT', self.response)
        self.assertEqual(self.response['DNT'], '1')

    def test_DNT_echo_off(self):
        self.request.META['HTTP_DNT'] = 'off'
        self.dnt.process_response(self.request, self.response)
        self.assertEqual(self.response['DNT'], 'off')

    def test_DNT_echo_default(self):
        self.dnt.process_response(self.request, self.response)
        self.assertNotIn('DNT', self.response)

class ReferrerPolicyTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Referrer-Policy Header is set.
        """
        response = self.client.get('/accounts/login/')
        self.assertNotEqual(response['Referrer-Policy'], None)

    def test_default_setting(self):
        with self.settings(REFERRER_POLICY=None):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'same-origin')

    def test_no_referrer_setting(self):
        with self.settings(REFERRER_POLICY='no-referrer'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'no-referrer')

    def test_no_referrer_when_downgrade_setting(self):
        with self.settings(REFERRER_POLICY='no-referrer-when-downgrade'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'no-referrer-when-downgrade')

    def test_origin_setting(self):
        with self.settings(REFERRER_POLICY='origin'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'origin')

    def test_origin_when_cross_origin_setting(self):
        with self.settings(REFERRER_POLICY='origin-when-cross-origin'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'origin-when-cross-origin')

    def test_same_origin_setting(self):
        with self.settings(REFERRER_POLICY='same-origin'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'same-origin')

    def test_strict_origin_setting(self):
        with self.settings(REFERRER_POLICY='strict-origin'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'strict-origin')

    def test_strict_origin_when_cross_origin_setting(self):
        with self.settings(REFERRER_POLICY='strict-origin-when-cross-origin'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')

    def test_unsafe_url_setting(self):
        with self.settings(REFERRER_POLICY='unsafe-url'):
            response = self.client.get('/accounts/login/')
            self.assertEqual(response['Referrer-Policy'], 'unsafe-url')

    def test_off_setting(self):
        with self.settings(REFERRER_POLICY='off'):
            response = self.client.get('/accounts/login/')
            self.assertEqual('Referrer-Policy' in response, False)

    def test_improper_configuration_raises(self):
        referer_policy_middleware = ReferrerPolicyMiddleware()
        self.assertRaises(
            ImproperlyConfigured,
            referer_policy_middleware.load_setting,
            'REFERRER_POLICY',
            'invalid',
        )
