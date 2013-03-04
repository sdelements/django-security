# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import datetime
import time # We monkeypatch this.

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.http import HttpResponseForbidden, HttpRequest, HttpResponse
from django.conf.urls.defaults import *
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import simplejson as json
from django.utils import timezone

from security.auth import min_length
from security.auth_throttling import delay_message, increment_counters, attempt_count, reset_counters
from security.middleware import MandatoryPasswordChangeMiddleware, BaseMiddleware
from security.middleware import SessionExpiryPolicyMiddleware
from security.models import PasswordExpiry
from security.password_expiry import never_expire_password
from security.views import require_ajax

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
        user = User.objects.create_user(username=username_local,
                email=email_local, password=password_local)
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
    REQUIRED_SETTINGS =('R1', 'R2')
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
    MIDDLEWARE_NAME = __module__ + '.BaseMiddlewareTestMiddleware'

    def test_settings_initially_loaded(self):
        expected_settings = {'R1': 1, 'R2': 2, 'O1': 3, 'O2': 4}
        with self.settings(MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), **expected_settings):
            response = self.client.get('/home/')
            self.assertEqual(expected_settings, response.loaded_settings)

    def test_required_settings(self):
        with self.settings(MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,)):
            self.assertRaises(ImproperlyConfigured, self.client.get, '/home/')

    def test_optional_settings(self):
        with self.settings(MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), R1=True, R2=True):
            response = self.client.get('/home/')
            self.assertEqual(None, response.loaded_settings['O1'])
            self.assertEqual(None, response.loaded_settings['O2'])

    def test_setting_change(self):
        with self.settings(MIDDLEWARE_CLASSES=(self.MIDDLEWARE_NAME,), R1=123, R2=True):
            response = self.client.get('/home/')
            self.assertEqual(123, response.loaded_settings['R1'])

            with override_settings(R1=456):
                response = self.client.get('/home/')
                self.assertEqual(456, response.loaded_settings['R1'])

            response = self.client.get('/home/')
            self.assertEqual(123, response.loaded_settings['R1'])

class LoginRequiredMiddlewareTests(TestCase):
    def setUp(self):
        self.login_url = reverse("django.contrib.auth.views.login")

    def test_aborts_if_auth_middlware_missing(self):
        middlware_classes = settings.MIDDLEWARE_CLASSES
        auth_middleware = 'django.contrib.auth.middleware.AuthenticationMiddleware'
        middlware_classes = [m for m in middlware_classes if m != auth_middleware]
        with self.settings(MIDDLEWARE_CLASSES=middlware_classes):
            self.assertRaises(ImproperlyConfigured, self.client.get, '/home/')

    def test_redirects_unauthenticated_request(self):
        response = self.client.get('/home/')
        self.assertRedirects(response, self.login_url + "?next=/home/")

    def test_redirects_unauthenticated_ajax_request(self):
        response = self.client.get('/home/',
                                   HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content),
                         {"login_url": self.login_url})

    def test_redirects_to_custom_login_url(self):
        middlware_classes = list(settings.MIDDLEWARE_CLASSES)
        custom_login_middleware = 'tests.tests.CustomLoginURLMiddleware'
        with self.settings(MIDDLEWARE_CLASSES=[custom_login_middleware] +
                                              middlware_classes):
            response = self.client.get('/home/')
            self.assertRedirects(response, '/custom-login/')
            response = self.client.get('/home/',
                                       HTTP_X_REQUESTED_WITH='XMLHttpRequest')
            self.assertEqual(response.status_code, 401)
            self.assertEqual(json.loads(response.content),
                             {"login_url": '/custom-login/'})


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
            with self.settings(MANDATORY_PASSWORD_CHANGE={"URL_NAME": "change_password"}):
                self.assertRedirects(self.client.get("/home/"), reverse("change_password"))
                never_expire_password(user)
                self.assertEqual(self.client.get("/home/").status_code, 200)
        finally:
            self.client.logout()
            user.delete()


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
        start_time = self.client.session[SessionExpiryPolicyMiddleware.START_TIME_KEY]
        last_activity = self.client.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY]
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
        Pretend we are 1 second passed the session age time and make sure out session
        is cleared.
        """
        delta = SessionExpiryPolicyMiddleware().SESSION_COOKIE_AGE + 1
        expired = timezone.now() - datetime.timedelta(seconds=delta)
        self.session_expiry_test(SessionExpiryPolicyMiddleware.START_TIME_KEY,
                                 expired)

    @login_user
    def test_session_inactive_too_long(self):
        """
        Pretend we are 1 second passed the session inactivity timeout and make sure
        the session is cleared.
        """
        delta = SessionExpiryPolicyMiddleware().SESSION_INACTIVITY_TIMEOUT + 1
        expired = timezone.now() - datetime.timedelta(seconds=delta)
        self.session_expiry_test(SessionExpiryPolicyMiddleware()
                                   .LAST_ACTIVITY_KEY,
                                 expired)

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
        self.assertEqual(response['X-FRAME-OPTIONS'], 'DENY')


class AuthenticationThrottlingTests(TestCase):
    def setUp(self):
        self.old_time = time.time
        self.old_config = getattr(settings, "AUTHENTICATION_THROTTLING", None)
        self.time = 0
        time.time = lambda: self.time
        settings.AUTHENTICATION_THROTTLING = {"DELAY_FUNCTION":
                                                lambda x, _: (2 ** (x - 1)
                                                                if x
                                                                else 0,
                                                              0),
                                              "LOGIN_URLS_WITH_TEMPLATES":
                                                [("accounts/login/",
                                                  "registration/login.html")]}
        self.user = User.objects.create_user(username="foo", password="foo",
                                             email="a@foo.org")

    def tearDown(self):
        time.time = self.old_time
        if self.old_config:
            settings.AUTHENTICATION_THROTTLING = self.old_config
        else:
            del(settings.AUTHENTICATION_THROTTLING)
        self.user.delete()

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
        self.assertEqual("1 minute", delay_message(30))
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
        self.client.post(reverse("reset_username_throttle", args=[self.user.id]))
        self.client.logout()
        self._succeed()

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

