# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from datetime import datetime, timedelta
import time # We monkeypatch this.

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.http import HttpResponseForbidden, HttpRequest
from django.conf.urls.defaults import *
from django.test import TestCase

from security.auth import min_length
from security.auth_throttling import *
from security.middleware import SessionExpiryPolicyMiddleware
from security.models import PasswordExpiry
from security.password_expiry import never_expire_password
from security.views import require_ajax

import settings


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
            self.assertTemplateUsed(self.client.get("/", follow=True),
                                    "registration/password_change_form.html")
            never_expire_password(user)
            self.assertTemplateNotUsed(self.client.get("/", follow=True),
                                       "registration/password_change_form.html")
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
        self.client.get('/')
        now = datetime.now()
        start_time = self.client.session[SessionExpiryPolicyMiddleware.START_TIME_KEY]
        last_activity = self.client.session[SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY]
        self.assertTrue((now-start_time).seconds < 10)
        self.assertTrue((now-last_activity).seconds < 10)

    def session_expiry_test(self, key, expired):
        """
        Verify that expired sessions are cleared from the system. (And that we
        redirect to the login page.)
        """
        response = self.client.get('/')
        self.assertRedirects(response, 'http://testserver/project/')
        session = self.client.session
        session[key] = expired
        session.save()
        response = self.client.get('/')
        self.assertRedirects(response, 'http://testserver/accounts/login/?next=/')

    @login_user
    def test_session_too_old(self):
        """
        Pretend we are 1 second passed the session age time and make sure out session
        is cleared.
        """
        expired = datetime.now() - timedelta(
                seconds=SessionExpiryPolicyMiddleware.SESSION_COOKIE_AGE + 1)
        self.session_expiry_test(SessionExpiryPolicyMiddleware.START_TIME_KEY, expired)

    @login_user
    def test_session_inactive_too_long(self):
        """
        Pretend we are 1 second passed the session inactivity timeout and make sure
        the session is cleared.
        """
        expired = datetime.now() - timedelta(
                seconds=SessionExpiryPolicyMiddleware.SESSION_INACTIVITY_TIMEOUT + 1)
        self.session_expiry_test(SessionExpiryPolicyMiddleware.LAST_ACTIVITY_KEY, expired)


class XFrameOptionsDenyTests(TestCase):

    def test_option_set(self):
        """
        Verify the HTTP Response Header is set.
        """
        response = self.client.get('/')
        self.assertEqual(response['X-FRAME-OPTIONS'], 'DENY')


class AuthenticationThrottlingTests(TestCase):
    def setUp(self):
        self.old_time = time.time
        self.old_config = settings.AUTHENTICATION_THROTTLING
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
        settings.AUTHENTICATION_THROTTLING = self.old_config
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
    def succeed(self):
        self.assertTemplateNotUsed(self.attempt("foo"),
                                   "registration/login.html")
        self.reset()
    def fail(self):
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
        self.succeed()

        self.set_time(0)
        self.typo()
        self.fail()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self.succeed()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self.typo()
        self.set_time(2)
        self.fail()

        self.set_time(0)
        self.typo()
        self.set_time(1)
        self.typo()
        self.set_time(3)
        self.succeed()

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
        self.succeed()


class AuthTests(TestCase):

    def test_min_length(self):
        self.assertRaises(ValidationError, min_length(6), "abcde")
        min_length(6)("abcdef")

