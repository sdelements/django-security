# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

from django.urls import path, re_path
from django.http import HttpResponse
from django.contrib.auth.views import LoginView, PasswordChangeView

from security.auth_throttling.views import reset_username_throttle
from security.views import csp_report

urlpatterns = [
    path("accounts/login/", LoginView.as_view(), {}, "login"),
    path("change_password/", PasswordChangeView.as_view(),
        {"post_change_redirect": "/home/"}, "change_password"),
    re_path(r"^admin/reset-account-throttling/(?P<user_id>-?[0-9]+)/",
        reset_username_throttle,
        {"redirect_url": "/admin"}, "reset_username_throttle"),
    path("home/", lambda request: HttpResponse()),
    path("custom-login/", lambda request: HttpResponse()),
    path("test1/", lambda request: HttpResponse(), {}, "test1"),
    path("test2/", lambda request: HttpResponse(), {}, "test2"),
    path("test3/", lambda request: HttpResponse(), {}, "test3"),
    path("test4/", lambda request: HttpResponse(), {}, "test4"),
    path("csp-report/", csp_report),
]
