# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

from django.conf.urls import url
from django.http import HttpResponse
from django.contrib.auth.views import LoginView, password_change

from security.auth_throttling.views import reset_username_throttle
from security.views import csp_report

urlpatterns = [
    url("^accounts/login/$", lambda request: LoginView.as_view()(request), name='login'),
    url("^change_password/$", password_change,
        {"post_change_redirect": "/home/"}, "change_password"),
    url(r"^admin/reset-account-throttling/(?P<user_id>-?[0-9]+)/",
        reset_username_throttle,
        {"redirect_url": "/admin"}, "reset_username_throttle"),
    url("^home/$", lambda request: HttpResponse()),
    url("^custom-login/$", lambda request: HttpResponse()),
    url("^test1/$", lambda request: HttpResponse(), {}, "test1"),
    url("^test2/$", lambda request: HttpResponse(), {}, "test2"),
    url("^test3/$", lambda request: HttpResponse(), {}, "test3"),
    url("^test4/$", lambda request: HttpResponse(), {}, "test4"),
    url("^csp-report/$", csp_report),
]
