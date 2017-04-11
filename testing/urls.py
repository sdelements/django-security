# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

import django
from django.conf.urls import url
from django.http import HttpResponse

if django.VERSION >= (1, 10):
    from django.contrib.auth.views import login, password_change
    from security.auth_throttling.views import reset_username_throttle
    from security.views import csp_report
    urlpatterns = [
        url("^accounts/login/$", login),
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
else:
    from django.conf.urls import patterns
    urlpatterns = patterns(
        "",
        ("^accounts/login/$", "django.contrib.auth.views.login"),
        ("^change_password/$", "django.contrib.auth.views.password_change",
         {"post_change_redirect": "/home/"}, "change_password"),
        (r"^admin/reset-account-throttling/(?P<user_id>-?[0-9]+)/",
         "security.auth_throttling.views.reset_username_throttle",
         {"redirect_url": "/admin"}, "reset_username_throttle"),
        ("^home/$", lambda request: HttpResponse()),
        ("^custom-login/$", lambda request: HttpResponse()),
        ("^test1/$", lambda request: HttpResponse(), {}, "test1"),
        ("^test2/$", lambda request: HttpResponse(), {}, "test2"),
        ("^test3/$", lambda request: HttpResponse(), {}, "test3"),
        ("^test4/$", lambda request: HttpResponse(), {}, "test4"),
        ("^csp-report/$", "security.views.csp_report"),
    )
