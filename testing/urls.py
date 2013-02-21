# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

from django.conf.urls.defaults import patterns
from django.http import HttpResponse


urlpatterns = patterns("",
    ("^accounts/login/$", "django.contrib.auth.views.login"),
    ("^change_password/$", "django.contrib.auth.views.password_change",
     {"post_change_redirect": "/home/"}, "change_password"),
    (r"^admin/reset-account-throttling/(?P<user_id>-?[0-9]+)/",
     "security.auth_throttling.views.reset_username_throttle",
     {"redirect_url": "/admin"}, "reset_username_throttle"), 
    ("^home/$", lambda request: HttpResponse()),
    ("^csp-report/$", "security.views.csp_report"),

)

