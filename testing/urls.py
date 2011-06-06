# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

from django.conf.urls.defaults import patterns
from django.http import HttpResponse


urlpatterns = patterns("",
    ("^accounts/login/$", "django.contrib.auth.views.login"),
    ("^change_password/$", "django.contrib.auth.views.password_change",
     {"post_change_redirect": "/home/"}),
    ("^home/$", lambda request: HttpResponse())
)

