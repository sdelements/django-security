import django
from django.conf.urls import patterns, url

from security import views

if django.VERSION >= (1, 10):
    urlpatterns = [
        url('^/csp-report/$', views.csp_report),
    ]
else:
    urlpatterns = patterns(
        '',
        url('^/csp-report/$', views.csp_report),
    )
