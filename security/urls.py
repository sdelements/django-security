import django
from django.conf.urls import url

from security import views

if django.VERSION >= (1, 10):
    urlpatterns = [
        url('^/csp-report/$', views.csp_report),
    ]
else:
    from django.conf.urls import patterns
    urlpatterns = patterns(
        '',
        url('^/csp-report/$', views.csp_report),
    )
