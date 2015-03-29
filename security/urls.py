from django.conf.urls import patterns, url

from security import views


urlpatterns = patterns(
    '',
    url('^/csp-report/$', views.csp_report),
)
