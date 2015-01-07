from django.conf.urls import patterns, url

urlpatterns = patterns('security.views',
    url('^/csp-report/$', 'csp_report'),
)
