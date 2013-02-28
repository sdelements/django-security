from django.conf.urls import patterns, include, url

urlpatterns = patterns('security.views',
        url('^/csp-report/$', security.views.csp_report),
        )
