from django.conf.urls import url

from security import views


urlpatterns = [
    url('^/csp-report/$', views.csp_report),
]
