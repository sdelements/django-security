from django.urls import path

from security import views

urlpatterns = [
    path("/csp-report/", views.csp_report),
]
