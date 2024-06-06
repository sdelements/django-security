from django.contrib import admin

from security.models import CspReport, PasswordExpiry

admin.site.register(PasswordExpiry)
admin.site.register(CspReport)
