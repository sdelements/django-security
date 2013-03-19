from django.contrib import admin

from security.models import PasswordExpiry, CspReport

admin.site.register(PasswordExpiry)
admin.site.register(CspReport)
