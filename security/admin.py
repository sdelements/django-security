from django.contrib import admin

from models import PasswordExpiry, CspReport

admin.site.register(PasswordExpiry)
admin.site.register(CspReport)
