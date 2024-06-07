# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="CspReport",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "document_uri",
                    models.URLField(
                        help_text="The address of the protected resource, with any fragment component removed",
                        max_length=1000,
                    ),
                ),
                (
                    "referrer",
                    models.URLField(
                        help_text="The referrer attribute of the protected resource",
                        max_length=1000,
                    ),
                ),
                (
                    "blocked_uri",
                    models.URLField(
                        help_text="URI of the resource that was prevented from loading due to the policy violation, with any fragment component removed",
                        max_length=1000,
                    ),
                ),
                (
                    "violated_directive",
                    models.CharField(
                        help_text="The policy directive that was violated",
                        max_length=1000,
                    ),
                ),
                (
                    "original_policy",
                    models.TextField(
                        help_text="The original policy as received by the user-agent.",
                        max_length=1000,
                        null=True,
                    ),
                ),
                (
                    "date_received",
                    models.DateTimeField(
                        help_text="When this report was received", auto_now_add=True
                    ),
                ),
                (
                    "sender_ip",
                    models.GenericIPAddressField(
                        help_text="IP of the browser sending this report"
                    ),
                ),
                (
                    "user_agent",
                    models.CharField(
                        help_text="User-Agent of reporting browser", max_length=1000
                    ),
                ),
            ],
            options={},
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name="PasswordExpiry",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "password_expiry_date",
                    models.DateTimeField(
                        help_text="The date and time when the user's password expires. If this is empty, the password never expires.",
                        auto_now_add=True,
                        null=True,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        to=settings.AUTH_USER_MODEL,
                        unique=True,
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "PasswordExpiries",
            },
            bases=(models.Model,),
        ),
    ]
