# -*- coding: utf-8 -*-
from django.db import models
from south.db import db
from south.utils import datetime_utils as datetime
from south.v2 import SchemaMigration


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'CspReport'
        db.create_table(
            "security_cspreport",
            (
                ("id", self.gf("django.db.models.fields.AutoField")(primary_key=True)),
                (
                    "document_uri",
                    self.gf("django.db.models.fields.URLField")(max_length=1000),
                ),
                (
                    "referrer",
                    self.gf("django.db.models.fields.URLField")(max_length=1000),
                ),
                (
                    "blocked_uri",
                    self.gf("django.db.models.fields.URLField")(max_length=1000),
                ),
                (
                    "violated_directive",
                    self.gf("django.db.models.fields.CharField")(max_length=1000),
                ),
                (
                    "original_policy",
                    self.gf("django.db.models.fields.TextField")(
                        max_length=1000, null=True
                    ),
                ),
                (
                    "date_received",
                    self.gf("django.db.models.fields.DateTimeField")(
                        auto_now_add=True, blank=True
                    ),
                ),
                (
                    "sender_ip",
                    self.gf("django.db.models.fields.GenericIPAddressField")(
                        max_length=39
                    ),
                ),
                (
                    "user_agent",
                    self.gf("django.db.models.fields.CharField")(max_length=1000),
                ),
            ),
        )
        db.send_create_signal("security", ["CspReport"])

    def backwards(self, orm):
        # Deleting model 'CspReport'
        db.delete_table("security_cspreport")

    models = {
        "auth.group": {
            "Meta": {"object_name": "Group"},
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "name": (
                "django.db.models.fields.CharField",
                [],
                {"unique": "True", "max_length": "80"},
            ),
            "permissions": (
                "django.db.models.fields.related.ManyToManyField",
                [],
                {
                    "to": "orm['auth.Permission']",
                    "symmetrical": "False",
                    "blank": "True",
                },
            ),
        },
        "auth.permission": {
            "Meta": {
                "ordering": "(u'content_type__app_label', u'content_type__model', u'codename')",
                "unique_together": "((u'content_type', u'codename'),)",
                "object_name": "Permission",
            },
            "codename": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "100"},
            ),
            "content_type": (
                "django.db.models.fields.related.ForeignKey",
                [],
                {
                    "to": "orm['contenttypes.ContentType']",
                    "on_delete": "django.db.models.CASCADE",
                },
            ),
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "name": ("django.db.models.fields.CharField", [], {"max_length": "50"}),
        },
        "auth.user": {
            "Meta": {"object_name": "User"},
            "date_joined": (
                "django.db.models.fields.DateTimeField",
                [],
                {"default": "datetime.datetime.now"},
            ),
            "email": (
                "django.db.models.fields.EmailField",
                [],
                {"max_length": "75", "blank": "True"},
            ),
            "first_name": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "30", "blank": "True"},
            ),
            "groups": (
                "django.db.models.fields.related.ManyToManyField",
                [],
                {
                    "symmetrical": "False",
                    "related_name": "u'user_set'",
                    "blank": "True",
                    "to": "orm['auth.Group']",
                },
            ),
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "is_active": (
                "django.db.models.fields.BooleanField",
                [],
                {"default": "True"},
            ),
            "is_staff": (
                "django.db.models.fields.BooleanField",
                [],
                {"default": "False"},
            ),
            "is_superuser": (
                "django.db.models.fields.BooleanField",
                [],
                {"default": "False"},
            ),
            "last_login": (
                "django.db.models.fields.DateTimeField",
                [],
                {"default": "datetime.datetime.now"},
            ),
            "last_name": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "30", "blank": "True"},
            ),
            "password": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "128"},
            ),
            "user_permissions": (
                "django.db.models.fields.related.ManyToManyField",
                [],
                {
                    "symmetrical": "False",
                    "related_name": "u'user_set'",
                    "blank": "True",
                    "to": "orm['auth.Permission']",
                },
            ),
            "username": (
                "django.db.models.fields.CharField",
                [],
                {"unique": "True", "max_length": "255"},
            ),
        },
        "contenttypes.contenttype": {
            "Meta": {
                "ordering": "('name',)",
                "unique_together": "(('app_label', 'model'),)",
                "object_name": "ContentType",
                "db_table": "'django_content_type'",
            },
            "app_label": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "100"},
            ),
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "model": ("django.db.models.fields.CharField", [], {"max_length": "100"}),
            "name": ("django.db.models.fields.CharField", [], {"max_length": "100"}),
        },
        "security.cspreport": {
            "Meta": {"object_name": "CspReport"},
            "blocked_uri": (
                "django.db.models.fields.URLField",
                [],
                {"max_length": "1000"},
            ),
            "date_received": (
                "django.db.models.fields.DateTimeField",
                [],
                {"auto_now_add": "True", "blank": "True"},
            ),
            "document_uri": (
                "django.db.models.fields.URLField",
                [],
                {"max_length": "1000"},
            ),
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "original_policy": (
                "django.db.models.fields.TextField",
                [],
                {"max_length": "1000", "null": "True"},
            ),
            "referrer": (
                "django.db.models.fields.URLField",
                [],
                {"max_length": "1000"},
            ),
            "sender_ip": (
                "django.db.models.fields.GenericIPAddressField",
                [],
                {"max_length": "39"},
            ),
            "user_agent": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "1000"},
            ),
            "violated_directive": (
                "django.db.models.fields.CharField",
                [],
                {"max_length": "1000"},
            ),
        },
        "security.passwordexpiry": {
            "Meta": {"object_name": "PasswordExpiry"},
            "id": ("django.db.models.fields.AutoField", [], {"primary_key": "True"}),
            "password_expiry_date": (
                "django.db.models.fields.DateTimeField",
                [],
                {"auto_now_add": "True", "null": "True", "blank": "True"},
            ),
            "user": (
                "django.db.models.fields.related.ForeignKey",
                [],
                {
                    "to": "orm['auth.User']",
                    "unique": "True",
                    "on_delete": "django.db.models.CASCADE",
                },
            ),
        },
    }

    complete_apps = ["security"]
