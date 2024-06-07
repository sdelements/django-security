from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

# Finding proper User model that we can set Foreign key to.
# In newer versions of Django default user model can be specified in settings
# as `AUTH_USER_MODEL`
USER_MODEL = getattr(settings, "AUTH_USER_MODEL", User)


class PasswordExpiry(models.Model):
    """
    Associate a password expiry date with a user. For now, this date is
    effectively just a flag to tell us whether the user has ever changed
    their password, used to force users to change their initial passwords
    when they log in for the first time. Instances are created by
    security.RequirePasswordChangeMiddleware.
    """

    class Meta(object):
        verbose_name_plural = "PasswordExpiries"

    user = models.OneToOneField(USER_MODEL, on_delete=models.deletion.CASCADE)

    password_expiry_date = models.DateTimeField(
        auto_now_add=True,
        null=True,
        help_text="The date and time when the user's password expires. If "
        "this is empty, the password never expires.",
    )

    def is_expired(self):
        if self.password_expiry_date is None:
            return False
        else:
            return self.password_expiry_date <= timezone.now()

    def never_expire(self):
        self.password_expiry_date = None
        self.save()

    def __unicode__(self):
        return "Password Expiry: {0}".format(self.user)


# http://www.w3.org/TR/CSP/#sample-violation-report
class CspReport(models.Model):
    """
    Content Security Policy violation report object. Each report represents
    a single alert raised by client browser in response to CSP received from
    the server.

    Each alert means the browser was unable to access a web resource (image,
    CSS, frame, script) because server's policy prohibited it from accessing
    it. These alerts should be reviewed on regular basis, as they will occur in
    two cases: first, false positives where too restrictive CSP is blocking
    legitimate website features and needs tuning. Second, when real attacks
    were fired against the user and this raises a question how the malicious
    code appeared on your website.

    CSP reports are available in Django admin view. To be logged into database,
    CSP reports view needs to be configured properly. See csp_report_
    view for more information. Content Security Policy can be switched
    on for a web application using ContentSecurityPolicyMiddleware_ middleware.
    """

    document_uri = models.URLField(
        max_length=1000,
        help_text="The address of the protected resource, "
        "with any fragment component removed",
    )
    referrer = models.URLField(
        max_length=1000,
        help_text="The referrer attribute of the protected resource",
    )
    blocked_uri = models.URLField(
        max_length=1000,
        help_text="URI of the resource that was prevented from loading due to "
        "the policy violation, with any fragment component removed",
    )
    violated_directive = models.CharField(
        max_length=1000,
        help_text="The policy directive that was violated",
    )
    original_policy = models.TextField(
        null=True,
        max_length=1000,
        help_text="The original policy as received by the user-agent.",
    )

    date_received = models.DateTimeField(
        auto_now_add=True,
        help_text="When this report was received",
    )
    sender_ip = models.GenericIPAddressField(
        help_text="IP of the browser sending this report",
    )
    user_agent = models.CharField(
        max_length=1000,
        help_text="User-Agent of reporting browser",
    )

    def __unicode__(self):
        return "CSP Report: {0} from {1}".format(
            self.blocked_uri,
            self.document_uri,
        )
