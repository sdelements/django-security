# Django-Security

[![Build Status](https://travis-ci.org/sdelements/django-security.svg?branch=master)](https://travis-ci.org/sdelements/django-security)

This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.

# Full documentation

Automatically generated documentation of `django-security` is available on Read The Docs:

* [Django-security documentation](http://django-security.readthedocs.org/en/master/)

# Requirements

* Python >= 3.6
* Django >= 1.11

For Django < 1.8 use django-security==0.9.4. For Django < 1.11 use django-security==0.11.3.

Note: For versions prior to 0.10.0, `datetime` objects were being added to the session and required Django's PickleSerializer for (de)serializing. This has now been changed so that the strings of these `datetime`s are being stored instead. If you are still using PickleSerializer for this reason, we suggest switching to Django's default JSONSerializer (default since Django 1.6) for better security.


# Installation

Install from Python packages repository:

    pip install django-security

If you prefer the latest development version, install from
[django-security](https://github.com/sdelements/django-security) repository on GitHub:

    git clone https://github.com/sdelements/django-security.git
    cd django-security
    sudo python setup.py install

Adding to Django application's `settings.py` file:

    INSTALLED_APPS = (
        ...
        'security',
        ...
    )

Pre-Django 1.10, middleware modules can be added to `MIDDLEWARE_CLASSES` list in settings file:

    MIDDLEWARE_CLASSES = (
        ...
        'security.middleware.DoNotTrackMiddleware',
        'security.middleware.ContentNoSniff',
        'security.middleware.XssProtectMiddleware',
        'security.middleware.XFrameOptionsMiddleware',
    )

After Django 1.10, middleware modules can be added to `MIDDLEWARE` list in settings file:

    MIDDLEWARE = (
        ...
        'security.middleware.DoNotTrackMiddleware',
        'security.middleware.ContentNoSniff',
        'security.middleware.XssProtectMiddleware',
        'security.middleware.XFrameOptionsMiddleware',
    )



Unlike the modules listed above, some other modules **require**  configuration settings,
fully described in [django-security documentation](http://django-security.readthedocs.org/en/latest/).
Brief description is provided below.

## Middleware

Provided middleware modules will modify web application's output and input and in most cases requires no
or minimum configuration.

<table>
<tr>
<th>Middleware
<th>Description
<th>Configuration
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ClearSiteDataMiddleware">ClearSiteDataMiddleware</a>
<td>Send Clear-Site-Data header in HTTP response for any page that has been whitelisted. <em>Recommended</em>.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ContentNoSniff">ContentNoSniff</a>
<td><b>DEPRECATED: </b>Will be removed in future releases, consider <a href="https://docs.djangoproject.com/en/1.11/ref/middleware/#django.middleware.security.SecurityMiddleware">django.middleware.security.SecurityMiddleware</a> via <i>SECURE_CONTENT_TYPE_NOSNIFF</i> setting.<br/>Disable possibly insecure autodetection of MIME types in browsers. <em>Recommended.</em>
<td>None.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ContentSecurityPolicyMiddleware">ContentSecurityPolicyMiddleware</a>
<td>Send Content Security Policy (CSP) header in HTTP response. <em>Recommended,</em> requires careful tuning.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.DoNotTrackMiddleware">DoNotTrackMiddleware</a>
<td>Read user browser's DoNotTrack preference and pass it to application.  <em>Recommended,</em> requires implementation in views and templates.
<td>None.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.LoginRequiredMiddleware">LoginRequiredMiddleware</a>
<td>Requires a user to be authenticated to view any page on the site that hasn't been white listed.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.MandatoryPasswordChangeMiddleware">MandatoryPasswordChangeMiddleware</a>
<td>Redirects any request from an authenticated user to the password change form if that user's password has expired.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.NoConfidentialCachingMiddleware">NoConfidentialCachingMiddleware</a>
<td>Adds No-Cache and No-Store headers to confidential pages.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.P3PPolicyMiddleware">P3PPolicyMiddleware</a>
<td><b>DEPRECATED: </b>Will be removed in future releases.<br/>Adds the HTTP header attribute specifying compact P3P policy.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ReferrerPolicyMiddleware">ReferrerPolicyMiddleware</a>
<td>Specify when the browser will set a `Referer` header.
<td>Optional.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.SessionExpiryPolicyMiddleware">SessionExpiryPolicyMiddleware</a>
<td>Expire sessions on browser close, and on expiry times stored in the cookie itself.
<td>Required.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.StrictTransportSecurityMiddleware">StrictTransportSecurityMiddleware</a>
<td><b>DEPRECATED: </b>Will be removed in future releases, consider <a href="https://docs.djangoproject.com/en/1.11/ref/middleware/#django.middleware.security.SecurityMiddleware">django.middleware.security.SecurityMiddleware</a> via <i>SECURE_HSTS_SECONDS</i>, <i>SECURE_HSTS_INCLUDE_SUBDOMAINS</i> and <i>SECURE_HSTS_PRELOAD</i> settings.<br/>Enforce SSL/TLS connection and disable plaintext fall-back. <em>Recommended</em> for SSL/TLS sites.
<td>Optional.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.XFrameOptionsMiddleware">XFrameOptionsMiddleware</a>
<td>Disable framing of the website, mitigating Clickjacking attacks. <em>Recommended.</em>
<td>Optional.

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.XssProtectMiddleware">XssProtectMiddleware</a>
<td><b>DEPRECATED: </b>Will be removed in future releases, consider <a href="https://docs.djangoproject.com/en/1.11/ref/middleware/#django.middleware.security.SecurityMiddleware">django.middleware.security.SecurityMiddleware</a> via <i>SECURE_BROWSER_XSS_FILTER</i> setting.<br/>Enforce browser's Cross Site Scripting protection. <em>Recommended.</em>
<td>None.

</table>

## Views

`csp_report`

View that allows reception of Content Security Policy violation reports sent by browsers in response
to CSP header set by ``ContentSecurityPolicyMiddleware`. This should be used only if long term, continuous CSP report
analysis is required. For one time CSP setup [CspBuilder](http://cspbuilder.info/) is much simpler.

This view can be configured to either log received reports or store them in database.
See [documentation](http://django-security.readthedocs.org/en/latest/#security.views.csp_report) for details.

`require_ajax`

A view decorator which ensures that the request being processed by view is an AJAX request. Example usage:

    @require_ajax
    def myview(request):
        ...

## Models

`CspReport`

Content Security Policy violation report object. Only makes sense if `ContentSecurityPolicyMiddleware` and `csp_report` view are used.
With this model, the reports can be then analysed in Django admin site.

`PasswordExpiry`

Associate a password expiry date with a user.

## Logging

All `django-security` modules send important log messages to `security` facility. The application should configure a handler to receive them:

    LOGGING = {
        ...
        'loggers': {
            'security': {
                'handlers': ['console',],
                'level': 'INFO',
                'propagate': False,
                'formatter': 'verbose',
            },
        },
        ...
    }
