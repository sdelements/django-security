# Django-Security

[![Build Status](https://travis-ci.org/sdelements/django-security.svg?branch=master)](https://travis-ci.org/sdelements/django-security)

This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.

# Full documentation

Automatically generated documentation of `django-security` is available on Read The Docs:

* [Django-security documentation](http://django-security.readthedocs.org/en/master/)

# Requirements

* Python >=3.12
* Django  ~4.2

# Installation

Install from Python packages repository:

    pip install django-security

If you prefer the latest development version, install from
[django-security](https://github.com/sdelements/django-security) repository on GitHub:

    git clone https://github.com/sdelements/django-security.git
    cd django-security
    poetry install

Adding to Django application's `settings.py` file:

    INSTALLED_APPS = (
        ...
        'security',
        ...
    )

Middleware modules can be added to `MIDDLEWARE` list in settings file:

    MIDDLEWARE = (
        ...
        'security.middleware.LoginRequiredMiddleware',
        ...
    )

Unlike the modules listed above, some other modules **require**  configuration settings,
fully described in [django-security documentation](http://django-security.readthedocs.org/en/latest/).
Brief description is provided below.

## Middleware

Provided middleware modules will modify web application's output and input and in most cases requires no
or minimum configuration.

<table>

<tr>
<th>Middleware</th>
<th>Description</th>
<th>Configuration</th>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ClearSiteDataMiddleware">ClearSiteDataMiddleware</a></td>
<td>Send Clear-Site-Data header in HTTP response for any page that has been whitelisted. <em>Recommended</em>.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ContentSecurityPolicyMiddleware">ContentSecurityPolicyMiddleware</a></td>
<td>Send Content Security Policy (CSP) header in HTTP response. <em>Recommended,</em> requires careful tuning.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.LoginRequiredMiddleware">LoginRequiredMiddleware</a></td>
<td>Requires a user to be authenticated to view any page on the site that hasn't been white listed.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.MandatoryPasswordChangeMiddleware">MandatoryPasswordChangeMiddleware</a></td>
<td>Redirects any request from an authenticated user to the password change form if that user's password has expired.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.NoConfidentialCachingMiddleware">NoConfidentialCachingMiddleware</a></td>
<td>Adds No-Cache and No-Store headers to confidential pages.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ReferrerPolicyMiddleware">ReferrerPolicyMiddleware</a></td>
<td>Specify when the browser will set a `Referer` header.</td>
<td>Optional.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.SessionExpiryPolicyMiddleware">SessionExpiryPolicyMiddleware</a></td>
<td>Expire sessions on browser close, and on expiry times stored in the cookie itself.</td>
<td>Required.</td>
</tr>

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ProfilingMiddleware">ProfilingMiddleware</a></td>
<td>A simple middleware to capture useful profiling information in Django.</td>
<td>Optional.</td>
</tr>

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
