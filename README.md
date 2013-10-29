# Django-Security

This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.

# Full documentation

Automatically generated documentation of `django-security` is available on Read The Docs:

* [Django-security documentation](http://django-security.readthedocs.org/en/latest/)

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

Middleware modules can be added to `MIDDLEWARE_CLASSES` list in settings file:

    MIDDLEWARE_CLASSES = (
    ...
    'security.middleware.DoNotTrackMiddleware',
    'security.middleware.ContentNoSniff',
    'security.middleware.XssProtectMiddleware',
    'security.middleware.XFrameOptionsMiddleware',
    'security.middleware.SessionExpiryPolicyMiddleware',
    'security.middleware.ContentSecurityPolicyMiddleware',
    )

Note that some of these modules will **require**  configuration settings,
fully described in [django-security documentation](http://django-security.readthedocs.org/en/latest/).
Brief description of modules is povided below.

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
<td>ContentNoSniff
<td>Disable possibly insecure autodetection of MIME types in browsers. *Recommended.*
<td>None

<tr>
<td><a href="http://django-security.readthedocs.org/en/latest/#security.middleware.ContentSecurityPolicyMiddleware">ContentSecurityPolicyMiddleware</a>
<td>Send Content Security Policy (CSP) header in HTTP response. *Recommended,* requires careful tuning.
<td>`CSP_MODE`, `CSP_STRING` or `CSP_DICT`

<tr>
<td>DoNotTrackMiddleware
<td>Read user browser's DoNotTrack preference and pass it to application. *Recommended,* requires implementation in views and templates.
<td>None ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.DoNotTrackMiddleware)

<tr>
<td>LoginRequiredMiddleware
<td>Requires a user to be authenticated to view any page on the site that hasn’t been white listed.
<td>`LOGIN_EXEMPT_URLS` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.LoginRequiredMiddleware))

<tr>
<td>MandatoryPasswordChangeMiddleware
<td>Redirects any request from an authenticated user to the password change form if that user’s password has expired.
<td>`MANDATORY_PASSWORD_CHANGE` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.MandatoryPasswordChangeMiddleware))

<tr>
<td>NoConfidentialCachingMiddleware
<td>Adds No-Cache and No-Store headers to confidential pages.
<td>`WHITELIST_ON`, `WHITELIST_REGEXES`, `BLACKLIST_ON`, `BLACKLIST_REGEXES` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.NoConfidentialCachingMiddleware))

<tr>
<td>P3PPolicyMiddleware
<td>Adds the HTTP header attribute specifying compact P3P policy.
<td>`P3P_COMPACT_POLICY`, `P3P_POLICY_URL` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.P3PPolicyMiddleware))

<tr>
<td>SessionExpiryPolicyMiddleware
<td>Expire sessions on browser close, and on expiry times stored in the cookie itself.
<td>None.

<tr>
<td>StrictTransportSecurityMiddleware
<td>Enforce SSL/TLS connection and disable plaintext fall-back. *Recommended* for SSL/TLS sites.
<td>`STS_MAX_AGE`, `STS_INCLUDE_SUBDOMAINS` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.StrictTransportSecurityMiddleware))

<tr>
<td>XFrameOptionsMiddleware
<td>Disable framing of the website, mitigating Clickjacking attacks. *Recommended.*
<td>`X_FRAME_OPTIONS` ([details](http://django-security.readthedocs.org/en/latest/#security.middleware.XFrameOptionsMiddleware))

<tr>
<td>XssProtectMiddleware
<td>Enforce browser's Cross Site Scripting protection. *Recommended.*
<td>None.

</table>

## Models

## Views




