import os as _os
import django

def is_version(version):
    return all(x >= y for x, y in zip(django.VERSION, version))


_PROJECT_PATH = _os.path.abspath(_os.path.dirname(__file__))

DEBUG = True
TEMPLATE_DEBUG = DEBUG
ADMINS = ()
MANAGERS = ADMINS
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'testing.db',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
    }
}
TIME_ZONE = 'America/Chicago'
USE_TZ = True
LANGUAGE_CODE = 'en-us'
SITE_ID = 1
USE_I18N = True
USE_L10N = True
MEDIA_ROOT = ''
MEDIA_URL = ''
STATIC_ROOT = ''
STATIC_URL = '/static/'
ADMIN_MEDIA_PREFIX = '/static/admin/'
STATICFILES_DIRS = ()
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)
SECRET_KEY = 'p_2zsf+@4uw$kcdl$!tkf0lrh%w^!#@2@iwo4plef2n$(@uj4_'
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)
MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'security.middleware.SessionExpiryPolicyMiddleware',
    'security.middleware.LoginRequiredMiddleware',
    'security.middleware.XFrameOptionsMiddleware',
    'security.middleware.ContentNoSniff',
    'security.middleware.ContentSecurityPolicyMiddleware',
    'security.middleware.StrictTransportSecurityMiddleware',
    'security.middleware.P3PPolicyMiddleware',
    'security.middleware.XssProtectMiddleware',
    'security.middleware.MandatoryPasswordChangeMiddleware',
    'security.middleware.NoConfidentialCachingMiddleware',
    'security.auth_throttling.Middleware',
)
ROOT_URLCONF = 'testing.urls'
TEMPLATE_DIRS = (_os.path.join(_PROJECT_PATH, "templates"),)
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    'security',
    'tests'
)

if is_version((1, 6)):
    TEST_RUNNER = 'django.test.runner.DiscoverRunner'

LOGIN_REDIRECT_URL="/home/"

# The tests for django.contrib.auth use certain URLs, and they'll fail if we
# interfere with these.
_DJANGO_TESTING_URLS = [
    'login/', 'login_required/', 'login_required_login_url/',
    'admin_password_reset/', 'logout/', 'password_reset/',
    'password_reset_from_email/', 'reset/', 'password_change/', 'remote_user/',
    'auth_processor_messages/', 'auth_processor_perms/',
    'auth_processor_user/', 'auth_processor_perm_in_perms/',
    'admin/auth/user/',
]

LOGIN_EXEMPT_URLS = ["accounts/login", "custom-login"] + _DJANGO_TESTING_URLS

MANDATORY_PASSWORD_CHANGE = {
    "URL_NAME": "change_password",
    "EXEMPT_URL_NAMES": (),
    "EXEMPT_URLS": _DJANGO_TESTING_URLS,
}

NO_CONFIDENTIAL_CACHING = {
    "WHITELIST_REGEXES": ["^/accounts/login$"],
    "BLACKLIST_REGEXES": ["^/accounts/logout$"]
}

AUTHENTICATION_THROTTLING = {
    "DELAY_FUNCTION": lambda x, y: (0, 0),
    "LOGIN_URLS_WITH_TEMPLATES": [
        ("accounts/login/", "login.html")
    ]
}

XSS_PROTECT = 'on'
X_FRAME_OPTIONS = 'allow-from: http://example.com'
X_FRAME_OPTIONS_EXCLUDE_URLS = (
    r'^/test\d/$',
)
CSP_STRING="allow 'self'; script-src *.google.com"
CSP_MODE='enforce'
P3P_POLICY_URL = '/w3c/p3p.xml'
P3P_COMPACT_POLICY = 'PRIVATE'

# Django 1.6 uses JSONSerializer which can't handle datetime
SESSION_SERIALIZER='django.contrib.sessions.serializers.PickleSerializer'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
