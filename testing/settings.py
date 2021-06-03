import os as _os


_PROJECT_PATH = _os.path.abspath(_os.path.dirname(__file__))

DEBUG = True
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
STATICFILES_DIRS = ()
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)
SECRET_KEY = 'p_2zsf+@4uw$kcdl$!tkf0lrh%w^!#@2@iwo4plef2n$(@uj4_'

MIDDLEWARE = (
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
    'security.middleware.ReferrerPolicyMiddleware',
)

ROOT_URLCONF = 'testing.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [_os.path.join(_PROJECT_PATH, "templates")],
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ]
        }
    }
]


INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    'django.contrib.messages',
    'django.contrib.admin',
    'security',
    'tests'
)

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

LOGIN_REDIRECT_URL = "/home/"

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

LOGIN_EXEMPT_URLS = [
    "accounts/login",
    "custom-login",
    "admin/reset-account-throttling",
] + _DJANGO_TESTING_URLS

SESSION_EXPIRY_EXEMPT_URLS = LOGIN_EXEMPT_URLS

CUSTOM_LOGOUT_MODULE = 'tests.tests.mocked_custom_logout'

MANDATORY_PASSWORD_CHANGE = {
    "URL_NAME": "change_password",
    "EXEMPT_URL_NAMES": (),
    "EXEMPT_URLS": _DJANGO_TESTING_URLS,
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
CSP_STRING = "allow 'self'; script-src *.google.com"
CSP_MODE = 'enforce'
P3P_POLICY_URL = '/w3c/p3p.xml'
P3P_COMPACT_POLICY = 'PRIVATE'

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

CLEAR_SITE_DATA_URL_WHITELIST = ('/home/')
