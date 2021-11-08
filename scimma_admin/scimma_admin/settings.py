"""
Django settings for scimma_admin project.

Generated by 'django-admin startproject' using Django 3.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import boto3
import requests
import configparser


def get_secret(name):
    sm = boto3.client("secretsmanager", region_name="us-west-2")
    return sm.get_secret_value(SecretId=name)["SecretString"]


def get_rds_db(db_instance_id):
    rds = boto3.client("rds", region_name="us-west-2")
    resp = rds.describe_db_instances(Filters=[
        {"Name": "db-instance-id", "Values": [db_instance_id]},
    ])
    return resp['DBInstances'][0]


def get_localdev_secret(name):
    """Load a secret which has been stored in the localdev.conf INI file at the root
    of the repo. This file's contents are set with 'make localdev-setup', using
    the scripts/setup_localdev_secrets.py script.

    """
    cp = configparser.ConfigParser()
    conf_file = os.path.join(os.path.dirname(BASE_DIR), "localdev.conf")
    print(conf_file)
    cp.read(os.path.join(conf_file))
    print(cp.sections())
    return cp["secrets"][name]

# ELB is extremely picky about the headers on HTTP 301 responses for them to be correctly passed
# back to the client. This custom middleware tries to keep it happy.
def set_redirect_headers(get_response):
    def middleware(request):
        response = get_response(request)
        if response.status_code == 301:
            response['Content-Type'] = '*/*; charset="UTF-8"'
            response['Content-Length'] = 0
        return response
    return middleware

SCIMMA_ENVIRONMENT = os.environ.get("SCIMMA_ENVIRONMENT", default="local")

_aws_name_prefixes = {
    "local": None, # AWS variables are not used for local testing
    "dev": "", # this is empty for historical reasons, it should probably be renamed in future
    "demo": "demo-",
    "prod": "prod-",
}

if not SCIMMA_ENVIRONMENT in _aws_name_prefixes.keys():
    raise RuntimeError(f"Specified environment ({SCIMMA_ENVIRONMENT}) is not known")

AWS_NAME_PREFIX = _aws_name_prefixes[SCIMMA_ENVIRONMENT]
LOCAL_TESTING = SCIMMA_ENVIRONMENT=="local"

print("SCIMMA_ENVIRONMENT:",SCIMMA_ENVIRONMENT)
print("AWS_NAME_PREFIX:",AWS_NAME_PREFIX)
print("LOCAL_TESTING:",LOCAL_TESTING)

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
if not LOCAL_TESTING:
    SECRET_KEY = get_secret(AWS_NAME_PREFIX+"scimma-admin-django-secret")
else:
    SECRET_KEY = "zzzlocal"

if not LOCAL_TESTING:
    SECURE_SSL_REDIRECT = True

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = SCIMMA_ENVIRONMENT != "prod"

# This looks scary, but it's OK because we always run behind a load balancer
# which verifies the HTTP Host header for us. In production, that's an EKS Load
# Balancer.
ALLOWED_HOSTS = ["*"]

# Application definition

INSTALLED_APPS = [
    'hopskotch_auth',
    'whitenoise.runserver_nostatic',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'mozilla_django_oidc',
    'bootstrap4'  # TODO: staticfile configuration must be fixed for uwsgi/deployment
]

MIDDLEWARE = [
    'scimma_admin.settings.set_redirect_headers', # must be placed before SecurityMiddleware to modify redirects
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Placement after SecurityMiddleware needed as per whitenoise docs
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'scimma_admin.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'scimma_admin.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {'default': {}}
if not LOCAL_TESTING:
    rds_db = get_rds_db(AWS_NAME_PREFIX+"scimma-admin-postgres")
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': rds_db['DBName'],
        'USER': rds_db['MasterUsername'],
        'PASSWORD': get_secret(AWS_NAME_PREFIX+"scimma-admin-db-password"),
        'HOST': rds_db['Endpoint']['Address'],
        'PORT': str(rds_db['Endpoint']['Port']),
    }
else:
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': 'localhost',
        'PORT': 5432,
    }


# Authentication
# https://mozilla-django-oidc.readthedocs.io/en/stable/settings.html
OIDC_OP_AUTHORIZATION_ENDPOINT = 'https://cilogon.org/authorize/'
OIDC_OP_TOKEN_ENDPOINT = 'https://cilogon.org/oauth2/token'
OIDC_OP_USER_ENDPOINT = 'https://cilogon.org/oauth2/userinfo'
OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_OP_JWKS_ENDPOINT = 'https://cilogon.org/oauth2/certs'
AUTHENTICATION_BACKENDS = (
    'hopskotch_auth.auth.HopskotchOIDCAuthenticationBackend',
)
if not LOCAL_TESTING:
    OIDC_RP_CLIENT_ID = get_secret(AWS_NAME_PREFIX+"scimma-admin-cilogon-client-id")
    OIDC_RP_CLIENT_SECRET = get_secret(AWS_NAME_PREFIX+"scimma-admin-cilogon-client-secret")
else:
    OIDC_RP_CLIENT_ID = 'cilogon:/client_id/79be6fcf2057dbc381dfb8ba9c17d5fd'
    OIDC_RP_CLIENT_SECRET = get_localdev_secret("cilogon_client_secret")


LOGIN_URL ='/hopauth/login'
LOGIN_REDIRECT_URL = '/hopauth'
LOGOUT_REDIRECT_URL = '/hopauth/logout'
LOGIN_REDIRECT_URL_FAILURE = '/hopauth/login_failure'

# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'America/Los_Angeles'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': "DEBUG" if DEBUG else "INFO",
            'propagate': False,
        },
        'django.db.backends': {
            'level': "INFO",
        },
    },
    'formatters': {
        'console': {
            'format': '%(asctime)s %(levelname)s [%(name)s:%(lineno)s] %(module)s %(process)d %(thread)d %(message)s',
        },
    },
}

# TLS termination is handled by an AWS ALB in production
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

KAFKA_USER_AUTH_GROUP = os.environ.get("KAFKA_USER_AUTH_GROUP", default="kafkaUsers")

# This URL will be shown to users as the place they should go to create accounts
USER_SIGNUP_URL = os.environ.get("USER_SIGNUP_URL", default=None)

try:
    from local_settings import *
except ImportError:
    pass
