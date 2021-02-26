# OIDC_OP_USER_ENDPOINT = 'http://localhost:8001'
OIDC_VERIFY_SSL = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': 'localhost',
        'PORT': 5432,
    }
}
