"""
Production settings for Hadnx.
"""
import os
from .base import *

DEBUG = False
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',') + ['hadnx.onrender.com', 'localhost', '127.0.0.1']

# SECURITY: Require HTTPS
# SECURITY: Require HTTPS (Handled by Render, so disabled here to prevent loops)
SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# LOGGING for Debugging Render
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'DEBUG',  # Log 500s and 4xxs details
            'propagate': False,
        },
    },
}
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SAMESITE = 'None'
SESSION_COOKIE_DOMAIN = None
CSRF_COOKIE_DOMAIN = None

# HSTS - Disabled temporarily to debug redirects
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = True

# CORS - Restrict to specific origins in production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') + [
    'http://localhost:5176',
    'https://hadnx.onrender.com',
    'https://hadnx.vercel.app'
]

CSRF_TRUSTED_ORIGINS = [
    'https://hadnx.onrender.com',
    'https://hadnx.vercel.app'
]

# Database - PostgreSQL in production
if os.environ.get('DATABASE_URL'):
    import dj_database_url
    # conn_max_age=0 is safer for serverless environments (Neon/Render) to avoid stale connections
    DATABASES['default'] = dj_database_url.config(conn_max_age=0)

# Static files
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'
