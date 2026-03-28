import os
from pathlib import Path
from .settings import *

# Production settings
DEBUG = False
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-phishguard-fyp-2026-change-in-production')

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_SECONDS = 31536000
SECURE_REDIRECT_EXEMPT = []
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Database (use PostgreSQL in production)
try:
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.config(
            default=f'sqlite:///{BASE_DIR}/db.sqlite3'
        )
    }
except ImportError:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Static files
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_ROOT = BASE_DIR / 'media'

# Allowed hosts
ALLOWED_HOSTS = ['*']  # In production, specify your domain

# CORS (if needed for API)
try:
    CORS_ALLOWED_ORIGINS = [
        "https://yourdomain.netlify.app",
    ]
except:
    pass

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'whitenoise.runserver_nostatic',
    'detector',
]

# Environment variables
ML_MODEL_PATH = BASE_DIR / 'ml' / 'phishguard_model.pkl'
VECTORIZER_PATH = BASE_DIR / 'ml' / 'tfidf_vectorizer.pkl'
