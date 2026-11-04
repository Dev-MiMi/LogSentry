"""Settings for the local dashboard and authenticated collector inbox."""

import os
from pathlib import Path
import secrets

from django.core.exceptions import ImproperlyConfigured


BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = os.environ.get("LOGSENTRY_DEBUG", "1") == "1"
SECRET_KEY = os.environ.get("LOGSENTRY_SECRET_KEY")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("Set LOGSENTRY_SECRET_KEY when LOGSENTRY_DEBUG=0.")
    # No committed secret. This temporary local key is enough for read-only pages.
    SECRET_KEY = secrets.token_urlsafe(50)

# Development server binds to loopback by default. Add other hosts explicitly
# only when needed; no wildcard allowed-host setting is used.
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
INSTALLED_APPS = [
    "django.contrib.staticfiles", "rest_framework",
    "dashboard.apps.DashboardConfig", "receiver.apps.ReceiverConfig",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "logsentry_web.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
}]
WSGI_APPLICATION = "logsentry_web.wsgi.application"
# Django has no ORM models/accounts yet; collected records use a separate store.
DATABASES = {"default": {"ENGINE": "django.db.backends.dummy"}}
LANGUAGE_CODE = "en-us"
# Dashboard display follows Nigeria time. Each source still supplies its own
# timezone when the collector interprets its original log timestamps.
TIME_ZONE = "Africa/Lagos"
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"

# The local collector owns this separate SQLite store. Web requests open it
# read-only; URL parameters can select source IDs, never filesystem paths.
LOGSENTRY_COLLECTION_DATABASE = BASE_DIR / "runtime" / "collection.sqlite3"

# Milestone 1: a separate, local event inbox. Incoming events cannot modify the
# collector's evidence database. Credentials are generated, never committed.
LOGSENTRY_RECEIVER_DATABASE = BASE_DIR / "runtime" / "receiver" / "events.sqlite3"
LOGSENTRY_RECEIVER_CREDENTIALS = BASE_DIR / "runtime" / "receiver" / "credentials.json"
REST_FRAMEWORK = {
    "UNAUTHENTICATED_USER": None,  # No Django accounts or session authentication.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}
