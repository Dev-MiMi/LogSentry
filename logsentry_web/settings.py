"""Settings for the local dashboard and authenticated collector inbox."""

import os
from pathlib import Path
import secrets

from django.core.exceptions import ImproperlyConfigured


BASE_DIR = Path(__file__).resolve().parent.parent
RUNTIME_DIR = Path(os.environ.get("LOGSENTRY_RUNTIME_DIR", BASE_DIR / "runtime"))
DEBUG = os.environ.get("LOGSENTRY_DEBUG", "1") == "1"
SECRET_KEY = os.environ.get("LOGSENTRY_SECRET_KEY")
if not SECRET_KEY and (RUNTIME_DIR / "web" / "secret.key").is_file():
    from receiver.storage import check_private
    check_private(RUNTIME_DIR / "web", directory=True)
    check_private(RUNTIME_DIR / "web" / "secret.key")
    SECRET_KEY = (RUNTIME_DIR / "web" / "secret.key").read_text().strip()
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("Set LOGSENTRY_SECRET_KEY when LOGSENTRY_DEBUG=0.")
    # Bootstrap only. init_web writes a persistent key before accounts are used.
    SECRET_KEY = secrets.token_urlsafe(50)

# Development server binds to loopback by default. Add other hosts explicitly
# only when needed; no wildcard allowed-host setting is used.
ALLOWED_HOSTS = [host.strip() for host in os.environ.get(
    "LOGSENTRY_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]").split(",") if host.strip()]
if not DEBUG and (not os.environ.get("LOGSENTRY_ALLOWED_HOSTS") or "*" in ALLOWED_HOSTS):
    raise ImproperlyConfigured("Set explicit LOGSENTRY_ALLOWED_HOSTS for deployment.")
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.staticfiles", "rest_framework",
    "dashboard.apps.DashboardConfig", "receiver.apps.ReceiverConfig",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "logsentry_web.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
    ]},
}]
WSGI_APPLICATION = "logsentry_web.wsgi.application"
# Accounts/sessions are separate from raw evidence and receiver records.
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": RUNTIME_DIR / "web" / "site.sqlite3"}}
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/receiver/"
LOGOUT_REDIRECT_URL = LOGIN_URL
SESSION_COOKIE_AGE = 8 * 60 * 60
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 3600 if not DEBUG else 0
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
# Only the supplied loopback-bound Gunicorn + Nginx deployment should enable this.
if os.environ.get("LOGSENTRY_TRUST_PROXY") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
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
LOGSENTRY_COLLECTION_DATABASE = RUNTIME_DIR / "collection.sqlite3"

# Milestone 1: a separate, local event inbox. Incoming events cannot modify the
# collector's evidence database. Credentials are generated, never committed.
LOGSENTRY_RECEIVER_DATABASE = RUNTIME_DIR / "receiver" / "events.sqlite3"
LOGSENTRY_RECEIVER_CREDENTIALS = RUNTIME_DIR / "receiver" / "credentials.json"
LOGSENTRY_FORWARDER_CONFIG = RUNTIME_DIR / "forwarder" / "config.json"
LOGSENTRY_OUTBOX_DATABASE = RUNTIME_DIR / "forwarder" / "outbox.sqlite3"
REST_FRAMEWORK = {
    "UNAUTHENTICATED_USER": None,  # No Django accounts or session authentication.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}
