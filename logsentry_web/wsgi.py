"""Web-server entry point; manage.py runserver also uses Django configuration."""

import os

from django.core.wsgi import get_wsgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "logsentry_web.settings")
application = get_wsgi_application()
