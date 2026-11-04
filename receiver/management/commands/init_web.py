"""Prepare private Django account/session storage and a local administrator."""

from pathlib import Path
import json
import os
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from receiver.storage import check_private


class Command(BaseCommand):
    help = "Initialize private account storage and generate a dashboard login in a private file."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin")

    def handle(self, *args, **options):
        database = Path(settings.DATABASES["default"]["NAME"])
        folder = database.parent
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        check_private(folder, directory=True)
        for path, contents in ((folder / "secret.key", secrets.token_urlsafe(50)), (database, "")):
            if not path.exists():
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(contents)
            check_private(path)
        call_command("migrate", interactive=False, verbosity=0)
        model = get_user_model()
        if model.objects.filter(username=options["username"]).exists():
            raise CommandError("Account already exists. Use changepassword to change its password.")
        password = secrets.token_urlsafe(24)
        path = folder / "initial-login.json"
        # Never overwrite or print the password; one-time operator handoff.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump({"username": options["username"], "password": password}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            model.objects.create_superuser(options["username"], password=password)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        self.stdout.write(f"Dashboard account created. Read the private login file locally: {path}")
        self.stdout.write("Restart Django, sign in, then use changepassword if desired and remove the handoff file.")
