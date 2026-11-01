"""Run `python3 -m logsentry` with the package context its imports require."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
