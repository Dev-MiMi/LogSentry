"""Capture actual OpenSSH output when auth.log/journald are unavailable.

setup creates a private, loopback-only SSH endpoint with dedicated keys. serve
runs OpenSSH in the foreground and records its stderr as JSON lines. The capture
timestamp is an observation time, not a timestamp supplied by sshd. No login
events are fabricated and no system SSH configuration is modified.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys

from .collection_sources import Source
from .collection_store import DEFAULT_DATABASE, _check_private, open_store
from .collector import register_source
from .reporting import _safe_text


DEFAULT_DIRECTORY = DEFAULT_DATABASE.parent / "ssh"
MAX_MESSAGE_BYTES = 8192
MAX_CAPTURE_BYTES = 10 * 1024 * 1024


def _binary(name):
    found = shutil.which(name)
    if not found and name == "sshd" and Path("/usr/sbin/sshd").is_file():
        found = "/usr/sbin/sshd"
    if not found:
        raise ValueError(f"{name} is not installed. See docs/ssh_collection.md for setup.")
    return str(Path(found).absolute())


def _write_private(path, text):
    """Create configuration without replacing existing files or links."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def _config_path(path):
    text = str(path)
    if any(ord(character) < 32 for character in text):
        raise ValueError("SSH paths cannot contain control characters.")
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def setup(directory: Path, port: int, username: str):
    """Prepare OpenSSH with a dedicated key and an immediately exiting session."""
    if not 1024 <= port <= 65535:
        raise ValueError("Choose an unprivileged SSH port between 1024 and 65535.")
    # AllowUsers understands patterns: require a literal existing account name.
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*\$?", username):
        raise ValueError("A simple existing system account name is required.")
    try:
        pwd.getpwnam(username)
    except KeyError as error:
        raise ValueError("The selected SSH account does not exist.") from error
    keygen, true = _binary("ssh-keygen"), _binary("true")
    directory = directory.absolute()
    _config_path(directory)
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)  # Existing keys/configuration are never replaced.
    for name in ("host_ed25519", "client_ed25519"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "logsentry-local-ssh",
                        "-f", str(directory / name)], check=True, timeout=30)
        (directory / name).chmod(0o600)
        (directory / (name + ".pub")).chmod(0o600)
    public = (directory / "client_ed25519.pub").read_text(encoding="utf-8")
    _write_private(directory / "authorized_keys", public)
    host_key = (directory / "host_ed25519.pub").read_text(encoding="utf-8").strip()
    _write_private(directory / "known_hosts", f"[127.0.0.1]:{port} {host_key}\n")
    config = f"""# Local LogSentry SSH endpoint; no global SSH configuration is read.
Port {port}
ListenAddress 127.0.0.1
AddressFamily inet
HostKey {_config_path(directory / 'host_ed25519')}
PidFile {_config_path(directory / 'sshd.pid')}
AuthorizedKeysFile {_config_path(directory / 'authorized_keys')}
AllowUsers {username}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
UsePAM no
StrictModes yes
LogLevel VERBOSE
LoginGraceTime 30
MaxAuthTries 3
MaxStartups 5:30:10
DisableForwarding yes
PermitTTY no
PermitUserRC no
ForceCommand {_config_path(Path(true))}
"""
    _write_private(directory / "sshd_config", config)
    _write_private(directory / "endpoint.json", json.dumps({"port": port, "username": username}) + "\n")
    return directory


def client_command(directory):
    endpoint = json.loads((directory / "endpoint.json").read_text())
    return ["ssh", "-T", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={directory / 'known_hosts'}",
            "-i", str(directory / "client_ed25519"), "-p", str(endpoint["port"]),
            f"{endpoint['username']}@127.0.0.1"]


class CaptureWriter:
    """Append bounded private records, keeping one rotated backup on disk."""

    def __init__(self, path):
        self.path = path
        self.stream = None

    def open(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("SSH capture output must be a private regular file owned by you.")
            self.stream = os.fdopen(fd, "ab", buffering=0)
        except BaseException:
            os.close(fd)
            raise

    def write(self, message, hostname, observed_at):
        record = {"version": 1, "observed_at": observed_at.isoformat(),
                  "hostname": hostname, "message": message}
        encoded = (json.dumps(record, ensure_ascii=True) + "\n").encode("utf-8")
        if self.stream is None:
            self.open()
        if os.fstat(self.stream.fileno()).st_size + len(encoded) > MAX_CAPTURE_BYTES:
            backup = self.path.with_name(self.path.name + ".1")
            if backup.exists() or backup.is_symlink():
                _check_private(backup)
            self.close()
            _check_private(self.path)
            os.replace(self.path, backup)
            self.open()
        remaining = memoryview(encoded)
        while remaining:
            written = self.stream.write(remaining)
            if not written:
                raise OSError("Could not finish writing the SSH capture record.")
            remaining = remaining[written:]

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None


def _stop(process):
    """Stop only the process group this capture command started."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def serve(directory: Path, database: Path, name: str, timezone_name: str):
    directory = directory.absolute()
    _check_private(directory, directory=True)
    config = directory / "sshd_config"
    _check_private(config)
    executable = _binary("sshd")
    login_command = client_command(directory)
    # Validate keys/config and runtime requirements before registering a source.
    preflight = subprocess.run([executable, "-t", "-f", str(config)], capture_output=True, timeout=15)
    if preflight.returncode:
        raise ValueError("OpenSSH configuration check failed: " + preflight.stderr.decode(errors="replace").strip())
    lock_path = directory / "capture.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        _check_private(lock_path)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("SSH capture is already running for this directory.") from error
        path = directory / "observed.jsonl"
        writer = CaptureWriter(path)
        try:
            writer.open()
            with open_store(database) as db:
                prior = db.execute("SELECT year FROM sources WHERE name=?", (name,)).fetchone()
                year = prior["year"] if prior else datetime.now(timezone.utc).year
                source = Source(name, path, "sshd_capture", year, timezone_name, socket.gethostname())
                register_source(db, source)
            process = subprocess.Popen([executable, "-D", "-e", "-f", str(config)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                print(f"Capturing OpenSSH output as source {name}. Keep the file collector running.", flush=True)
                print("Login check (exits immediately after authenticating):\n" + shlex.join(login_command), flush=True)
                while True:
                    raw = process.stderr.readline(MAX_MESSAGE_BYTES + 1)
                    if not raw:
                        break
                    if len(raw) > MAX_MESSAGE_BYTES:
                        raise ValueError("OpenSSH output exceeded 8 KiB per message; capture stopped.")
                    message = raw.decode("utf-8", errors="backslashreplace").removesuffix("\n").removesuffix("\r")
                    writer.write(message, source.hostname, datetime.now(timezone.utc))
                    print(_safe_text(message), flush=True)
                return process.wait()
            finally:
                _stop(process)
                process.stderr.close()
        finally:
            writer.close()
    finally:
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("setup", help="Generate private keys and loopback-only SSH configuration")
    prepare.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    prepare.add_argument("--port", type=int, default=2222)
    prepare.add_argument("--user", default=pwd.getpwuid(os.getuid()).pw_name)
    run = commands.add_parser("serve", help="Run actual sshd and capture its output")
    run.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    run.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    run.add_argument("--name", default="local-ssh")
    run.add_argument("--timezone", default="Africa/Lagos", help="Login-policy timezone (capture times include a UTC offset)")
    args = parser.parse_args(argv)
    previous_handler = signal.getsignal(signal.SIGTERM)
    def stop_requested(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop_requested)
    try:
        if args.command == "setup":
            directory = setup(args.directory, args.port, args.user)
            print(f"SSH configuration created in {directory}. Start with python3 -m logsentry.ssh_capture serve")
            print("Login check:\n" + shlex.join(client_command(directory)))
            return 0
        return serve(args.directory, args.database, args.name, args.timezone)
    except KeyboardInterrupt:
        print("\nSSH capture stopped.")
        return 0
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"SSH capture failed: {_safe_text(error)}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
