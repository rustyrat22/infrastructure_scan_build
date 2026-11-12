"""Shared process and filesystem hardening helpers for Flash_Network.

The scripts in this repository run untrusted remote commands through plink and
parse packet data from the local network.  Keeping the security-sensitive
helpers in one module means every script gets the same timeouts, output caps,
process-tree cleanup, restrictive permissions, trusted-tool resolution, and
console sanitisation.
"""

import locale
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import unicodedata
from collections import namedtuple


# A single command must never be able to grow memory without bound.
DEFAULT_MAX_STDOUT = 4 * 1024 * 1024
DEFAULT_MAX_STDERR = 1 * 1024 * 1024

ProcessResult = namedtuple(
    "ProcessResult",
    "stdout stderr returncode timed_out stdout_truncated stderr_truncated",
)

_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"          # CSI sequences
    r"|\x1b\][^\x07]*(?:\x07|\x1b\\)"    # OSC sequences
    r"|\x1b[@-_]"                        # other two-byte escapes
)

# Bidi overrides can make console output look like something it is not.
_BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


class _BoundedBuffer:
    """Thread-safe byte buffer that keeps only the first *limit* bytes."""

    def __init__(self, limit):
        self._limit = max(0, int(limit))
        self._data = bytearray()
        self._truncated = False
        self._lock = threading.Lock()

    def append(self, chunk):
        if not chunk:
            return
        with self._lock:
            remaining = self._limit - len(self._data)
            if remaining > 0:
                self._data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._truncated = True
            else:
                self._truncated = True

    def snapshot(self):
        with self._lock:
            return bytes(self._data), self._truncated


def _reader(stream, buffer):
    """Drain *stream* into *buffer* until EOF without ever blocking forever."""
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            buffer.append(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _kill_process_tree(process):
    """Terminate *process* and every child it spawned."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe"
        )
        command = [taskkill if os.path.isfile(taskkill) else "taskkill",
                   "/F", "/T", "/PID", str(process.pid)]
        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            process.kill()
        except OSError:
            pass
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass


def run_bounded(command, timeout=60, max_stdout=DEFAULT_MAX_STDOUT,
                max_stderr=DEFAULT_MAX_STDERR, stdin_data=None, cwd=None,
                env=None, encoding=None):
    """Run *command* with a timeout and capped stdout/stderr.

    The child is started in its own process group/session so a timeout can
    terminate the whole process tree rather than just the direct child.  Output
    is drained continuously; once a cap is reached the excess is discarded so
    the child never blocks on a full pipe.
    """
    if encoding is None:
        encoding = locale.getpreferredencoding(False) or "utf-8"

    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        "cwd": cwd,
        "env": env,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(command, **popen_kwargs)

    stdout_buffer = _BoundedBuffer(max_stdout)
    stderr_buffer = _BoundedBuffer(max_stderr)
    stdout_thread = threading.Thread(
        target=_reader, args=(process.stdout, stdout_buffer), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_reader, args=(process.stderr, stderr_buffer), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    if stdin_data is not None:
        try:
            data = stdin_data.encode(encoding) if isinstance(stdin_data, str) else stdin_data
            process.stdin.write(data)
            process.stdin.close()
        except (OSError, ValueError):
            pass

    timed_out = False
    try:
        process.wait(timeout=timeout if timeout and timeout > 0 else None)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_tree(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    # Give the reader threads a chance to drain.  A grandchild that inherited
    # the pipes can keep them open, so never wait forever here.
    stdout_thread.join(5)
    stderr_thread.join(5)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    stdout_bytes, stdout_truncated = stdout_buffer.snapshot()
    stderr_bytes, stderr_truncated = stderr_buffer.snapshot()
    returncode = process.returncode if process.returncode is not None else -1

    return ProcessResult(
        stdout_bytes.decode(encoding, "replace"),
        stderr_bytes.decode(encoding, "replace"),
        returncode,
        timed_out,
        stdout_truncated,
        stderr_truncated,
    )


# --- Filesystem permissions ------------------------------------------------

def _windows_user():
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def _set_windows_acl(path, directory):
    user = _windows_user()
    if not user:
        raise OSError("Cannot determine the current Windows user for ACL tightening")
    grant = f"{user}:(OI)(CI)F" if directory else f"{user}:F"
    # Resolve icacls from System32 so a planted icacls.exe in the working
    # directory (or a non-absolute PATH entry) cannot run with our privileges.
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    icacls = os.path.join(system_root, "System32", "icacls.exe")
    if not os.path.isfile(icacls):
        icacls = "icacls"
    command = [icacls, path, "/inheritance:r", "/grant:r", grant]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"Failed to run icacls on {path!r}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise OSError(
            f"Failed to restrict ACL on {path!r}: {detail or 'icacls failed'}"
        )


def secure_output_dir(path):
    """Create *path* if needed and restrict it to the current user.

    Existing directories are tightened too: a scan must not inherit broad
    permissions from a directory that was created by an earlier version.
    """
    os.makedirs(path, exist_ok=True)
    if os.name == "nt":
        _set_windows_acl(path, True)
    else:
        os.chmod(path, 0o700)
    return path


def secure_file(path):
    """Restrict *path* to the current user (0600 / owner-only ACL)."""
    if os.name == "nt":
        _set_windows_acl(path, False)
    else:
        os.chmod(path, 0o600)
    return path


def create_secure_temp_file(prefix="flashnet_", suffix=""):
    """Create a private temp file and return ``(fd, path)``."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    try:
        secure_file(path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return fd, path


# --- Trusted tool resolution ----------------------------------------------

def _is_within(path, directory):
    try:
        return os.path.commonpath([path, directory]) == directory
    except ValueError:
        return False


def resolve_tool(name):
    """Resolve *name* to a trusted absolute executable path, or ``None``.

    Only absolute PATH entries are considered, and any candidate inside the
    current working directory is rejected.  This prevents a dropped
    ``plink.exe``/``tshark.exe`` in the scan directory from being executed.
    """
    if not name:
        return None
    cwd = os.path.realpath(os.getcwd())
    # Running from a drive/filesystem root is not a plausible download
    # directory; otherwise every absolute path would look "inside cwd".
    cwd_is_root = os.path.dirname(cwd) == cwd
    names = [name]
    if os.name == "nt" and not name.lower().endswith(".exe"):
        names.append(name + ".exe")

    search_dirs = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        search_dirs.append(entry)

    # Windows built-ins are normally on PATH, but fall back to System32 so a
    # damaged PATH cannot make the scripts silently unusable.
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        search_dirs.append(os.path.join(system_root, "System32"))

    seen = set()
    for directory in search_dirs:
        key = os.path.normcase(os.path.realpath(directory))
        if key in seen:
            continue
        seen.add(key)
        if not cwd_is_root and _is_within(key, cwd):
            continue
        for candidate_name in names:
            candidate = os.path.join(directory, candidate_name)
            if not os.path.isfile(candidate):
                continue
            full = os.path.realpath(candidate)
            if not cwd_is_root and _is_within(full, cwd):
                continue
            if os.name != "nt" and not os.access(full, os.X_OK):
                continue
            return full
    return None


# --- Console sanitisation -------------------------------------------------

def sanitize_console_text(value, max_length=200):
    """Strip escape sequences, control characters, and bidi overrides.

    Remote hostnames, HTTP headers, package names, and command output can all
    contain bytes chosen by an attacker.  Printing them verbatim lets an
    attacker manipulate the operator's terminal.
    """
    if value is None:
        return ""
    text = str(value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    cleaned = []
    for char in text:
        if char in ("\t",):
            cleaned.append(" ")
        elif char in ("\r", "\n"):
            cleaned.append(" ")
        elif unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            cleaned.append(char)
    text = "".join(cleaned)
    if max_length is not None and len(text) > max_length:
        text = text[:max_length]
    return text


def sanitize_console_block(value, max_length=None):
    """Like :func:`sanitize_console_text` but preserves line structure.

    Use this for command output that is deliberately displayed to the
    operator; escape sequences and invisible controls are still removed.
    """
    if value is None:
        return ""
    text = str(value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    cleaned = []
    for char in text:
        if char in ("\n", "\t"):
            cleaned.append(char)
        elif char == "\r":
            continue
        elif unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            cleaned.append(char)
    text = "".join(cleaned)
    if max_length is not None and len(text) > max_length:
        text = text[:max_length]
    return text
