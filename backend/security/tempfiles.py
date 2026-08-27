"""Secure temp-file creation.

Plain f"/tmp/name_{x}" paths are guessable and let another local user
pre-create a symlink at that path before we write to it (CWE-377: the
external process we spawn — dumpcap, espeak-ng — would then follow the
symlink and write through it). tempfile.mkstemp() opens with O_CREAT|O_EXCL
on a random name, so the path can't be pre-planted.
"""

import os
import tempfile
from pathlib import Path


def secure_tmp_path(suffix: str, prefix: str = "cyber_") -> Path:
    """Reserve a fresh, unpredictable temp path (0600, not yet closed by
    caller-relevant tools). We only need the *name* — the file is closed
    immediately and the external tool (re)writes it."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)
    return Path(path)
