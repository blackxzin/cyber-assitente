"""Testes de security/tempfiles.py — path de temp seguro (mkstemp),
usado no lugar de nomes fixos/previsíveis em /tmp (CWE-377)."""

from pathlib import Path

from security.tempfiles import secure_tmp_path


def test_secure_tmp_path_creates_unique_file_with_suffix():
    p1 = secure_tmp_path(".pcapng", prefix="cyber_cap_")
    p2 = secure_tmp_path(".pcapng", prefix="cyber_cap_")
    try:
        assert p1 != p2
        assert p1.exists() and p2.exists()
        assert p1.suffix == ".pcapng"
        assert p1.name.startswith("cyber_cap_")
    finally:
        p1.unlink(missing_ok=True)
        p2.unlink(missing_ok=True)


def test_secure_tmp_path_returns_path_instance():
    p = secure_tmp_path(".wav")
    try:
        assert isinstance(p, Path)
    finally:
        p.unlink(missing_ok=True)
