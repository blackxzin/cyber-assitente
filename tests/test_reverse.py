"""Testes de backend/tools/reverse.py (engenharia reversa de binário local).

Igual test_pentest.py: `_run` é mockado, só valida path/args/argv aqui —
binário real (file/strings/objdump/readelf/nm/r2) é coberto em
test_reverse_integration.py.
"""

import pytest

from tools import reverse
from tools.reverse import (
    tool_re_analyze,
    tool_re_disasm,
    tool_re_file_info,
    tool_re_headers,
    tool_re_strings,
    tool_re_symbols,
)


async def test_re_file_info_rejects_missing_path():
    result = await tool_re_file_info({})
    assert result.startswith("Uso:")


async def test_re_file_info_rejects_nonexistent_file():
    result = await tool_re_file_info({"path": "/tmp/nao-existe-xyz-123"})
    assert result.startswith("arquivo não encontrado")


async def test_re_file_info_rejects_directory(tmp_path):
    result = await tool_re_file_info({"path": str(tmp_path)})
    assert result.startswith("arquivo não encontrado")


async def test_re_file_info_rejects_oversized_file(tmp_path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(b"\x00")
    monkeypatch.setattr(reverse, "_MAX_FILE_SIZE", 0)
    result = await tool_re_file_info({"path": str(f)})
    assert result.startswith("arquivo grande demais")


async def test_re_file_info_runs_real_file_command(tmp_path, monkeypatch):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 20)
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        return "ELF 64-bit LSB executable"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_file_info({"path": str(f)})
    assert result == "ELF 64-bit LSB executable"
    assert captured["argv"] == ["file", "-b", str(f)]


async def test_re_strings_returns_output(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"hello world")

    async def fake_run(argv, timeout=None):
        return "hello world\nsecret-looking-thing\n"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_strings({"path": str(f)})
    assert "hello world" in result


async def test_re_strings_filters_by_term(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")

    async def fake_run(argv, timeout=None):
        return "http://evil.example/payload\nirrelevant line\nANOTHER http url here\n"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_strings({"path": str(f), "filter": "http"})
    assert "http://evil.example/payload" in result
    assert "ANOTHER http url here" in result
    assert "irrelevant line" not in result


async def test_re_strings_filter_with_no_match(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")

    async def fake_run(argv, timeout=None):
        return "just some ordinary text\n"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_strings({"path": str(f), "filter": "nada-bate-aqui"})
    assert "nenhuma string casando" in result


async def test_re_strings_clamps_min_len(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        return "ok"

    monkeypatch.setattr(reverse, "_run", fake_run)
    await tool_re_strings({"path": str(f), "min_len": 999})
    assert captured["argv"][:2] == ["strings", "-n"]
    assert captured["argv"][2] == "32"  # clamped ao teto


async def test_re_symbols_falls_back_to_readelf_when_stripped(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    calls = []

    async def fake_run(argv, timeout=None):
        calls.append(argv[0])
        if argv[0] == "nm":
            return "nm: s.bin: no symbols"
        return "Symbol table via readelf"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_symbols({"path": str(f)})
    assert result == "Symbol table via readelf"
    assert calls == ["nm", "readelf"]


async def test_re_symbols_returns_nm_output_directly_when_present(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")

    async def fake_run(argv, timeout=None):
        return "0000000000001139 T main"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_symbols({"path": str(f)})
    assert "main" in result


async def test_re_headers_rejects_missing_path():
    result = await tool_re_headers({})
    assert result.startswith("Uso:")


async def test_re_disasm_includes_symbol_flag_when_given(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        return "disasm output"

    monkeypatch.setattr(reverse, "_run", fake_run)
    await tool_re_disasm({"path": str(f), "symbol": "main"})
    assert "--disassemble=main" in captured["argv"]
    assert "-M" in captured["argv"] and "intel" in captured["argv"]


async def test_re_disasm_without_symbol_disassembles_everything(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        return "full disasm"

    monkeypatch.setattr(reverse, "_run", fake_run)
    await tool_re_disasm({"path": str(f)})
    assert not any(a.startswith("--disassemble=") for a in captured["argv"])


async def test_re_analyze_handles_missing_binary_gracefully(tmp_path, monkeypatch):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")

    async def fake_run(argv, timeout=None):
        return "erro: ferramenta não encontrada (r2)"

    monkeypatch.setattr(reverse, "_run", fake_run)
    result = await tool_re_analyze({"path": str(f)})
    assert result.startswith("erro:")


async def test_run_missing_binary_returns_friendly_error():
    result = await reverse._run(["nao-existe-binario-xyz-re"])
    assert result == "erro: ferramenta não encontrada (nao-existe-binario-xyz-re)"
