"""Testes de integração real de backend/tools/reverse.py: compila um
binário ELF mínimo de teste e roda file/strings/objdump/readelf/nm de
verdade contra ele. Marcados 'integration' (mesmo motivo de
test_pentest_integration.py — fora do pytest padrão e do CI).

    pytest -m integration tests/test_reverse_integration.py
"""

import shutil
import subprocess  # nosec B404 — só usado no setup do teste (gcc), não em código de produção

import pytest

from tools.reverse import (
    tool_re_disasm,
    tool_re_file_info,
    tool_re_headers,
    tool_re_strings,
    tool_re_symbols,
    tool_re_yara_scan,
)

pytestmark = pytest.mark.integration

_SOURCE = """
#include <stdio.h>
const char *marker = "CYBER_REVERSE_TEST_MARKER_xyz789";
int named_function(int x) { return x * 2; }
int main(void) {
    printf("%s %d\\n", marker, named_function(21));
    return 0;
}
"""


@pytest.fixture
def compiled_binary(tmp_path):
    src = tmp_path / "sample.c"
    src.write_text(_SOURCE)
    binary = tmp_path / "sample"
    subprocess.run(  # nosec B603 B607 — argv fixo, sem input externo, só setup de teste
        ["gcc", "-O0", "-g", str(src), "-o", str(binary)],
        check=True, capture_output=True,
    )
    return binary


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("file") is None,
                     reason="gcc/file não instalados")
async def test_re_file_info_identifies_elf(compiled_binary):
    out = await tool_re_file_info({"path": str(compiled_binary)})
    assert "ELF" in out


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("strings") is None,
                     reason="gcc/strings não instalados")
async def test_re_strings_finds_embedded_marker(compiled_binary):
    out = await tool_re_strings({"path": str(compiled_binary), "filter": "CYBER_REVERSE_TEST_MARKER"})
    assert "CYBER_REVERSE_TEST_MARKER_xyz789" in out


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("nm") is None,
                     reason="gcc/nm não instalados")
async def test_re_symbols_lists_named_function(compiled_binary):
    out = await tool_re_symbols({"path": str(compiled_binary)})
    assert "named_function" in out


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("readelf") is None,
                     reason="gcc/readelf não instalados")
async def test_re_headers_shows_elf_header(compiled_binary):
    # readelf/nm seguem o locale do sistema (aqui saiu em pt-BR: "Cabeçalho ELF") —
    # checa pelos bytes mágicos ELF em vez de string de rótulo dependente de idioma.
    out = await tool_re_headers({"path": str(compiled_binary)})
    assert "7f 45 4c 46" in out.lower()


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("objdump") is None,
                     reason="gcc/objdump não instalados")
async def test_re_disasm_of_named_function(compiled_binary):
    out = await tool_re_disasm({"path": str(compiled_binary), "symbol": "named_function"})
    assert "named_function" in out


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("yara") is None,
                     reason="gcc/yara não instalados")
async def test_re_yara_scan_matches_real_rule_against_embedded_marker(compiled_binary, tmp_path):
    rules = tmp_path / "test.yar"
    rules.write_text("""
rule cyber_test_marker {
    strings:
        $marker = "CYBER_REVERSE_TEST_MARKER_xyz789"
    condition:
        $marker
}
""")
    out = await tool_re_yara_scan({"path": str(compiled_binary), "rules": str(rules)})
    assert "cyber_test_marker" in out
    assert not out.lower().startswith("erro")


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("yara") is None,
                     reason="gcc/yara não instalados")
async def test_re_yara_scan_no_match_against_real_binary(compiled_binary, tmp_path):
    rules = tmp_path / "test.yar"
    rules.write_text("""
rule never_matches {
    strings:
        $x = "STRING_QUE_NAO_EXISTE_NO_BINARIO_abc123"
    condition:
        $x
}
""")
    out = await tool_re_yara_scan({"path": str(compiled_binary), "rules": str(rules)})
    assert "nenhuma regra casou" in out
