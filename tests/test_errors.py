"""Testes de security/errors.py — str(exc) vazio não pode virar mensagem em branco."""

from security.errors import describe_exception


def test_exception_with_message_keeps_type_and_message():
    result = describe_exception(ValueError("host inválido"))
    assert result == "ValueError: host inválido"


def test_exception_with_empty_str_falls_back_to_type_name():
    class BlankError(Exception):
        def __str__(self):
            return ""

    result = describe_exception(BlankError())
    assert result == "BlankError"


def test_timeout_error_with_no_args_shows_type_name():
    # asyncio.TimeoutError / httpx.ReadTimeout commonly carry no message.
    result = describe_exception(TimeoutError())
    assert result == "TimeoutError"
