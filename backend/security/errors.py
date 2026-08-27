"""Exception formatting for user-facing/log messages.

str(exc) is empty for several stdlib exceptions raised with no message
(httpx.ReadTimeout, asyncio.TimeoutError, ...) — always including the type
name keeps "algo falhou: " from ever rendering as a blank, undiagnosable
message.
"""


def describe_exception(exc: BaseException) -> str:
    msg = str(exc)
    return f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__
