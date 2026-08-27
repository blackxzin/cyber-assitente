"""Audio: STT via faster-whisper e TTS.

STT: 100% local (faster-whisper). TTS: voz feminina pt-BR via Edge-TTS
(Microsoft, natural, grátis) com fallback para espeak-ng se sem internet.
"""

import asyncio
import io
import wave

from security.sanitize import sanitize_text
from security.tempfiles import secure_tmp_path

# Voz feminina pt-BR (Edge-TTS). "Francisca" = voz natural Microsoft.
_TTS_VOICE = "pt-BR-FranciscaNeural"
_TTS_FALLBACK = "pt-br"  # espeak-ng se offline

# Modelo whisper local (baixado na primeira execução).
# small = multilíngue, bom pt-BR; cpu_int8 roda em CPU sem CUDA.
_STT_MODEL = "small"
_STT_COMPUTE = "int8"

_model = None  # carregado preguiçosamente


def _get_model():
    """Carrega o modelo whisper uma única vez (custoso)."""
    global _model
    if _model is None:
        from faster_whisper import WhisperModel
        _model = WhisperModel(_STT_MODEL, compute_type=_STT_COMPUTE)
    return _model


def _to_wav_pcm(data: bytes) -> bytes:
    """Decodifica qualquer formato (webm/opus/wav) via PyAV → WAV 16kHz mono."""
    import av
    buf = io.BytesIO()
    with wave.open(buf, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(16000)
        container = av.open(io.BytesIO(data))
        resampler = av.AudioResampler(format="s16", layout="mono", rate=16000)
        for frame in container.decode(audio=0):
            for rf in resampler.resample(frame):
                out.writeframes(rf.to_ndarray().tobytes())
        for rf in resampler.resample(None):  # flush do resampler (essencial)
            out.writeframes(rf.to_ndarray().tobytes())
        container.close()
    return buf.getvalue()


async def transcribe_audio(data: bytes) -> str:
    """Transcreve áudio (webm/wav/qualquer) com o whisper local."""
    model = await asyncio.to_thread(_get_model)
    wav = await asyncio.to_thread(_to_wav_pcm, data)

    def _do():
        segments, _ = model.transcribe(io.BytesIO(wav), language="pt")
        return " ".join(s.text for s in segments).strip()

    text = await asyncio.to_thread(_do)
    return sanitize_text(text)


async def speak_to_wav(text: str) -> bytes:
    """Gera WAV de fala em pt-BR.

    Tenta Edge-TTS (voz feminina natural). Se falhar (sem internet), faz
    fallback para espeak-ng local. Levanta RuntimeError se ambos falharem.
    """
    text = sanitize_text(text)

    # 1. Tenta Edge-TTS (voz feminina, natural)
    try:
        wav = await _speak_edge_tts(text)
        return wav
    except Exception as exc:
        from security.logging import log_event
        log_event("warning", "tts_fallback", f"Edge-TTS falhou, usando espeak-ng: {exc}")

    # 2. Fallback: espeak-ng local
    tmp = secure_tmp_path(".wav", prefix="cyber_tts_")
    proc = await asyncio.create_subprocess_exec(
        "espeak-ng", "-v", _TTS_FALLBACK, "-w", str(tmp), text,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        await asyncio.wait_for(proc.communicate(), 30)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError("TTS excedeu 30s")
    if proc.returncode != 0 or not tmp.exists():
        raise RuntimeError("espeak-ng falhou ao gerar áudio")
    wav = tmp.read_bytes()
    tmp.unlink(missing_ok=True)
    return wav


async def _speak_edge_tts(text: str) -> bytes:
    """Sintetiza com Edge-TTS (voz feminina pt-BR) e devolve o MP3."""
    import edge_tts
    communicate = edge_tts.Communicate(text, _TTS_VOICE)
    chunks = bytearray()
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            chunks.extend(chunk["data"])
    if not chunks:
        raise RuntimeError("Edge-TTS retornou áudio vazio")
    return bytes(chunks)
