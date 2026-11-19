"""Audio helpers.  Messages are plain mono 16-bit WAV files (16 kHz)."""
from __future__ import annotations

import io
import math
import struct
import wave

RATE = 16000


def pcm_to_wav(pcm: bytes, rate: int = RATE, channels: int = 1) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def make_test_wav(seconds: float = 2.0, rate: int = RATE, freq: float = 440.0) -> bytes:
    """A sine tone: lets you test the whole system without a microphone."""
    n = int(seconds * rate)
    pcm = b"".join(struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate)))
                   for i in range(n))
    return pcm_to_wav(pcm, rate)


def record_wav(seconds: float, rate: int = RATE) -> bytes:
    import sounddevice as sd            # imported lazily so tests need no audio device
    audio = sd.rec(int(seconds * rate), samplerate=rate, channels=1, dtype="int16")
    sd.wait()
    return pcm_to_wav(audio.tobytes(), rate)


def play_wav(wav_bytes: bytes) -> None:
    import numpy as np
    import sounddevice as sd
    with wave.open(io.BytesIO(wav_bytes)) as w:
        rate, ch = w.getframerate(), w.getnchannels()
        data = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    sd.play(data.reshape(-1, ch), rate)
    sd.wait()


def wav_duration(wav_bytes: bytes) -> float:
    with wave.open(io.BytesIO(wav_bytes)) as w:
        return w.getnframes() / w.getframerate()
