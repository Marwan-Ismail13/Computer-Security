"""A SecureVoice node = listener (receives) + sender (connects out).

Full duplex is achieved by giving every laptop BOTH roles: it listens on its own
port for incoming messages and opens a connection to the peer to send.  Each
direction therefore has its own handshake and its own session keys.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable

from .crypto_layers import (CryptoError, IntegrityError, ReplayError,
                            SecureReceiver, SecureSender, accept_handshake,
                            create_handshake)
from .protocol import (CHALLENGE, HANDSHAKE, MESSAGE, ConnectionClosed,
                       ProtocolError, read_frame, write_frame)

CHALLENGE_LEN = 16


class Node:
    def __init__(self, my_private, peer_public, listen_host: str = "0.0.0.0",
                 listen_port: int = 12347, inbox: str | Path = "inbox",
                 on_message: Callable[[Path, bytes], None] | None = None,
                 on_event: Callable[[str], None] | None = None):
        self._private = my_private
        self._peer_public = peer_public
        self._host, self._port_req = listen_host, listen_port
        self._inbox = Path(inbox)
        self._on_message = on_message or (lambda path, data: None)
        self._on_event = on_event or (lambda text: print(text, flush=True))
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._counter = 0
        self._lock = threading.Lock()
        self.port = listen_port

    # ------------------------------------------------------------ receiving
    def start(self) -> None:
        self._inbox.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":                      # on Windows REUSEADDR would allow port hijacking
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self._host, self._port_req))
        s.listen(5)
        s.settimeout(0.5)
        self._sock = s
        self.port = s.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self._on_event(f"listening on {self._host}:{self.port}")

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn: socket.socket, addr) -> None:
        who = f"{addr[0]}:{addr[1]}"
        with conn:
            conn.settimeout(60)
            try:
                challenge = os.urandom(CHALLENGE_LEN)
                write_frame(conn, CHALLENGE, challenge)
                ftype, hs = read_frame(conn)
                if ftype != HANDSHAKE:
                    raise ProtocolError("expected HANDSHAKE frame")
                keys = accept_handshake(hs, self._private, self._peer_public, challenge)
                receiver = SecureReceiver(keys)
                self._on_event(f"handshake OK with {who}")
                while True:
                    try:
                        ftype, payload = read_frame(conn)
                    except ConnectionClosed:
                        break
                    if ftype != MESSAGE:
                        raise ProtocolError("expected MESSAGE frame")
                    try:
                        data = receiver.decrypt(payload)
                    except (IntegrityError, ReplayError) as exc:   # drop packet, keep session
                        self._on_event(f"REJECTED packet from {who}: "
                                       f"{type(exc).__name__}: {exc}")
                        continue
                    path = self._save(data)
                    self._on_event(f"received {len(data)} bytes from {who} -> {path}")
                    self._on_message(path, data)
            except CryptoError as exc:
                self._on_event(f"REJECTED handshake from {who}: {type(exc).__name__}: {exc}")
            except (ProtocolError, OSError) as exc:
                self._on_event(f"connection problem with {who}: {exc}")

    def _save(self, data: bytes) -> Path:
        with self._lock:
            self._counter += 1
            name = f"msg_{time.strftime('%Y%m%d_%H%M%S')}_{self._counter}.wav"
        path = self._inbox / name
        path.write_bytes(data)
        return path

    # -------------------------------------------------------------- sending
    def send(self, host: str, port: int, data: bytes, timeout: float = 15.0) -> None:
        """Connect, run the handshake, send one encrypted message."""
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(60)
            ftype, challenge = read_frame(s)
            if ftype != CHALLENGE:
                raise ProtocolError("expected CHALLENGE frame")
            keys, hs = create_handshake(self._private, self._peer_public, challenge)
            write_frame(s, HANDSHAKE, hs)
            write_frame(s, MESSAGE, SecureSender(keys).encrypt(data))
