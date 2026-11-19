"""Tiny length-prefixed framing for TCP:  | type 1B | length 4B | payload |

Frame types of one secure session (receiver = server, sender = client):

    server -> client   CHALLENGE   16 random bytes (fresh per connection)
    client -> server   HANDSHAKE   RSA-wrapped session keys + signature (see crypto_layers)
    client -> server   MESSAGE     one encrypted+authenticated packet (repeatable)
"""
from __future__ import annotations

import socket
import struct

CHALLENGE = 1
HANDSHAKE = 2
MESSAGE = 3

HEADER = struct.Struct(">BI")
MAX_FRAME = 64 * 1024 * 1024          # 64 MB: far above 1 minute of WAV audio


class ProtocolError(Exception):
    """Malformed or unexpected data on the wire."""


class ConnectionClosed(Exception):
    """Peer closed the connection cleanly between two frames."""


def recv_exact(sock: socket.socket, n: int, at_boundary: bool = False) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            if at_boundary and not buf:
                raise ConnectionClosed()
            raise ProtocolError("connection closed in the middle of a frame")
        buf += chunk
    return bytes(buf)


def write_frame(sock: socket.socket, ftype: int, payload: bytes) -> None:
    sock.sendall(HEADER.pack(ftype, len(payload)) + payload)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    ftype, length = HEADER.unpack(recv_exact(sock, HEADER.size, at_boundary=True))
    if length > MAX_FRAME:
        raise ProtocolError(f"frame too large ({length} bytes)")
    return ftype, recv_exact(sock, length)
