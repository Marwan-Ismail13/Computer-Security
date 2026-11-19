"""Integration tests: real TCP sockets on localhost, two nodes, both directions."""
import socket
import time

import pytest

from securevoice.audio import make_test_wav, wav_duration
from securevoice.crypto_layers import (SecureSender, create_handshake,
                                       generate_rsa_keypair)
from securevoice.node import Node
from securevoice.protocol import (HANDSHAKE, MAX_FRAME, MESSAGE, HEADER,
                                  read_frame, write_frame)


def wait_for(pred, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture(scope="module")
def keys():
    return {"a": generate_rsa_keypair(), "b": generate_rsa_keypair(),
            "evil": generate_rsa_keypair()}


class Rig:
    """Two nodes (A = source, B = destination); each records what it received."""
    def __init__(self, keys, tmp_path):
        self.events_a, self.events_b = [], []
        self.got_a, self.got_b = [], []
        self.a = Node(keys["a"], keys["b"].public_key(), "127.0.0.1", 0, tmp_path / "ia",
                      on_message=lambda p, d: self.got_a.append(d), on_event=self.events_a.append)
        self.b = Node(keys["b"], keys["a"].public_key(), "127.0.0.1", 0, tmp_path / "ib",
                      on_message=lambda p, d: self.got_b.append(d), on_event=self.events_b.append)
        self.a.start(); self.b.start()

    def stop(self):
        self.a.stop(); self.b.stop()


@pytest.fixture
def rig(keys, tmp_path):
    r = Rig(keys, tmp_path)
    yield r
    r.stop()


def raw_session(port, priv, peer_pub):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    _, challenge = read_frame(s)
    k, hs = create_handshake(priv, peer_pub, challenge)
    write_frame(s, HANDSHAKE, hs)
    return s, SecureSender(k), hs


# ---- normal operation -----------------------------------------------------
def test_one_direction_a_to_b(rig):
    wav = make_test_wav(1)
    rig.a.send("127.0.0.1", rig.b.port, wav)
    assert wait_for(lambda: rig.got_b) and rig.got_b[0] == wav


def test_reverse_direction_b_to_a(rig):
    wav = make_test_wav(1, freq=880)
    rig.b.send("127.0.0.1", rig.a.port, wav)
    assert wait_for(lambda: rig.got_a) and rig.got_a[0] == wav


def test_one_minute_voice_message(rig):
    wav = make_test_wav(60)
    assert 59.9 < wav_duration(wav) < 60.1
    rig.a.send("127.0.0.1", rig.b.port, wav)
    assert wait_for(lambda: rig.got_b, timeout=30) and rig.got_b[0] == wav


def test_saved_to_inbox(rig, tmp_path):
    wav = make_test_wav(1)
    rig.a.send("127.0.0.1", rig.b.port, wav)
    assert wait_for(lambda: rig.got_b)
    files = list((tmp_path / "ib").glob("*.wav"))
    assert len(files) == 1 and files[0].read_bytes() == wav


# ---- attacks over the network ---------------------------------------------
def test_tampered_packet_rejected_then_session_continues(rig, keys):
    s, snd, _ = raw_session(rig.b.port, keys["a"], keys["b"].public_key())
    bad = bytearray(snd.encrypt(b"x" * 100)); bad[30] ^= 1
    write_frame(s, MESSAGE, bytes(bad))
    assert wait_for(lambda: any("REJECTED packet" in e for e in rig.events_b))
    assert rig.got_b == []
    write_frame(s, MESSAGE, snd.encrypt(b"good one"))
    assert wait_for(lambda: rig.got_b == [b"good one"])
    s.close()


def test_replayed_packet_in_same_session_rejected(rig, keys):
    s, snd, _ = raw_session(rig.b.port, keys["a"], keys["b"].public_key())
    pkt = snd.encrypt(b"pay 10")
    write_frame(s, MESSAGE, pkt)
    assert wait_for(lambda: len(rig.got_b) == 1)
    write_frame(s, MESSAGE, pkt)
    assert wait_for(lambda: any("ReplayError" in e for e in rig.events_b))
    assert len(rig.got_b) == 1
    s.close()


def test_whole_session_replay_on_new_connection_rejected(rig, keys):
    s, snd, hs = raw_session(rig.b.port, keys["a"], keys["b"].public_key())
    pkt = snd.encrypt(b"recorded by MITM")
    write_frame(s, MESSAGE, pkt)
    assert wait_for(lambda: len(rig.got_b) == 1)
    s.close()
    # attacker replays the recorded handshake + packet on a NEW connection
    s2 = socket.create_connection(("127.0.0.1", rig.b.port), timeout=5)
    read_frame(s2)                         # fresh challenge, different from the recorded one
    write_frame(s2, HANDSHAKE, hs)
    write_frame(s2, MESSAGE, pkt)
    assert wait_for(lambda: any("REJECTED handshake" in e for e in rig.events_b))
    assert len(rig.got_b) == 1
    s2.close()


def test_sender_with_unknown_key_rejected(rig, keys):
    s, snd, _ = raw_session(rig.b.port, keys["evil"], keys["b"].public_key())
    write_frame(s, MESSAGE, snd.encrypt(b"fake"))
    assert wait_for(lambda: any("REJECTED handshake" in e for e in rig.events_b))
    assert rig.got_b == []
    s.close()


def test_garbage_and_oversized_frames_do_not_kill_server(rig):
    for junk in (b"\x00" * 3, HEADER.pack(MESSAGE, MAX_FRAME + 1)):
        s = socket.create_connection(("127.0.0.1", rig.b.port), timeout=5)
        read_frame(s)
        s.sendall(junk)
        s.close()
    wav = make_test_wav(1)
    rig.a.send("127.0.0.1", rig.b.port, wav)       # server still works afterwards
    assert wait_for(lambda: rig.got_b == [wav])
