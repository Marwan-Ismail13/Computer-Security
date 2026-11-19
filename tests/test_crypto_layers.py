"""Unit tests for the three crypto layers (rubric: >= 5 cases)."""
import os

import pytest

from securevoice.crypto_layers import (HandshakeError, IntegrityError,
                                       ReplayError, SecureReceiver,
                                       SecureSender, accept_handshake,
                                       create_handshake, fingerprint,
                                       generate_rsa_keypair)


@pytest.fixture(scope="module")
def rsa_keys():
    return {"src": generate_rsa_keypair(), "dst": generate_rsa_keypair(),
            "mitm": generate_rsa_keypair()}


@pytest.fixture
def pair(rsa_keys):
    keys, hs = create_handshake(rsa_keys["src"], rsa_keys["dst"].public_key())
    rx_keys = accept_handshake(hs, rsa_keys["dst"], rsa_keys["src"].public_key())
    return SecureSender(keys), SecureReceiver(rx_keys)


# ---- Case 1-3: correctness ------------------------------------------------
def test_roundtrip_small(pair):
    s, r = pair
    assert r.decrypt(s.encrypt(b"hello voice")) == b"hello voice"


def test_roundtrip_one_minute_audio_size(pair):
    s, r = pair
    audio = os.urandom(16000 * 2 * 60)          # 16 kHz, 16-bit, mono, 60 s
    assert r.decrypt(s.encrypt(audio)) == audio


def test_empty_message(pair):
    s, r = pair
    assert r.decrypt(s.encrypt(b"")) == b""


def test_multiple_messages_in_order(pair):
    s, r = pair
    for i in range(5):
        msg = f"message {i}".encode()
        assert r.decrypt(s.encrypt(msg)) == msg


# ---- Case 4-5: confidentiality -------------------------------------------
def test_same_plaintext_gives_different_ciphertext(pair):
    s, _ = pair
    assert s.encrypt(b"same") != s.encrypt(b"same")


def test_plaintext_not_visible_in_packet(pair):
    s, _ = pair
    secret = b"TOP-SECRET-VOICE" * 10
    assert secret[:16] not in s.encrypt(secret)


# ---- Case 6-9: active attacks (integrity / replay) -----------------------
@pytest.mark.parametrize("pos", [0, 8, 24, -1])   # seq, IV, ciphertext, tag
def test_any_flipped_byte_is_detected(pair, pos):
    s, r = pair
    p = bytearray(s.encrypt(b"important"))
    p[pos] ^= 0xFF
    with pytest.raises(IntegrityError):
        r.decrypt(bytes(p))


def test_replay_rejected(pair):
    s, r = pair
    p = s.encrypt(b"pay 10")
    r.decrypt(p)
    with pytest.raises(ReplayError):
        r.decrypt(p)


def test_truncated_packet_rejected(pair):
    s, r = pair
    with pytest.raises(IntegrityError):
        r.decrypt(s.encrypt(b"data")[:20])


def test_wrong_session_keys_rejected(rsa_keys, pair):
    s, _ = pair
    k2, hs2 = create_handshake(rsa_keys["src"], rsa_keys["dst"].public_key())
    other = SecureReceiver(accept_handshake(hs2, rsa_keys["dst"], rsa_keys["src"].public_key()))
    with pytest.raises(IntegrityError):
        other.decrypt(s.encrypt(b"x"))


# ---- Case 10-12: handshake ------------------------------------------------
def test_handshake_keys_match(rsa_keys):
    keys, hs = create_handshake(rsa_keys["src"], rsa_keys["dst"].public_key())
    assert accept_handshake(hs, rsa_keys["dst"], rsa_keys["src"].public_key()) == keys


def test_forged_handshake_from_mitm_rejected(rsa_keys):
    _, forged = create_handshake(rsa_keys["mitm"], rsa_keys["dst"].public_key())
    with pytest.raises(HandshakeError):
        accept_handshake(forged, rsa_keys["dst"], rsa_keys["src"].public_key())


def test_tampered_handshake_rejected(rsa_keys):
    _, hs = create_handshake(rsa_keys["src"], rsa_keys["dst"].public_key())
    bad = bytearray(hs); bad[10] ^= 1
    with pytest.raises(HandshakeError):
        accept_handshake(bytes(bad), rsa_keys["dst"], rsa_keys["src"].public_key())


def test_fingerprint_is_stable_and_unique(rsa_keys):
    a, b = rsa_keys["src"].public_key(), rsa_keys["dst"].public_key()
    assert fingerprint(a) == fingerprint(a) != fingerprint(b)


# ---- Case 13: challenge binding (blocks replay of a whole recorded session) ----
def test_handshake_bound_to_challenge(rsa_keys):
    _, hs = create_handshake(rsa_keys["src"], rsa_keys["dst"].public_key(), b"challenge-1")
    with pytest.raises(HandshakeError):
        accept_handshake(hs, rsa_keys["dst"], rsa_keys["src"].public_key(), b"challenge-2")
