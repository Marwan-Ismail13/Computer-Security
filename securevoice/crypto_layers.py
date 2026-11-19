r"""
Three sequential cryptographic layers for SecureVoice.

    Layer 1  RSA-2048 (OAEP + PSS)  - key exchange and sender authentication
    Layer 2  AES-256-CBC            - confidentiality of the voice data
    Layer 3  HMAC-SHA256            - integrity / authenticity of every packet

Sending a message goes through the layers in this order:

    plaintext --(PKCS7 pad)--> AES-256-CBC --> HMAC-SHA256 --> packet
    (AES and HMAC keys were delivered earlier, wrapped by RSA in the handshake)

Packet format (encrypt-then-MAC):

    | seq (8 B) | IV (16 B) | ciphertext (n*16 B) | HMAC tag (32 B) |
      \_________ authenticated by the HMAC tag ________/

Defences built in:
    * eavesdropping      -> AES-CBC with a fresh random IV per packet
    * tampering          -> HMAC is verified BEFORE decrypting anything
    * replay             -> monotonically increasing sequence number
    * key substitution   -> handshake is signed with the sender's RSA key and
                            checked against a pinned (pre-shared) public key
    * reflection         -> one session (own keys) per direction
    * session replay     -> receiver's random challenge is signed into the handshake
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------- constants
RSA_KEY_BITS = 2048
AES_KEY_LEN = 32      # AES-256
MAC_KEY_LEN = 32      # HMAC-SHA256 key
IV_LEN = 16           # AES block size
TAG_LEN = 32          # SHA-256 output
SEQ_LEN = 8           # 64-bit sequence number
BLOCK = 16
MIN_PACKET = SEQ_LEN + IV_LEN + BLOCK + TAG_LEN


# --------------------------------------------------------------- exceptions
class CryptoError(Exception):
    """Base class for all errors raised by this module."""


class HandshakeError(CryptoError):
    """Key exchange failed (bad signature, wrong key, corrupted data)."""


class IntegrityError(CryptoError):
    """HMAC check failed or the packet is malformed (tampering / wrong key)."""


class ReplayError(CryptoError):
    """A packet with an old sequence number was received (replay attack)."""


# ---------------------------------------------------------- RSA key helpers
def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def save_private_key(key: rsa.RSAPrivateKey, path: str | Path,
                     password: bytes | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(password)
           if password else serialization.NoEncryption())
    Path(path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))


def save_public_key(key: rsa.RSAPublicKey, path: str | Path) -> None:
    Path(path).write_bytes(key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private_key(path: str | Path, password: bytes | None = None):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password)


def load_public_key(path: str | Path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 fingerprint of a public key; compare it out-of-band."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# ----------------------------------------------- Layer 1: RSA key exchange
@dataclass(frozen=True)
class SessionKeys:
    enc_key: bytes  # AES-256 key
    mac_key: bytes  # HMAC-SHA256 key


def _oaep():
    return asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)


def _pss():
    return asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH)


def create_handshake(my_private: rsa.RSAPrivateKey,
                     peer_public: rsa.RSAPublicKey,
                     challenge: bytes = b"") -> tuple[SessionKeys, bytes]:
    """Sender side: make fresh session keys and wrap them for the receiver.

    Returns (keys, handshake_bytes).  handshake = RSA-OAEP(keys) || RSA-PSS signature.
    The signature also covers `challenge`, a random value chosen by the receiver for
    this connection, so a recorded handshake cannot be replayed on a new connection.
    """
    keys = SessionKeys(os.urandom(AES_KEY_LEN), os.urandom(MAC_KEY_LEN))
    wrapped = peer_public.encrypt(keys.enc_key + keys.mac_key, _oaep())
    signature = my_private.sign(wrapped + challenge, _pss(), hashes.SHA256())
    return keys, wrapped + signature


def accept_handshake(handshake: bytes, my_private: rsa.RSAPrivateKey,
                     peer_public: rsa.RSAPublicKey,
                     challenge: bytes = b"") -> SessionKeys:
    """Receiver side: verify the sender's signature, then unwrap the keys."""
    wrapped_len = my_private.key_size // 8
    if len(handshake) <= wrapped_len:
        raise HandshakeError("handshake is too short")
    wrapped, signature = handshake[:wrapped_len], handshake[wrapped_len:]
    try:
        peer_public.verify(signature, wrapped + challenge, _pss(), hashes.SHA256())
    except InvalidSignature as exc:
        raise HandshakeError("signature check failed (wrong or forged sender)") from exc
    try:
        material = my_private.decrypt(wrapped, _oaep())
    except ValueError as exc:
        raise HandshakeError("could not decrypt session keys") from exc
    if len(material) != AES_KEY_LEN + MAC_KEY_LEN:
        raise HandshakeError("unexpected key material length")
    return SessionKeys(material[:AES_KEY_LEN], material[AES_KEY_LEN:])


# ------------------------------------- Layers 2 + 3: AES-CBC then HMAC-SHA256
class SecureSender:
    """Encrypts messages: pad -> AES-256-CBC -> HMAC-SHA256 (encrypt-then-MAC)."""

    def __init__(self, keys: SessionKeys):
        self._keys = keys
        self._seq = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        self._seq += 1
        iv = os.urandom(IV_LEN)
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(self._keys.enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        body = struct.pack(">Q", self._seq) + iv + ciphertext
        tag = hmac.new(self._keys.mac_key, body, hashlib.sha256).digest()
        return body + tag


class SecureReceiver:
    """Verifies HMAC and sequence number, then decrypts."""

    def __init__(self, keys: SessionKeys):
        self._keys = keys
        self._last_seq = 0

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < MIN_PACKET:
            raise IntegrityError("packet too short")
        body, tag = packet[:-TAG_LEN], packet[-TAG_LEN:]
        expected = hmac.new(self._keys.mac_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):          # constant-time compare
            raise IntegrityError("HMAC mismatch: packet modified or wrong key")
        seq = struct.unpack(">Q", body[:SEQ_LEN])[0]
        if seq <= self._last_seq:
            raise ReplayError(f"old sequence number {seq} (last accepted {self._last_seq})")
        iv = body[SEQ_LEN:SEQ_LEN + IV_LEN]
        ciphertext = body[SEQ_LEN + IV_LEN:]
        if len(ciphertext) % BLOCK:
            raise IntegrityError("ciphertext is not block aligned")
        decryptor = Cipher(algorithms.AES(self._keys.enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise IntegrityError("bad padding") from exc
        self._last_seq = seq                                 # only after full success
        return plaintext
