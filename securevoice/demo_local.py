"""Single-machine demo of the three layers (no network, no audio yet).

    python -m securevoice.demo_local
"""
import os

from .crypto_layers import (CryptoError, SecureReceiver, SecureSender,
                            accept_handshake, create_handshake,
                            generate_rsa_keypair)


def main() -> None:
    print("== Generating RSA keys for Laptop 1 (source) and Laptop 3 (destination)")
    l1, l3 = generate_rsa_keypair(), generate_rsa_keypair()

    print("== Layer 1: RSA handshake (L1 -> L3)")
    keys, handshake = create_handshake(l1, l3.public_key())
    rx_keys = accept_handshake(handshake, l3, l1.public_key())
    print("   session keys match:", keys == rx_keys)

    sender, receiver = SecureSender(keys), SecureReceiver(rx_keys)
    voice = b"RIFF-fake-voice-data " * 1000
    packet = sender.encrypt(voice)

    print(f"== Layers 2+3: AES-256-CBC + HMAC-SHA256  ({len(voice)} B -> {len(packet)} B)")
    print("   what the MITM sees:", packet[:32].hex(), "...")
    print("   decrypted OK:", receiver.decrypt(packet) == voice)

    print("== Active attack 1: flip one bit")
    bad = bytearray(sender.encrypt(voice)); bad[40] ^= 1
    try:
        receiver.decrypt(bytes(bad))
    except CryptoError as e:
        print("   rejected ->", type(e).__name__, ":", e)

    print("== Active attack 2: replay an old packet")
    try:
        receiver.decrypt(packet)
    except CryptoError as e:
        print("   rejected ->", type(e).__name__, ":", e)

    print("== Active attack 3: MITM swaps in its own keys during the handshake")
    mitm = generate_rsa_keypair()
    _, forged = create_handshake(mitm, l3.public_key())
    try:
        accept_handshake(forged, l3, l1.public_key())
    except CryptoError as e:
        print("   rejected ->", type(e).__name__, ":", e)


if __name__ == "__main__":
    main()
