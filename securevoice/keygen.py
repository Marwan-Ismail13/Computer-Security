"""Generate an RSA key pair for one laptop.

    python -m securevoice.keygen laptop1
    python -m securevoice.keygen laptop3

Creates keys/<name>_private.pem (keep secret, git-ignored) and
keys/<name>_public.pem (copy this file to the other laptop).
Compare the printed fingerprints by voice/chat so a MITM cannot swap keys.
"""
import sys
from pathlib import Path

from .crypto_layers import (fingerprint, generate_rsa_keypair,
                            save_private_key, save_public_key)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python -m securevoice.keygen <name>")
    name = sys.argv[1]
    out = Path("keys")
    out.mkdir(exist_ok=True)
    private = generate_rsa_keypair()
    save_private_key(private, out / f"{name}_private.pem")
    save_public_key(private.public_key(), out / f"{name}_public.pem")
    print(f"Created keys/{name}_private.pem and keys/{name}_public.pem")
    print("Public key fingerprint:", fingerprint(private.public_key()))


if __name__ == "__main__":
    main()
