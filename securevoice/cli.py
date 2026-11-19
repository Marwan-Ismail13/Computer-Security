"""Command-line app: one laptop = listener + sender (full duplex).

    python -m securevoice.cli run --name laptop1 --peer-pub keys/laptop3_public.pem \
           --peer-host 192.168.1.20 --peer-port 12347 --listen-port 12347 --play

Commands inside the app:
    r [sec]    record (default 60 s) and send
    f <file>   send an existing .wav file
    t          send a 2 s test tone (no microphone needed)
    q          quit
"""
import argparse
import sys
from pathlib import Path

from . import audio
from .crypto_layers import fingerprint, load_private_key, load_public_key
from .node import Node


def main() -> None:
    ap = argparse.ArgumentParser(prog="securevoice.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="listen and send (full duplex)")
    r.add_argument("--name", required=True, help="uses keys/<name>_private.pem")
    r.add_argument("--peer-pub", required=True, help="other side's public key (.pem)")
    r.add_argument("--peer-host", required=True, help="IP to send to (the MITM IP in the 3-laptop test)")
    r.add_argument("--peer-port", type=int, default=12347)
    r.add_argument("--listen-port", type=int, default=12347)
    r.add_argument("--inbox", default="inbox")
    r.add_argument("--play", action="store_true", help="play received messages")
    args = ap.parse_args()

    me = load_private_key(Path("keys") / f"{args.name}_private.pem")
    peer = load_public_key(args.peer_pub)
    print("my public key fingerprint  :", fingerprint(me.public_key()))
    print("peer public key fingerprint:", fingerprint(peer))
    print("(compare these with the other laptop out-of-band!)")

    def on_message(path, data):
        if args.play:
            try:
                audio.play_wav(data)
            except Exception as exc:        # no speaker / bad wav must not kill the listener
                print("playback failed:", exc)

    node = Node(me, peer, listen_port=args.listen_port, inbox=args.inbox, on_message=on_message)
    node.start()

    def send(data: bytes):
        try:
            node.send(args.peer_host, args.peer_port, data)
            print(f"sent {len(data)} bytes to {args.peer_host}:{args.peer_port}")
        except Exception as exc:
            print("send failed:", exc)

    print(__doc__.split("Commands inside the app:")[1])
    try:
        while True:
            parts = input("> ").strip().split()
            if not parts:
                continue
            cmd = parts[0].lower()
            if cmd == "q":
                break
            elif cmd == "r":
                secs = float(parts[1]) if len(parts) > 1 else 60.0
                print(f"recording {secs:.0f} s ... speak now")
                send(audio.record_wav(secs))
            elif cmd == "f" and len(parts) > 1:
                send(Path(" ".join(parts[1:])).read_bytes())
            elif cmd == "t":
                send(audio.make_test_wav(2.0))
            else:
                print("unknown command (r / f <file> / t / q)")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        node.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
