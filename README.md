# SecureVoice - Layered Cryptography for Voice Messages

**Course:** CS 401 Computer Security - MSA University, Fall 2026
**Team (2 students):** Marwan Ismail, _<partner name>_

## What is this project?

A Python system that sends a ~1 minute **voice message** between laptops over a network, protected by
**three cryptographic algorithms applied in sequential layers**, and then **attacks its own system**
from a Man-in-the-Middle (MITM) laptop to show what the encryption stops and why.

```
 Laptop 1 (Source)              Laptop 2 (MITM)               Laptop 3 (Destination)
 record voice                   passive: sniff + analyse      receive
 RSA handshake  ------------->  active: modify / replay /  -> verify HMAC + sequence
 AES-256-CBC encrypt            inject                        AES-256-CBC decrypt
 HMAC-SHA256 tag                                              play voice
        <------------------ works in both directions ------------------>
```

## The three layers

| Layer | Algorithm | Job | Stops |
|------:|-----------|-----|-------|
| 1 | **RSA-2048** (OAEP encryption + PSS signature) | Deliver the session keys and authenticate the sender | Key theft, fake-key MITM |
| 2 | **AES-256-CBC** (random IV per packet) | Encrypt the voice data | Eavesdropping (passive attack) |
| 3 | **HMAC-SHA256** + sequence number (encrypt-then-MAC) | Detect any change, reorder or replay | Tampering, injection, replay (active attack) |

Packet format: `| seq 8B | IV 16B | ciphertext | HMAC tag 32B |`. The HMAC is verified **before** anything is decrypted.
Each direction uses its own session keys, so a packet cannot be reflected back at its sender.

## Repository layout

```
securevoice/
  crypto_layers.py   the 3 layers (done)
  keygen.py          make an RSA key pair per laptop (done)
  demo_local.py      one-machine demo incl. 3 active attacks (done)
  protocol.py        length-prefixed TCP frames (done)
  node.py            listener + sender, full duplex (done)
  audio.py           record / play / test-tone WAV (done)
  cli.py             command-line app for each laptop (done)
  ...                GUI, MITM attack scripts (next steps)
tests/               unit tests (pytest)
keys/                RSA keys (private keys are git-ignored)
docs/                paper, slides, diagrams
```

## Quick start

```bash
git clone https://github.com/Marwan-Ismail13/Computer-Security
cd Computer-Security
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest -v                  # unit tests
python -m securevoice.demo_local     # see encryption + attacks being blocked
python -m securevoice.keygen laptop1 # generate keys; copy *_public.pem to the other laptop
```

## Running on the laptops

1. On **every** laptop: `python -m securevoice.keygen <name>` (e.g. `laptop1`, `laptop3`).
2. Copy each `*_public.pem` to the other laptop's `keys/` folder (never copy `*_private.pem`).
   Compare the printed fingerprints by voice/chat.
3. All laptops on the same Wi-Fi/hotspot. Find each IP with `ipconfig` (Windows) or `ip a` (Linux).
4. Start the app on each laptop (Windows may ask to allow Python through the firewall: allow **Private** networks):

```bash
# Laptop 3 (destination)                         # Laptop 1 (source)
python -m securevoice.cli run --name laptop3 \   python -m securevoice.cli run --name laptop1 \
  --peer-pub keys/laptop1_public.pem \             --peer-pub keys/laptop3_public.pem \
  --peer-host <LAPTOP1_IP> --play                  --peer-host <LAPTOP3_IP> --play
```
Then type `t` (test tone), `r` (record 60 s) or `f file.wav`. Both laptops can send and receive.
In the final 3-laptop test, the source's `--peer-host` is the **MITM laptop's IP** (the MITM forwards to the destination).

## Roadmap

- [x] Choose algorithms, project structure, README
- [x] Crypto layers (RSA handshake, AES-CBC, HMAC-SHA256, replay protection)
- [x] Unit tests (18 cases) + network integration tests (9 cases)
- [x] TCP networking with framing, both directions, replay-proof handshake
- [x] Audio record / play (`sounddevice`) and command-line app
- [ ] Related articles (2-3 IEEE/ACM papers)
- [ ] GUI (`tkinter`)
- [ ] Integration tests
- [ ] MITM laptop: passive attack (sniffing, brute force, statistical analysis)
- [ ] MITM laptop: active attack (modify, replay, inject)
- [ ] Final test on 3 laptops with 1 minute voice messages
- [ ] PowerPoint (5-10 slides) and IEEE-format paper
- [ ] Submit 2 days before the discussion

## Security notes / limitations

- Public keys must be exchanged and their **fingerprints compared out-of-band** (pinned keys). Without this,
  no scheme can stop an active MITM from substituting keys.
- The receiver sends a random challenge on every connection and the sender signs it into the handshake,
  so a recorded handshake + packets cannot be replayed on a new connection (tested).
- Educational project - not audited for production use.
