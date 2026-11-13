# Cooper & Hunter Climate App

Python app that talks to Cooper & Hunter (GREE-based) climate systems over
**UDP port 7000** using the GREE/EWPE Smart JSON protocol with its AES
encrypted `pack` messages.

## How the protocol works

1. **Discover** — a plaintext `{"t": "scan"}` datagram is broadcast to UDP
   port 7000. Every unit replies with a `{"t": "pack", "pack": "<base64>" }`
   envelope whose payload is AES encrypted and contains the device MAC,
   name, and firmware version.
2. **Bind (secure handshake)** — a `bind` pack encrypted with the factory
   AES-128 key (`a3K8Bx%2r8Y7#xDh`, AES-128-ECB) is sent to the device. The
   device replies with `bindok` and a per-device AES key. Newer G5 firmware
   uses AES-128-GCM instead; both ciphers are supported for decoding
   replies.
3. **Send JSON messages** — status queries (`t: "status"`) and commands
   (`t: "cmd"`) are encrypted with the negotiated key and sent as
   `{"t": "pack"}` envelopes to UDP port 7000.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# 1. Find units on the local network
python3 app.py discover

# 2. Bind to a unit (prints the device key to reuse later)
python3 app.py bind --host 192.168.1.50 --mac aabbccdd1122

# 3. Read the current status
python3 app.py status --host 192.168.1.50 --mac aabbccdd1122 \
    --key <key-from-bind> --cols Pow,SetTem,WdSpd

# 4. Set properties (power on, 24 C, fan medium)
python3 app.py set --host 192.168.1.50 --mac aabbccdd1122 \
    --key <key-from-bind> Pow=1 SetTem=24 WdSpd=2

# 5. Send any raw EWPE JSON pack
python3 app.py raw --host 192.168.1.50 --mac aabbccdd1122 \
    --key <key-from-bind> --json '{"t":"status","cols":["Pow"]}'
```

Common properties: `Pow`, `SetTem`, `WdSpd`, `Mod`, `Air`, `Blo`, `Health`,
`Lig`, `SwhSlp`, `SwUpDn`, `SwingLfRig`, `Quiet`, `Tur`, `StHt`, `SvSt`,
`TemUn`.

## Library use

```python
from gree_ewpe import EwpeClient, discover

for device in discover():
    print(device["ip"], device["mac"], device["name"])

client = EwpeClient("192.168.1.50", "aabbccdd1122")
client.bind()
print(client.get_status(["Pow", "SetTem", "WdSpd"]))
client.send_properties({"Pow": 1, "SetTem": 24, "WdSpd": 2})
```

## Tests

```bash
python3 -m pytest tests
```

The test suite includes a simulated UDP device so the full
discover → bind → status → set flow is verified without hardware.

## Security notes

The EWPE protocol's "secure connection" is device-side AES encryption with
static or bind-negotiated keys over UDP. The factory key is public
knowledge and ECB mode leaks structure, so treat this as an obfuscated
local LAN protocol: keep it on a trusted network and do not expose UDP
port 7000 beyond it.
