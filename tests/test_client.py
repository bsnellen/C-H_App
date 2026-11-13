import json
import socket
import threading

import pytest

from gree_ewpe.client import EwpeClient, discover
from gree_ewpe.crypto import CipherV1

DEVICE_MAC = "aabbccdd1122"
BOUND_KEY = "0123456789abcdef"


class FakeDevice:
    def __init__(self, sock):
        self.sock = sock
        self.cipher = CipherV1()
        self.bound = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _reply(self, data, addr):
        self.sock.sendto(data, addr)

    def _serve(self):
        while True:
            try:
                payload, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            obj = json.loads(payload.decode())
            if obj.get("t") == "scan":
                pack = self.cipher.encrypt(
                    {"t": "dev", "mac": DEVICE_MAC, "name": "C&H Unit", "ver": "V2.2.1"}
                )[0]
                self._reply(
                    json.dumps({"t": "pack", "i": 1, "cid": DEVICE_MAC, "pack": pack}).encode(),
                    addr,
                )
                continue
            key = BOUND_KEY if self.bound else CipherV1().key
            inner = CipherV1(key).decrypt(obj["pack"])
            if inner.get("t") == "bind":
                response = {"t": "bindok", "mac": DEVICE_MAC, "key": BOUND_KEY}
                self.bound = True
            elif inner.get("t") == "status":
                cols = inner["cols"]
                values = [1 if c == "Pow" else 25 if c == "SetTem" else 0 for c in cols]
                response = {"t": "dat", "mac": DEVICE_MAC, "cols": cols, "dat": values}
            elif inner.get("t") == "cmd":
                response = {
                    "t": "res",
                    "mac": DEVICE_MAC,
                    "opt": inner["opt"],
                    "val": inner["p"],
                }
            else:
                response = {"t": "unknown"}
            blob, _ = CipherV1(key).encrypt(response)
            self._reply(
                json.dumps({"t": "pack", "i": 0, "cid": DEVICE_MAC, "pack": blob}).encode(),
                addr,
            )


@pytest.fixture()
def fake_device():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    FakeDevice(sock)
    yield "127.0.0.1", port
    sock.close()


def test_bind_negotiates_key(fake_device):
    host, port = fake_device
    client = EwpeClient(host, DEVICE_MAC, port=port, timeout=2.0)
    assert client.bind() == BOUND_KEY
    assert client.key == BOUND_KEY


def test_status_after_bind(fake_device):
    host, port = fake_device
    client = EwpeClient(host, DEVICE_MAC, port=port, timeout=2.0)
    client.bind()
    status = client.get_status(["Pow", "SetTem"])
    assert status == {"Pow": 1, "SetTem": 25}


def test_send_properties(fake_device):
    host, port = fake_device
    client = EwpeClient(host, DEVICE_MAC, port=port, timeout=2.0)
    client.bind()
    result = client.send_properties({"Pow": 1, "SetTem": 25, "WdSpd": 0})
    assert result == {"Pow": 1, "SetTem": 25, "WdSpd": 0}


def test_send_json_raw(fake_device):
    host, port = fake_device
    client = EwpeClient(host, DEVICE_MAC, port=port, timeout=2.0)
    client.bind()
    pack = client.send_json({"t": "status", "mac": DEVICE_MAC, "cols": ["Pow"]})
    assert pack["t"] == "dat"


def test_discover_finds_device(fake_device):
    host, port = fake_device
    devices = discover(timeout=1.0, port=port, broadcast=host)
    assert len(devices) == 1
    assert devices[0]["mac"] == DEVICE_MAC
    assert devices[0]["ip"] == host
