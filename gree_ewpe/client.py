import json
import socket

from .crypto import DEFAULT_KEY, CipherV1, decrypt_pack
from .protocol import (
    build_bind_request,
    build_command_request,
    build_scan_packet,
    build_status_request,
    envelope,
    parse_discovery,
    parse_properties,
)

DEFAULT_PORT = 7000
DEFAULT_TIMEOUT = 5.0
DEFAULT_STATUS_COLUMNS = [
    "Pow",
    "Mod",
    "SetTem",
    "TemUn",
    "TemRec",
    "WdSpd",
    "Air",
    "Blo",
    "Health",
    "SwhSlp",
    "Lig",
    "SwUpDn",
    "SwingLfRig",
    "Quiet",
    "Tur",
    "StHt",
    "SvSt",
]


class EwpeError(Exception):
    pass


class DeviceTimeoutError(EwpeError):
    pass


class BindError(EwpeError):
    pass


class EwpeClient:
    def __init__(self, host, mac, port=DEFAULT_PORT, key=DEFAULT_KEY, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.mac = mac
        self.port = port
        self.key = key
        self.timeout = timeout

    def bind(self):
        inner = build_bind_request(self.mac)
        response = self._exchange(envelope(inner, self.mac, i=1), CipherV1())
        pack = response.get("pack", {})
        if pack.get("t") != "bindok":
            raise BindError(f"Device did not accept bind: {pack}")
        self.key = pack.get("key", self.key)
        return self.key

    def get_status(self, cols=None):
        inner = build_status_request(self.mac, cols or DEFAULT_STATUS_COLUMNS)
        pack = self._send_inner(inner)
        if pack.get("t") == "dat":
            return parse_properties(pack, "dat")
        return pack

    def send_properties(self, properties):
        inner = build_command_request(self.mac, properties)
        pack = self._send_inner(inner)
        if pack.get("t") == "res":
            return parse_properties(pack, "res")
        return pack

    def send_json(self, inner):
        return self._send_inner(inner)

    def _send_inner(self, inner):
        response = self._exchange(envelope(inner, self.mac), self._cipher())
        return response.get("pack", {})

    def _cipher(self):
        return CipherV1(self.key)

    def _exchange(self, request, cipher):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            if "pack" in request:
                request["pack"], tag = cipher.encrypt(request["pack"])
                if tag:
                    request["tag"] = tag
            data = json.dumps(request, separators=(",", ":")).encode()
            sock.sendto(data, (self.host, self.port))
            while True:
                payload, addr = self._recv(sock)
                if addr[0] != self.host:
                    continue
                return self._decode(payload)
        except socket.timeout as exc:
            raise DeviceTimeoutError(
                f"No response from {self.host}:{self.port} within {self.timeout}s"
            ) from exc
        finally:
            sock.close()

    def _recv(self, sock):
        try:
            return sock.recvfrom(4096)
        except OSError as exc:
            raise DeviceTimeoutError(str(exc)) from exc

    def _decode(self, payload):
        obj = json.loads(payload.decode())
        if "pack" not in obj or isinstance(obj["pack"], dict):
            return obj
        obj["pack"] = decrypt_pack(obj["pack"], obj.get("tag"), self.key)
        return obj


def discover(timeout=3.0, port=DEFAULT_PORT, broadcast="255.255.255.255"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    devices = {}
    try:
        sock.sendto(json.dumps(build_scan_packet()).encode(), (broadcast, port))
        while True:
            try:
                payload, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            try:
                obj = json.loads(payload.decode())
                pack = obj["pack"]
                if not isinstance(pack, dict):
                    pack = decrypt_pack(pack, obj.get("tag"))
                device = parse_discovery(pack, addr)
                devices[device["mac"]] = device
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
    finally:
        sock.close()
    return list(devices.values())
