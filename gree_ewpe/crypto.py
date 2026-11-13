import base64
import json

from Crypto.Cipher import AES

DEFAULT_KEY = "a3K8Bx%2r8Y7#xDh"
GCM_KEY = "{yxAHAY_Lm6pbC/<"
GCM_NONCE = bytes(
    [0x54, 0x40, 0x78, 0x44, 0x49, 0x67, 0x5A, 0x51, 0x6C, 0x5E, 0x63, 0x13]
)
GCM_AAD = b"qualcomm-test"


def _pad(data: str) -> str:
    pad_len = 16 - (len(data) % 16)
    return data + chr(pad_len) * pad_len


def _unpad(data: str) -> str:
    if not data:
        return data
    pad_len = ord(data[-1])
    if 0 < pad_len <= 16 and data.endswith(chr(pad_len) * pad_len):
        return data[:-pad_len]
    return data


class DecryptionError(Exception):
    pass


class Cipher:
    def encrypt(self, payload):
        raise NotImplementedError

    def decrypt(self, blob, tag=None):
        raise NotImplementedError


class CipherV1(Cipher):
    def __init__(self, key: str = DEFAULT_KEY):
        self.key = key

    def _cipher(self):
        return AES.new(self.key.encode(), AES.MODE_ECB)

    def encrypt(self, payload):
        plaintext = json.dumps(payload, separators=(",", ":"))
        encrypted = self._cipher().encrypt(_pad(plaintext).encode())
        return base64.b64encode(encrypted).decode(), None

    def decrypt(self, blob, tag=None):
        try:
            decrypted = self._cipher().decrypt(base64.b64decode(blob)).decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise DecryptionError(str(exc)) from exc
        try:
            return json.loads(_unpad(decrypted))
        except json.JSONDecodeError as exc:
            raise DecryptionError(str(exc)) from exc


class CipherV2(Cipher):
    def __init__(self, key: str = GCM_KEY):
        self.key = key

    def _cipher(self):
        cipher = AES.new(self.key.encode(), AES.MODE_GCM, nonce=GCM_NONCE)
        cipher.update(GCM_AAD)
        return cipher

    def encrypt(self, payload):
        cipher = self._cipher()
        encrypted, tag = cipher.encrypt_and_digest(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        return base64.b64encode(encrypted).decode(), base64.b64encode(tag).decode()

    def decrypt(self, blob, tag=None):
        if tag is None:
            raise DecryptionError("CipherV2 requires an authentication tag")
        try:
            decrypted = self._cipher().decrypt_and_verify(
                base64.b64decode(blob), base64.b64decode(tag)
            ).decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise DecryptionError(str(exc)) from exc
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise DecryptionError(str(exc)) from exc


def decrypt_pack(blob, tag=None, key=DEFAULT_KEY):
    try:
        return CipherV1(key).decrypt(blob, tag)
    except DecryptionError:
        return CipherV2().decrypt(blob, tag)
