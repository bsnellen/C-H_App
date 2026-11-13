import json

import pytest

from gree_ewpe.crypto import DEFAULT_KEY, CipherV1, CipherV2, decrypt_pack


def test_cipher_v1_roundtrip():
    payload = {"t": "status", "mac": "aabbccdd1122", "cols": ["Pow"]}
    blob, tag = CipherV1().encrypt(payload)
    assert tag is None
    assert CipherV1().decrypt(blob) == payload


def test_cipher_v1_uses_default_key():
    payload = {"t": "scan"}
    blob, _ = CipherV1().encrypt(payload)
    assert CipherV1(DEFAULT_KEY).decrypt(blob) == payload


def test_cipher_v1_padding_matches_reference():
    payload = {"t": "bind"}
    cipher = CipherV1()
    blob, _ = cipher.encrypt(payload)
    from Crypto.Cipher import AES

    raw = AES.new(cipher.key.encode(), AES.MODE_ECB).decrypt(__import__("base64").b64decode(blob))
    text = raw.decode()
    pad_len = ord(text[-1])
    assert 0 < pad_len <= 16
    assert json.loads(text[:-pad_len]) == payload


def test_cipher_v2_roundtrip_with_tag():
    payload = {"t": "cmd", "opt": ["Pow"], "p": [1]}
    blob, tag = CipherV2().encrypt(payload)
    assert tag is not None
    assert CipherV2().decrypt(blob, tag) == payload


def test_cipher_v2_requires_tag():
    blob, _ = CipherV2().encrypt({"t": "cmd"})
    with pytest.raises(Exception):
        CipherV2().decrypt(blob)


def test_decrypt_pack_falls_back_to_v2():
    payload = {"t": "res", "opt": ["Pow"], "val": [0]}
    blob, tag = CipherV2().encrypt(payload)
    assert decrypt_pack(blob, tag) == payload


def test_decrypt_pack_v1_with_custom_key():
    payload = {"t": "dat", "cols": ["Pow"], "dat": [1]}
    blob, _ = CipherV1("0123456789abcdef").encrypt(payload)
    assert decrypt_pack(blob, None, "0123456789abcdef") == payload
