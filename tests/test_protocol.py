import pytest

from gree_ewpe.protocol import (
    build_bind_request,
    build_command_request,
    build_scan_packet,
    build_status_request,
    envelope,
    parse_discovery,
    parse_properties,
)


def test_build_scan_packet():
    assert build_scan_packet() == {"t": "scan"}


def test_build_bind_request():
    assert build_bind_request("aabbccdd1122") == {
        "t": "bind",
        "uid": 0,
        "mac": "aabbccdd1122",
    }


def test_build_status_request():
    assert build_status_request("aabbccdd1122", ["Pow", "SetTem"]) == {
        "t": "status",
        "mac": "aabbccdd1122",
        "cols": ["Pow", "SetTem"],
    }


def test_build_command_request():
    assert build_command_request("aabbccdd1122", {"Pow": 1, "SetTem": 25}) == {
        "t": "cmd",
        "mac": "aabbccdd1122",
        "opt": ["Pow", "SetTem"],
        "p": [1, 25],
    }


def test_envelope_defaults():
    inner = {"t": "status", "mac": "x"}
    assert envelope(inner, "x")["i"] == 0


def test_parse_properties_dat():
    pack = {"t": "dat", "cols": ["Pow", "SetTem"], "dat": [1, 25]}
    assert parse_properties(pack, "dat") == {"Pow": 1, "SetTem": 25}


def test_parse_properties_res_val():
    pack = {"t": "res", "opt": ["Pow"], "val": [0]}
    assert parse_properties(pack, "res") == {"Pow": 0}


def test_parse_properties_res_fallback_p():
    pack = {"t": "res", "opt": ["Pow"], "p": [1]}
    assert parse_properties(pack, "res") == {"Pow": 1}


def test_parse_properties_length_mismatch():
    with pytest.raises(ValueError):
        parse_properties({"t": "dat", "cols": ["Pow"], "dat": []}, "dat")


def test_parse_discovery():
    pack = {"mac": "aabbccdd1122", "name": "Living room", "ver": "V2.2.1"}
    device = parse_discovery(pack, ("192.168.1.50", 7000))
    assert device == {
        "ip": "192.168.1.50",
        "port": 7000,
        "mac": "aabbccdd1122",
        "name": "Living room",
        "brand": None,
        "model": None,
        "version": "V2.2.1",
    }


def test_parse_discovery_requires_identity():
    with pytest.raises(ValueError):
        parse_discovery({"name": "x"}, ("192.168.1.50", 7000))
