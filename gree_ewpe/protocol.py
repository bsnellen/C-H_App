def envelope(inner, mac, i=0):
    return {"cid": "app", "i": i, "t": "pack", "uid": 0, "tcid": mac, "pack": inner}


def build_scan_packet():
    return {"t": "scan"}


def build_bind_request(mac):
    return {"t": "bind", "uid": 0, "mac": mac}


def build_status_request(mac, cols):
    return {"t": "status", "mac": mac, "cols": list(cols)}


def build_command_request(mac, properties):
    return {
        "t": "cmd",
        "mac": mac,
        "opt": list(properties.keys()),
        "p": list(properties.values()),
    }


def parse_properties(pack, kind):
    if kind == "dat":
        cols, values = pack.get("cols"), pack.get("dat")
    elif kind == "res":
        cols, values = pack.get("opt"), pack.get("val")
        if values is None:
            values = pack.get("p", [])
    else:
        raise ValueError(f"Unsupported response kind: {kind}")
    if not isinstance(cols, list) or not isinstance(values, list):
        raise ValueError("Property arrays are missing or invalid")
    if len(cols) != len(values):
        raise ValueError("Property arrays have different lengths")
    return dict(zip(cols, values))


def parse_discovery(pack, addr):
    identity = pack.get("mac") or pack.get("cid")
    if not identity:
        raise ValueError("Discovery response has no usable identity")
    return {
        "ip": addr[0],
        "port": addr[1],
        "mac": identity,
        "name": pack.get("name"),
        "brand": pack.get("brand"),
        "model": pack.get("model"),
        "version": pack.get("ver"),
    }
