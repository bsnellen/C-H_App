import argparse
import json
import sys

from .client import DEFAULT_PORT, DEFAULT_STATUS_COLUMNS, EwpeClient, EwpeError, discover
from .crypto import DEFAULT_KEY


def parse_value(value):
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gree-ewpe",
        description=(
            "Send GREE/EWPE JSON messages to Cooper & Hunter climate systems "
            "over UDP port 7000."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover", help="Broadcast a scan and list devices")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--broadcast", default="255.255.255.255")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)

    for name, help_text in (
        ("bind", "Perform the AES bind handshake and print the device key"),
        ("status", "Query device status"),
        ("set", "Set device properties"),
        ("raw", "Send a raw EWPE JSON pack"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--host", required=True, help="Device IP address")
        p.add_argument("--mac", required=True, help="Device MAC address")
        p.add_argument("--port", type=int, default=DEFAULT_PORT)
        p.add_argument("--key", default=DEFAULT_KEY, help="AES key from a previous bind")
        p.add_argument("--timeout", type=float, default=5.0)

    sub.choices["status"].add_argument(
        "--cols",
        default=",".join(DEFAULT_STATUS_COLUMNS),
        help="Comma-separated status columns to request",
    )
    sub.choices["set"].add_argument(
        "properties",
        nargs="+",
        metavar="PROP=VALUE",
        help="Properties to set, e.g. Pow=1 SetTem=25 WdSpd=0",
    )
    sub.choices["raw"].add_argument(
        "--json",
        required=True,
        help='Inner pack JSON, e.g. {"t":"status","cols":["Pow"]}',
    )
    return parser


def run(args):
    if args.command == "discover":
        return discover(timeout=args.timeout, port=args.port, broadcast=args.broadcast)

    client = EwpeClient(
        host=args.host,
        mac=args.mac,
        port=args.port,
        key=args.key,
        timeout=args.timeout,
    )
    if args.command == "bind":
        key = client.bind()
        return {"mac": client.mac, "key": key}
    if args.command == "status":
        return client.get_status(args.cols.split(","))
    if args.command == "set":
        properties = {}
        for item in args.properties:
            if "=" not in item:
                raise ValueError(f"Expected PROP=VALUE, got: {item}")
            name, value = item.split("=", 1)
            properties[name] = parse_value(value)
        return client.send_properties(properties)
    if args.command == "raw":
        return client.send_json(json.loads(args.json))
    raise ValueError(f"Unknown command: {args.command}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (EwpeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0
