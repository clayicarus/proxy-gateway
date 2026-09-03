#!/usr/bin/env python3
"""Verify an authenticated Hysteria2 path by tunneling a TCP connection."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from contextlib import suppress


class ProbeError(RuntimeError):
    """Raised when the Hysteria2 connectivity probe fails."""


def parse_host_port(value: str, argument: str) -> tuple[str, int]:
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1 or not value[closing + 1 :].startswith(":"):
            raise argparse.ArgumentTypeError(
                f"{argument} must be host:port; IPv6 literals need brackets"
            )
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        if value.count(":") != 1:
            raise argparse.ArgumentTypeError(
                f"{argument} must be host:port; IPv6 literals need brackets"
            )
        host, port_text = value.rsplit(":", 1)

    if not host:
        raise argparse.ArgumentTypeError(f"{argument} host cannot be empty")
    try:
        port = int(port_text)
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"{argument} has an invalid port") from err
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{argument} port must be between 1 and 65535")
    return host, port


def private_write(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as config_file:
        config_file.write(content)


def read_process_output(process: subprocess.Popen[str], output: deque[str]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        output.append(line.rstrip())


def recent_output(output: deque[str]) -> str:
    if not output:
        return "no client output was captured"
    return "\n".join(output)


def wait_for_socks(process: subprocess.Popen[str], port: int, timeout: float, output: deque[str]) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProbeError(
                "hysteria client exited before its SOCKS5 listener became ready:\n"
                + recent_output(output)
            )
        with suppress(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        time.sleep(0.1)
    raise ProbeError(
        f"timed out waiting {timeout:g}s for the local SOCKS5 listener:\n"
        + recent_output(output)
    )


def recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise ProbeError("SOCKS5 proxy closed the connection unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def socks_address(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ProbeError("target hostname is longer than 255 bytes")
        return b"\x03" + bytes([len(encoded)]) + encoded + port.to_bytes(2, "big")

    if address.version == 4:
        return b"\x01" + address.packed + port.to_bytes(2, "big")
    return b"\x04" + address.packed + port.to_bytes(2, "big")


def socks_connect(proxy_port: int, host: str, port: int, timeout: float) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(b"\x05\x01\x00")
        version, method = recv_exact(conn, 2)
        if (version, method) != (5, 0):
            raise ProbeError(f"unexpected SOCKS5 authentication response: {version:#x}, {method:#x}")

        conn.sendall(b"\x05\x01\x00" + socks_address(host, port))
        response = recv_exact(conn, 4)
        if response[0] != 5:
            raise ProbeError(f"unexpected SOCKS5 response version: {response[0]:#x}")
        if response[1] != 0:
            errors = {
                1: "general failure",
                2: "connection not allowed",
                3: "network unreachable",
                4: "host unreachable",
                5: "connection refused",
                6: "TTL expired",
                7: "command not supported",
                8: "address type not supported",
            }
            detail = errors.get(response[1], "unknown error")
            raise ProbeError(f"SOCKS5 CONNECT to {host}:{port} failed: {detail} ({response[1]})")


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def find_available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check a Hysteria2 gateway by opening a TCP connection through it."
    )
    parser.add_argument("--server", required=True, help="Gateway address, for example gateway.example.com:8443")
    parser.add_argument("--auth", required=True, help="Hysteria2 auth, for example alice:node:password")
    parser.add_argument("--sni", help="TLS server name; strongly recommended when --server is an IP address")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate validation")
    parser.add_argument(
        "--target",
        default="example.com:443",
        help="TCP target reached through the gateway (default: example.com:443)",
    )
    parser.add_argument("--timeout", type=float, default=15, help="Timeout in seconds (default: 15)")
    parser.add_argument("--hysteria-bin", default="hysteria", help="Path or command name of the Hysteria2 client")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.timeout <= 0:
        raise ProbeError("--timeout must be greater than zero")
    try:
        target_host, target_port = parse_host_port(args.target, "--target")
    except argparse.ArgumentTypeError as err:
        raise ProbeError(str(err)) from err
    if os.path.sep in args.hysteria_bin:
        if not Path(args.hysteria_bin).is_file():
            raise ProbeError(f"Hysteria client was not found: {args.hysteria_bin}")
    elif shutil.which(args.hysteria_bin) is None:
        raise ProbeError(f"Hysteria client was not found in PATH: {args.hysteria_bin}")

    socks_port = find_available_port()
    client_config: dict[str, object] = {
        "server": args.server,
        "auth": args.auth,
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    tls_config: dict[str, object] = {}
    if args.sni:
        tls_config["sni"] = args.sni
    if args.insecure:
        tls_config["insecure"] = True
    if tls_config:
        client_config["tls"] = tls_config

    temp_dir = Path(tempfile.mkdtemp(prefix="hy2-connectivity-"))
    config_path = temp_dir / "client.json"
    process: subprocess.Popen[str] | None = None
    output: deque[str] = deque(maxlen=40)
    try:
        private_write(config_path, json.dumps(client_config))
        process = subprocess.Popen(
            [args.hysteria_bin, "client", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        threading.Thread(target=read_process_output, args=(process, output), daemon=True).start()
        wait_for_socks(process, socks_port, args.timeout, output)
        socks_connect(socks_port, target_host, target_port, args.timeout)
        print(f"OK: {args.server} authenticated and connected to {args.target} through Hysteria2")
        return 0
    finally:
        if process is not None:
            stop_process(process)
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, subprocess.SubprocessError) as err:
        print(f"FAILED: {err}", file=sys.stderr)
        raise SystemExit(1)
