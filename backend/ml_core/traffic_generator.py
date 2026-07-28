from __future__ import annotations

import argparse
import os
import random
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCAPY_CONFIG_HOME = Path(__file__).resolve().parent / ".scapy_config"
SCAPY_CONFIG_HOME.mkdir(exist_ok=True)
os.environ.setdefault("XDG_CONFIG_HOME", str(SCAPY_CONFIG_HOME))

from scapy.all import IP, TCP, UDP, RandShort, send

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"NetShield_AI live traffic simulator\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args) -> None:
        return


def start_local_http_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Local HTTP target running at http://{host}:{port}")
    return server


def normal_http_traffic(host: str, port: int, stop_event: threading.Event) -> None:
    paths = ["/", "/health", "/dashboard", "/api/traffic/summary", "/api/predict/check"]

    while not stop_event.is_set():
        try:
            path = random.choice(paths)
            request = (
                f"GET {path}?ts={time.time()} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "User-Agent: NetShield-TrafficSimulator/1.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode()

            with socket.create_connection((host, port), timeout=1.5) as sock:
                sock.sendall(request)
                sock.recv(1024)

            print(f"[LOW-RISK] HTTP request -> {host}:{port}{path}")
        except OSError as exc:
            print(f"[WARN] HTTP traffic failed: {exc}")

        time.sleep(random.uniform(0.25, 1.2))


def tcp_port_scan_burst(target_ip: str, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        time.sleep(random.uniform(3.0, 7.0))
        ports = random.sample(range(20, 1024), k=random.randint(25, 80))
        print(f"[HIGH-RISK] TCP SYN scan burst -> {target_ip} ports={len(ports)}")

        for port in ports:
            packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            send(packet, verbose=False)
            time.sleep(random.uniform(0.002, 0.015))


def udp_dos_burst(target_ip: str, target_port: int, stop_event: threading.Event) -> None:
    payloads = [
        b"NetShield_AI burst payload",
        random.randbytes(128) if hasattr(random, "randbytes") else bytes(random.getrandbits(8) for _ in range(128)),
        random.randbytes(512) if hasattr(random, "randbytes") else bytes(random.getrandbits(8) for _ in range(512)),
    ]

    while not stop_event.is_set():
        time.sleep(random.uniform(5.0, 10.0))
        packet_count = random.randint(120, 350)
        print(f"[HIGH-RISK] UDP packet burst -> {target_ip}:{target_port} packets={packet_count}")

        for _ in range(packet_count):
            payload = random.choice(payloads)
            packet = IP(dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / payload
            send(packet, verbose=False)
            time.sleep(random.uniform(0.001, 0.006))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dynamic local traffic simulator for NetShield_AI live sniffer.")
    parser.add_argument("--bind-host", default="127.0.0.1", help="Local HTTP server bind host.")
    parser.add_argument("--port", type=int, default=8088, help="Local HTTP server port.")
    parser.add_argument("--target-ip", default="127.0.0.1", help="Target IP for HTTP, scan, and burst traffic.")
    parser.add_argument("--burst-port", type=int, default=9099, help="UDP destination port for burst simulation.")
    parser.add_argument("--normal-only", action="store_true", help="Generate only low-risk HTTP traffic.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    stop_event = threading.Event()
    server = start_local_http_server(args.bind_host, args.port)

    workers = [
        threading.Thread(target=normal_http_traffic, args=(args.target_ip, args.port, stop_event), daemon=True),
    ]

    if not args.normal_only:
        workers.extend(
            [
                threading.Thread(target=tcp_port_scan_burst, args=(args.target_ip, stop_event), daemon=True),
                threading.Thread(target=udp_dos_burst, args=(args.target_ip, args.burst_port, stop_event), daemon=True),
            ]
        )

    print("🚦 Dynamic traffic generator started. Press Ctrl+C to stop.")
    print("Use only inside your own lab machine/network.")

    for worker in workers:
        worker.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping traffic generator...")
    finally:
        stop_event.set()
        server.shutdown()


if __name__ == "__main__":
    main()
