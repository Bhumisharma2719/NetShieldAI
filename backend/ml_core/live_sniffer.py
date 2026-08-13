from __future__ import annotations

import argparse
import math
import os
import ipaddress
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import joblib
import pandas as pd

SCAPY_CONFIG_HOME = Path(__file__).resolve().parent / ".scapy_config"
SCAPY_CONFIG_HOME.mkdir(exist_ok=True)
os.environ.setdefault("XDG_CONFIG_HOME", str(SCAPY_CONFIG_HOME))

from scapy.all import DNS, DNSQR, ICMP, IP, Raw, TCP, UDP, AsyncSniffer, conf, get_if_list, get_working_ifaces

try:
    from scapy.arch.windows import get_windows_if_list  # type: ignore
except Exception:  # pragma: no cover - only available on Windows hosts
    get_windows_if_list = None

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.live_traffic_store import append_live_log, classify_attack_type, clear_live_traffic_store

MODEL_PATH = Path(__file__).resolve().parent / "anomaly_model.pkl"
FLOW_IDLE_TTL_SECONDS = 90
IGNORED_CAPTURE_PORTS = {3000, 8000}
IGNORED_IP_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("172.18.0.0/16"),
    ipaddress.ip_network("192.168.65.0/24"),
)


class Color:
    RESET = "\033[0m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


@dataclass
class FlowStats:
    src_ip: str
    dst_ip: str
    proto: str
    src_port: int
    dst_port: int
    start_ts: float
    last_ts: float
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0

    @property
    def dur(self) -> float:
        return max(self.last_ts - self.start_ts, 0.001)

    @property
    def packets(self) -> int:
        return self.spkts + self.dpkts

    @property
    def bytes(self) -> int:
        return self.sbytes + self.dbytes

    @property
    def sload(self) -> float:
        return self.sbytes / self.dur

    @property
    def dload(self) -> float:
        return self.dbytes / self.dur


@dataclass
class LiveSnifferController:
    preferred_iface: str | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    interfaces: list[str] = field(default_factory=list)
    sniffers: list[AsyncSniffer] = field(default_factory=list)
    scorer: "LiveFlowScorer | None" = None

    def stop(self) -> None:
        self.stop_event.set()
        for sniffer in self.sniffers:
            try:
                sniffer.stop()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)


class LiveFlowScorer:
    def __init__(self, model_path: Path) -> None:
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}. Run train_anomaly_model.py first.")

        self.model = joblib.load(model_path)
        self.flows: dict[tuple, FlowStats] = {}
        self.lock = threading.Lock()
        self.last_store_error = 0.0
        self.last_real_packet_at = 0.0
        self.last_any_packet_at = 0.0

    def update_from_packet(self, packet, capture_source: str = "real") -> None:
        if not self.should_capture_packet(packet):
            return

        ip = packet[IP]
        proto, sport, dport = self._transport_tuple(packet)
        now = time.time()
        size = len(packet)

        forward_key = (proto, ip.src, sport, ip.dst, dport)
        reverse_key = (proto, ip.dst, dport, ip.src, sport)
        snapshot = None

        with self.lock:
            if reverse_key in self.flows:
                flow = self.flows[reverse_key]
                flow.dpkts += 1
                flow.dbytes += size
                direction = "reverse"
            else:
                flow = self.flows.get(forward_key)
                if flow is None:
                    flow = FlowStats(
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        proto=proto,
                        src_port=sport,
                        dst_port=dport,
                        start_ts=now,
                        last_ts=now,
                    )
                    self.flows[forward_key] = flow

                flow.spkts += 1
                flow.sbytes += size
                direction = "forward"

            flow.last_ts = now
            snapshot = self._snapshot_flow(flow, packet_size=size, direction=direction)
            self.last_any_packet_at = now
            if capture_source == "real":
                self.last_real_packet_at = now

        self.store_packet_decision(snapshot, capture_source=capture_source)

    @staticmethod
    def should_capture_packet(packet) -> bool:
        if IP not in packet:
            return False

        ip_layer = packet[IP]
        if LiveFlowScorer._is_ignored_ip(ip_layer.src) or LiveFlowScorer._is_ignored_ip(ip_layer.dst):
            return False

        if TCP in packet:
            tcp_layer = packet[TCP]
            if int(tcp_layer.sport) in IGNORED_CAPTURE_PORTS or int(tcp_layer.dport) in IGNORED_CAPTURE_PORTS:
                return False

        if UDP in packet:
            udp_layer = packet[UDP]
            if int(udp_layer.sport) in IGNORED_CAPTURE_PORTS or int(udp_layer.dport) in IGNORED_CAPTURE_PORTS:
                return False

        return True

    def score_flows(self) -> list[dict]:
        now = time.time()
        scored: list[dict] = []

        with self.lock:
            stale_keys = [key for key, flow in self.flows.items() if now - flow.last_ts > FLOW_IDLE_TTL_SECONDS]
            for key in stale_keys:
                self.flows.pop(key, None)

            flow_snapshots = list(self.flows.values())

        for flow in flow_snapshots:
            prediction = self._predict(flow.packets, flow.bytes)
            risk_score = self._risk_score_percent(prediction, flow.packets, flow.bytes)
            scored.append(
                {
                    "prediction": prediction,
                    "label": "Anomaly" if prediction == 1 else "Normal",
                    "risk_score": risk_score,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "proto": flow.proto,
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                    "dur": flow.dur,
                    "spkts": flow.spkts,
                    "dpkts": flow.dpkts,
                    "sbytes": flow.sbytes,
                    "dbytes": flow.dbytes,
                    "sload": flow.sload,
                    "dload": flow.dload,
                }
            )

        return sorted(scored, key=lambda item: item["risk_score"], reverse=True)

    def _predict(self, packets: int, bytes_value: int) -> int:
        features = pd.DataFrame([{"packets": packets, "bytes": bytes_value}])
        return int(self.model.predict(features)[0])

    def store_packet_decision(self, snapshot: dict, capture_source: str = "real") -> None:
        try:
            prediction = self._predict(snapshot["packets"], snapshot["bytes"])
            risk_score = self._risk_score_percent(prediction, snapshot["packets"], snapshot["bytes"])
            risk_label = "HIGH-RISK" if risk_score >= 70 else "SUSPICIOUS" if risk_score >= 40 else "SAFE"
            attack_type = classify_attack_type(
                {
                    "risk_score": risk_score,
                    "proto": snapshot["proto"],
                    "packets": snapshot["packets"],
                    "bytes": snapshot["bytes"],
                    "dur": snapshot["dur"],
                    "dst_port": snapshot["dst_port"],
                }
            )

            append_live_log(
                {
                    "id": uuid4().hex,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src_ip": snapshot["src_ip"],
                    "dst_ip": snapshot["dst_ip"],
                    "proto": snapshot["proto"],
                    "src_port": snapshot["src_port"],
                    "dst_port": snapshot["dst_port"],
                    "direction": snapshot["direction"],
                    "packet_size": snapshot["packet_size"],
                    "packets": snapshot["packets"],
                    "bytes": snapshot["bytes"],
                    "dur": round(snapshot["dur"], 6),
                    "spkts": snapshot["spkts"],
                    "dpkts": snapshot["dpkts"],
                    "sbytes": snapshot["sbytes"],
                    "dbytes": snapshot["dbytes"],
                    "sload": round(snapshot["sload"], 6),
                    "dload": round(snapshot["dload"], 6),
                    "prediction": prediction,
                    "label": "Anomaly" if prediction == 1 else "Normal",
                    "risk_score": risk_score,
                    "risk_label": risk_label,
                    "threat_label": risk_label,
                    "attack_type": attack_type,
                    "capture_source": capture_source,
                }
            )

            print(
                f"[SNIFFER] Captured packet from {snapshot['src_ip']} to {snapshot['dst_ip']} "
                f"| proto={snapshot['proto']} | packets={snapshot['packets']} | bytes={snapshot['bytes']} "
                f"| risk={risk_score:.1f}% | label={risk_label}",
                flush=True,
            )
        except Exception as exc:
            now = time.time()
            if now - self.last_store_error > 10:
                print(f"{Color.YELLOW}[WARN] Could not persist live packet decision: {exc}{Color.RESET}")
                self.last_store_error = now

    def get_real_idle_seconds(self) -> float:
        with self.lock:
            if self.last_real_packet_at <= 0:
                return float("inf")
            return time.time() - self.last_real_packet_at

    def generate_demo_packets(self) -> list:
        source_ip = random.choice(["192.168.1.25", "192.168.0.25", "10.0.0.25"])
        dns_dest = random.choice(["8.8.8.8", "1.1.1.1", "8.8.4.4"])
        https_dest = random.choice(["142.250.190.78", "142.250.190.14", "151.101.1.69"])
        burst_dest = random.choice(["13.107.42.16", "52.95.110.1", "104.18.12.123"])

        dns_query = random.choice(["www.google.com", "www.cloudflare.com", "api.github.com", "docs.python.org"])
        http_path = random.choice(["/", "/search", "/api/status", "/health"])

        packets = [
            IP(src=source_ip, dst=dns_dest) / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=dns_query)),
            IP(src=source_ip, dst=https_dest) / TCP(sport=54000, dport=443, flags="PA") / Raw(
                load=f"GET {http_path} HTTP/1.1\r\nHost: demo.local\r\nConnection: close\r\n\r\n".encode()
            ),
        ]

        burst_payload_sizes = [256, 384, 512, 768, 1024]
        for _ in range(6):
            payload_size = random.choice(burst_payload_sizes)
            packets.append(
                IP(src=source_ip, dst=burst_dest) / TCP(sport=55000, dport=443, flags="PA") / Raw(
                    load=os.urandom(payload_size)
                )
            )

        return packets

    @staticmethod
    def _snapshot_flow(flow: FlowStats, packet_size: int, direction: str) -> dict:
        return {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "proto": flow.proto,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "direction": direction,
            "packet_size": packet_size,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "dur": flow.dur,
            "spkts": flow.spkts,
            "dpkts": flow.dpkts,
            "sbytes": flow.sbytes,
            "dbytes": flow.dbytes,
            "sload": flow.sload,
            "dload": flow.dload,
        }

    @staticmethod
    def _risk_score_percent(prediction: int, packets: int, bytes_value: int) -> float:
        packet_factor = min(max(packets, 0) / 2500, 1.0)
        byte_factor = min(max(bytes_value, 0) / 5_000_000, 1.0)
        traffic_factor = math.sqrt((packet_factor * 0.45) + (byte_factor * 0.55))

        if prediction == 1:
            return round(70.0 + (traffic_factor * 30.0), 2)

        return round(10.0 + (traffic_factor * 25.0), 2)

    @staticmethod
    def _transport_tuple(packet) -> tuple[str, int, int]:
        if TCP in packet:
            return "tcp", int(packet[TCP].sport), int(packet[TCP].dport)
        if UDP in packet:
            return "udp", int(packet[UDP].sport), int(packet[UDP].dport)
        if ICMP in packet:
            return "icmp", int(packet[ICMP].type), int(packet[ICMP].code)
        return str(packet[IP].proto), 0, 0

    @staticmethod
    def _is_ignored_ip(value: str) -> bool:
        try:
            ip_address = ipaddress.ip_address(value)
        except ValueError:
            return False

        if ip_address.is_loopback or ip_address.is_link_local:
            return True

        return any(ip_address in network for network in IGNORED_IP_NETWORKS)


def color_for_score(score: float) -> str:
    if score >= 70:
        return Color.RED
    if score >= 40:
        return Color.YELLOW
    return Color.GREEN


def resolve_capture_interfaces(preferred_iface: str | None = None) -> list[str]:
    def unique_preserve_order(items: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    def is_virtual_iface(name: str) -> bool:
        lower_name = name.lower()
        return lower_name in {"lo", "loopback"} or lower_name.startswith(
            ("docker", "br-", "veth", "virbr", "tun", "tap", "cni", "flannel", "nflog")
        )

    def iface_ipv4_addresses(iface: object) -> list[str]:
        addresses: list[str] = []
        for attr in ("ip", "addr", "address"):
            value = getattr(iface, attr, None)
            if isinstance(value, str) and value:
                addresses.append(value)
        for attr in ("ips", "addresses"):
            value = getattr(iface, attr, None)
            if isinstance(value, (list, tuple, set)):
                addresses.extend([str(item) for item in value if item])
        return addresses

    def normalize_windows_iface(item: object) -> str | None:
        if isinstance(item, str):
            return item.strip() or None

        if isinstance(item, dict):
            for key in ("name", "description", "guid", "win_name"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            return None

        for attr in ("name", "description", "guid", "win_name"):
            value = getattr(item, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    def is_container_interface(iface: object, iface_name: str) -> bool:
        lower_name = iface_name.lower()
        if lower_name.startswith(("docker", "br-", "veth", "virbr", "tun", "tap", "cni", "flannel", "nflog")):
            return True

        for address in iface_ipv4_addresses(iface):
            try:
                ip_address = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip_address in ipaddress.ip_network("172.18.0.0/16") or ip_address.is_loopback:
                return True
        return False

    def is_physical_like(name: str) -> bool:
        lower_name = name.lower()
        return any(token in lower_name for token in ("wi-fi", "wifi", "wlan", "wlp", "ethernet", "lan", "hotspot", "mobile"))

    if preferred_iface:
        return [preferred_iface]

    route_iface = None
    try:
        route_result = conf.route.route("8.8.8.8")
        if isinstance(route_result, tuple) and route_result:
            route_iface = route_result[0]
    except Exception:
        route_iface = None

    iface_map: dict[str, object] = {}
    try:
        if hasattr(conf.ifaces, "data") and isinstance(conf.ifaces.data, dict):
            iface_map = {getattr(iface, "name", str(name)): iface for name, iface in conf.ifaces.data.items()}
        else:
            iface_map = {getattr(iface, "name", str(iface)): iface for iface in conf.ifaces.values()}
    except Exception:
        iface_map = {}

    if route_iface:
        route_iface_name = str(route_iface)
        route_iface_obj = iface_map.get(route_iface_name)
        if route_iface_obj is not None and not is_virtual_iface(route_iface_name) and not is_container_interface(
            route_iface_obj, route_iface_name
        ):
            return [route_iface_name]

    candidates: list[str] = []

    if callable(get_windows_if_list):
        try:
            for item in get_windows_if_list():
                iface_name = normalize_windows_iface(item)
                if iface_name and not is_virtual_iface(iface_name):
                    candidates.append(iface_name)
        except Exception:
            pass

    for iface_name, iface in iface_map.items():
        iface_name = getattr(iface, "name", None) or str(iface)
        if not iface_name or is_virtual_iface(iface_name):
            continue
        if is_container_interface(iface, iface_name):
            continue
        if is_physical_like(iface_name):
            candidates.append(iface_name)

    try:
        working_ifaces = get_working_ifaces()
        for iface in working_ifaces:
            iface_name = getattr(iface, "name", None) or str(iface)
            if iface_name and not is_virtual_iface(iface_name) and not is_container_interface(iface, iface_name):
                candidates.append(iface_name)
    except Exception:
        pass

    for iface_name in get_if_list():
        if not iface_name or is_virtual_iface(iface_name):
            continue

        iface_obj = iface_map.get(iface_name)
        if iface_obj is not None and is_container_interface(iface_obj, iface_name):
            continue

        candidates.append(iface_name)

    return unique_preserve_order(candidates)

def _resolve_active_interface_set(preferred_iface: str | None = None) -> list[str]:
    interfaces = resolve_capture_interfaces(preferred_iface)
    return interfaces


def _restart_sniffers(controller: LiveSnifferController, interfaces: list[str], scorer: LiveFlowScorer) -> None:
    for sniffer in controller.sniffers:
        try:
            sniffer.stop()
        except Exception:
            pass

    controller.sniffers = [
        AsyncSniffer(iface=iface_name, prn=lambda packet, _scorer=scorer: _scorer.update_from_packet(packet, "real"), store=False)
        for iface_name in interfaces
    ]

    for sniffer in controller.sniffers:
        sniffer.start()


def _sniffer_worker(controller: LiveSnifferController) -> None:
    try:
        conf.verb = 0
    except Exception:
        pass

    scorer = LiveFlowScorer(MODEL_PATH)
    controller.scorer = scorer

    if os.getenv("RESET_LIVE_TRAFFIC_ON_START", "1") != "0":
        clear_live_traffic_store()

    current_interfaces: list[str] = []

    while not controller.stop_event.is_set():
        resolved_interfaces = _resolve_active_interface_set(controller.preferred_iface)
        if resolved_interfaces != current_interfaces:
            current_interfaces = resolved_interfaces
            controller.interfaces = current_interfaces
            if current_interfaces:
                print(f"[SNIFFER] Active interface set: {', '.join(current_interfaces)}", flush=True)
                _restart_sniffers(controller, current_interfaces, scorer)
            else:
                print("[SNIFFER] No active physical interface found. Demo fallback active.", flush=True)

        if scorer.get_real_idle_seconds() >= 3.0:
            for packet in scorer.generate_demo_packets():
                scorer.update_from_packet(packet, capture_source="demo")
            time.sleep(1.0)
            continue

        time.sleep(1.0)

    for sniffer in controller.sniffers:
        try:
            sniffer.stop()
        except Exception:
            pass


def start_live_sniffer_background(preferred_iface: str | None = None) -> LiveSnifferController:
    controller = LiveSnifferController(preferred_iface=preferred_iface)
    controller.thread = threading.Thread(target=_sniffer_worker, args=(controller,), daemon=True)
    controller.thread.start()
    return controller


def print_flow_logs(scorer: LiveFlowScorer, top_n: int) -> None:
    scored = scorer.score_flows()[:top_n]
    print(f"\n{Color.BOLD}{Color.CYAN}[NetShield_AI Live Sniffer]{Color.RESET} active flows={len(scored)}")

    if not scored:
        print(f"{Color.DIM}Waiting for live IP packets on the selected adapter...{Color.RESET}")
        return

    for item in scored:
        color = color_for_score(item["risk_score"])
        status = "HIGH-RISK" if item["risk_score"] >= 70 else "LOW-RISK"
        print(
            f"{color}[{status}] {item['src_ip']} -> {item['dst_ip']} "
            f"| proto={item['proto']} | packets={item['packets']} | bytes={item['bytes']} "
            f"| dur={item['dur']:.2f}s | sload={item['sload']:.1f}B/s | dload={item['dload']:.1f}B/s "
            f"| risk={item['risk_score']:.2f}%{Color.RESET}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live socket packet sniffer with NetShield_AI anomaly scoring.")
    parser.add_argument("--iface", default=None, help="Network interface name. Omit to use Scapy default interface.")
    parser.add_argument("--interval", type=float, default=2.5, help="Seconds between scoring windows.")
    parser.add_argument("--top", type=int, default=12, help="Number of highest-risk active flows to print.")
    parser.add_argument("--list-ifaces", action="store_true", help="List Scapy-visible network interfaces and exit.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return

    print(f"{Color.BOLD}🚀 NetShield_AI live sniffer starting...{Color.RESET}")
    print(f"Model: {MODEL_PATH}")
    if args.iface:
        print(f"Requested interface: {args.iface}")
    print("Capture output is silent. Real packets are stored for the API and dashboard.")

    controller = start_live_sniffer_background(args.iface)

    try:
        while True:
            time.sleep(max(args.interval, 1.0))
    except KeyboardInterrupt:
        print("\nStopping live sniffer...")
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
