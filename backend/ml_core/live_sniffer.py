from __future__ import annotations

import argparse
import math
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import joblib
import pandas as pd

SCAPY_CONFIG_HOME = Path(__file__).resolve().parent / ".scapy_config"
SCAPY_CONFIG_HOME.mkdir(exist_ok=True)
os.environ.setdefault("XDG_CONFIG_HOME", str(SCAPY_CONFIG_HOME))

from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer, conf, get_if_list

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.live_traffic_store import append_live_log, classify_attack_type

MODEL_PATH = Path(__file__).resolve().parent / "anomaly_model.pkl"
FLOW_IDLE_TTL_SECONDS = 90


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


class LiveFlowScorer:
    def __init__(self, model_path: Path) -> None:
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}. Run train_anomaly_model.py first.")

        self.model = joblib.load(model_path)
        self.flows: dict[tuple, FlowStats] = {}
        self.lock = threading.Lock()
        self.last_store_error = 0.0

    def update_from_packet(self, packet) -> None:
        if IP not in packet:
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

        self.store_packet_decision(snapshot)

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

    def store_packet_decision(self, snapshot: dict) -> None:
        try:
            prediction = self._predict(snapshot["packets"], snapshot["bytes"])
            risk_score = self._risk_score_percent(prediction, snapshot["packets"], snapshot["bytes"])
            risk_label = "HIGH-RISK" if risk_score >= 70 else "MEDIUM-RISK" if risk_score >= 40 else "LOW-RISK"
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
                    "attack_type": attack_type,
                }
            )
        except Exception as exc:
            now = time.time()
            if now - self.last_store_error > 10:
                print(f"{Color.YELLOW}[WARN] Could not persist live packet decision: {exc}{Color.RESET}")
                self.last_store_error = now

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


def color_for_score(score: float) -> str:
    if score >= 70:
        return Color.RED
    if score >= 40:
        return Color.YELLOW
    return Color.GREEN


def print_flow_logs(scorer: LiveFlowScorer, top_n: int) -> None:
    scored = scorer.score_flows()[:top_n]
    print(f"\n{Color.BOLD}{Color.CYAN}[NetShield_AI Live Sniffer]{Color.RESET} active flows={len(scored)}")

    if not scored:
        print(f"{Color.DIM}Waiting for live IP packets... start traffic_generator.py in another terminal.{Color.RESET}")
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

    scorer = LiveFlowScorer(MODEL_PATH)
    iface = args.iface or conf.iface

    print(f"{Color.BOLD}🚀 NetShield_AI dynamic live sniffer starting...{Color.RESET}")
    print(f"Model: {MODEL_PATH}")
    print(f"Interface: {iface}")
    print("Tip: On Windows, run terminal as Administrator and install Npcap with loopback support.\n")

    sniffer = AsyncSniffer(iface=args.iface, prn=scorer.update_from_packet, store=False)
    sniffer.start()

    try:
        while True:
            time.sleep(args.interval)
            print_flow_logs(scorer, top_n=args.top)
    except KeyboardInterrupt:
        print("\nStopping live sniffer...")
    finally:
        sniffer.stop()


if __name__ == "__main__":
    main()
