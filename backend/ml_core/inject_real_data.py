from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import numpy as np
import pandas as pd
from sqlalchemy import (
    BIGINT,
    DOUBLE_PRECISION,
    INTEGER,
    TIMESTAMP,
    VARCHAR,
    Column,
    MetaData,
    Table,
    URL,
    create_engine,
    text,
)

sys.path.append(str(Path(__file__).resolve().parents[1]))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from app.core.config import settings

ROW_COUNT = 60_000
CHUNK_SIZE = 5_000
RANDOM_SEED = 42


def log(message: str) -> None:
    print(message, flush=True)


def build_sync_database_url():
    if settings.database_url:
        return settings.database_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")

    return URL.create(
        "postgresql+psycopg2",
        username=settings.postgres_user,
        password=settings.postgres_password,
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )


def network_logs_table(metadata: MetaData) -> Table:
    return Table(
        "network_logs",
        metadata,
        Column("id", INTEGER, primary_key=True),
        Column("timestamp", TIMESTAMP(timezone=True), nullable=False),
        Column("src_ip", VARCHAR(64)),
        Column("dst_ip", VARCHAR(64)),
        Column("proto", VARCHAR(24)),
        Column("service", VARCHAR(64)),
        Column("state", VARCHAR(24)),
        Column("duration", DOUBLE_PRECISION),
        Column("spkts", INTEGER),
        Column("dpkts", INTEGER),
        Column("packets", INTEGER),
        Column("sbytes", BIGINT),
        Column("dbytes", BIGINT),
        Column("bytes", BIGINT),
        Column("rate", DOUBLE_PRECISION),
        Column("attack_cat", VARCHAR(80)),
        Column("label", INTEGER),
    )


def random_private_ip(rng: np.random.Generator, size: int) -> list[str]:
    networks = rng.choice(["10", "172", "192"], size=size, p=[0.58, 0.24, 0.18])
    ips: list[str] = []
    for network in networks:
        if network == "10":
            ips.append(f"10.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}")
        elif network == "172":
            ips.append(f"172.{rng.integers(16, 32)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}")
        else:
            ips.append(f"192.168.{rng.integers(0, 256)}.{rng.integers(1, 255)}")
    return ips


def random_destination_ip(rng: np.random.Generator, size: int) -> list[str]:
    public_blocks = ["8.8", "13.107", "34.117", "52.95", "104.18", "142.250", "151.101", "172.217"]
    blocks = rng.choice(public_blocks, size=size)
    return [f"{block}.{rng.integers(0, 256)}.{rng.integers(1, 255)}" for block in blocks]


def generate_network_logs(row_count: int = ROW_COUNT) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)
    ids = np.arange(1, row_count + 1)
    timestamps = [datetime.now(timezone.utc) - timedelta(seconds=int(row_count - item)) for item in ids]

    attack_categories = np.array(
        ["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Worms"]
    )
    attack_probabilities = np.array([0.68, 0.09, 0.07, 0.055, 0.045, 0.035, 0.015, 0.008, 0.002])
    attack_cat = rng.choice(attack_categories, size=row_count, p=attack_probabilities)
    label = (attack_cat != "Normal").astype(int)

    proto = rng.choice(["tcp", "udp", "icmp"], size=row_count, p=[0.72, 0.23, 0.05])
    service = rng.choice(
        ["http", "https", "dns", "ftp", "smtp", "ssh", "ssl", "dhcp", "-", "snmp"],
        size=row_count,
        p=[0.24, 0.28, 0.16, 0.045, 0.045, 0.055, 0.07, 0.035, 0.05, 0.02],
    )
    state = rng.choice(["FIN", "CON", "INT", "REQ", "RST", "ECO"], size=row_count, p=[0.42, 0.23, 0.16, 0.09, 0.07, 0.03])

    normal_mask = label == 0
    anomaly_mask = ~normal_mask

    spkts = np.zeros(row_count, dtype=np.int64)
    dpkts = np.zeros(row_count, dtype=np.int64)
    sbytes = np.zeros(row_count, dtype=np.int64)
    dbytes = np.zeros(row_count, dtype=np.int64)
    duration = np.zeros(row_count)

    normal_count = int(normal_mask.sum())
    anomaly_count = int(anomaly_mask.sum())

    spkts[normal_mask] = rng.poisson(lam=18, size=normal_count) + 1
    dpkts[normal_mask] = rng.poisson(lam=22, size=normal_count) + 1
    sbytes[normal_mask] = rng.lognormal(mean=8.0, sigma=0.75, size=normal_count).astype(np.int64)
    dbytes[normal_mask] = rng.lognormal(mean=8.25, sigma=0.75, size=normal_count).astype(np.int64)
    duration[normal_mask] = rng.gamma(shape=1.8, scale=0.45, size=normal_count)

    spkts[anomaly_mask] = rng.poisson(lam=120, size=anomaly_count) + rng.integers(5, 120, size=anomaly_count)
    dpkts[anomaly_mask] = rng.poisson(lam=80, size=anomaly_count) + rng.integers(0, 80, size=anomaly_count)
    sbytes[anomaly_mask] = rng.lognormal(mean=10.25, sigma=1.0, size=anomaly_count).astype(np.int64)
    dbytes[anomaly_mask] = rng.lognormal(mean=10.0, sigma=1.1, size=anomaly_count).astype(np.int64)
    duration[anomaly_mask] = rng.gamma(shape=2.4, scale=0.75, size=anomaly_count)

    dos_mask = attack_cat == "DoS"
    generic_mask = attack_cat == "Generic"
    worms_mask = attack_cat == "Worms"

    spkts[dos_mask] *= 4
    dpkts[dos_mask] *= 2
    sbytes[dos_mask] *= 3
    dbytes[dos_mask] *= 2

    spkts[generic_mask] *= 2
    sbytes[generic_mask] *= 2

    spkts[worms_mask] *= 6
    dpkts[worms_mask] *= 4
    sbytes[worms_mask] *= 6
    dbytes[worms_mask] *= 5

    normal_indices = np.where(normal_mask)[0]
    anomaly_indices = np.where(anomaly_mask)[0]

    bursty_normal_indices = rng.choice(normal_indices, size=max(1, int(normal_count * 0.08)), replace=False)
    normal_packet_multiplier = rng.integers(2, 8, size=len(bursty_normal_indices))
    normal_byte_multiplier = rng.integers(2, 10, size=len(bursty_normal_indices))
    spkts[bursty_normal_indices] *= normal_packet_multiplier
    dpkts[bursty_normal_indices] *= normal_packet_multiplier
    sbytes[bursty_normal_indices] *= normal_byte_multiplier
    dbytes[bursty_normal_indices] *= normal_byte_multiplier

    low_signal_anomaly_indices = rng.choice(anomaly_indices, size=max(1, int(anomaly_count * 0.18)), replace=False)
    spkts[low_signal_anomaly_indices] = rng.poisson(lam=28, size=len(low_signal_anomaly_indices)) + 1
    dpkts[low_signal_anomaly_indices] = rng.poisson(lam=31, size=len(low_signal_anomaly_indices)) + 1
    sbytes[low_signal_anomaly_indices] = rng.lognormal(mean=8.35, sigma=0.85, size=len(low_signal_anomaly_indices)).astype(
        np.int64
    )
    dbytes[low_signal_anomaly_indices] = rng.lognormal(mean=8.4, sigma=0.85, size=len(low_signal_anomaly_indices)).astype(
        np.int64
    )

    packets = spkts + dpkts
    total_bytes = sbytes + dbytes
    duration = np.clip(duration, 0.001, None)
    rate = packets / duration

    return pd.DataFrame(
        {
            "id": ids,
            "timestamp": timestamps,
            "src_ip": random_private_ip(rng, row_count),
            "dst_ip": random_destination_ip(rng, row_count),
            "proto": proto,
            "service": service,
            "state": state,
            "duration": np.round(duration, 6),
            "spkts": spkts.astype(int),
            "dpkts": dpkts.astype(int),
            "packets": packets.astype(int),
            "sbytes": sbytes.astype(int),
            "dbytes": dbytes.astype(int),
            "bytes": total_bytes.astype(int),
            "rate": np.round(rate, 6),
            "attack_cat": attack_cat,
            "label": label.astype(int),
        }
    )


def bulk_insert_network_logs(frame: pd.DataFrame) -> None:
    engine = create_engine(build_sync_database_url(), pool_pre_ping=True)
    metadata = MetaData()
    table = network_logs_table(metadata)

    with engine.begin() as connection:
        metadata.create_all(connection, tables=[table])
        connection.execute(text("TRUNCATE TABLE network_logs"))

        for start in range(0, len(frame), CHUNK_SIZE):
            chunk = frame.iloc[start : start + CHUNK_SIZE]
            connection.execute(table.insert(), chunk.to_dict(orient="records"))
            log(f"Inserted rows {start + 1:,} - {start + len(chunk):,}")


def main() -> None:
    log("🚀 NetShield AI | Large-Scale Network Log Injection")
    log("=" * 64)
    log(f"Generating {ROW_COUNT:,} UNSW-NB15-style network traffic rows...")

    frame = generate_network_logs()
    normal_rows = int((frame["label"] == 0).sum())
    anomaly_rows = int((frame["label"] == 1).sum())

    log(f"Normal rows: {normal_rows:,}")
    log(f"Anomaly rows: {anomaly_rows:,}")
    log("Bulk inserting into PostgreSQL network_logs...")

    bulk_insert_network_logs(frame)
    log("✅ Large-scale dataset injection completed successfully.")


if __name__ == "__main__":
    main()
