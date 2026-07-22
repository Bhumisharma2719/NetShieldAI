from pathlib import Path
import sys

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sqlalchemy import URL, create_engine

sys.path.append(str(Path(__file__).resolve().parents[1]))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from app.core.config import settings

MODEL_PATH = Path(__file__).resolve().parent / "anomaly_model.pkl"
CONFUSION_MATRIX_PATH = Path(__file__).resolve().parent / "confusion_matrix.png"
FEATURE_COLUMNS = ["packets", "bytes"]


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


def fetch_network_logs() -> pd.DataFrame:
    log("🔌 Connecting to PostgreSQL database...")
    query = """
        SELECT packets, bytes, attack_cat, label
        FROM network_logs
        WHERE packets IS NOT NULL
          AND bytes IS NOT NULL
    """

    try:
        engine = create_engine(build_sync_database_url(), pool_pre_ping=True)
        with engine.connect() as connection:
            frame = pd.read_sql_query(query, connection)
    except Exception as exc:
        raise RuntimeError(f"❌ Database connection/fetch failed: {exc}") from exc

    log("✅ PostgreSQL connection successful")
    log(f"📦 Total rows fetched from PostgreSQL: {len(frame):,}")
    return frame


def build_target(frame: pd.DataFrame) -> pd.Series:
    if "label" in frame.columns and frame["label"].notna().any():
        log("🎯 Target source column: label")
        return pd.to_numeric(frame["label"], errors="coerce").fillna(0).astype(int).clip(0, 1)

    if "attack_cat" not in frame.columns:
        raise ValueError("❌ Target column missing. Expected 'label' or 'attack_cat' in network_logs table.")

    log("🎯 Target source column: attack_cat")
    return frame["attack_cat"].fillna("Normal").astype(str).str.lower().ne("normal").astype(int)


def preprocess(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    log("🧹 Preprocessing network logs...")
    missing_features = [column for column in FEATURE_COLUMNS if column not in frame.columns]
    if missing_features:
        raise ValueError(f"❌ Missing required feature columns: {', '.join(missing_features)}")

    cleaned = frame.dropna(subset=FEATURE_COLUMNS).copy()
    cleaned[FEATURE_COLUMNS] = cleaned[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    cleaned = cleaned.dropna(subset=FEATURE_COLUMNS)

    X = cleaned[FEATURE_COLUMNS].clip(lower=0)
    y = build_target(cleaned)

    if len(X) < 1_000:
        raise ValueError(f"❌ Training needs a larger dataset. Only {len(X):,} valid rows found.")
    if y.nunique() < 2:
        raise ValueError("❌ Training needs both normal and anomaly rows, but only one class was found.")

    log(f"✅ Valid training rows: {len(X):,}")
    log(f"✅ Selected features: {', '.join(FEATURE_COLUMNS)}")
    log(f"✅ Normal rows: {(y == 0).sum():,} | Anomaly rows: {(y == 1).sum():,}")
    return X, y


def train_model(X: pd.DataFrame, y: pd.Series) -> tuple[RandomForestClassifier, pd.DataFrame, pd.Series, pd.Series]:
    log("✂️ Splitting data into 80% training and 20% testing...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    log("🌲 Training Random Forest Classifier on large-scale traffic data...")
    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    log("✅ Model Training Status: Completed")
    log(f"✅ Training rows: {len(X_train):,} | Testing rows: {len(X_test):,}")
    return model, X_test, y_test, y_pred


def evaluate_model(y_test: pd.Series, y_pred: pd.Series) -> None:
    accuracy = accuracy_score(y_test, y_pred) * 100
    report = classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"])

    log("\n📊 Upgraded Model Evaluation")
    log("-" * 64)
    log(f"🎯 Accuracy Score: {accuracy:.2f}%")
    log("\n📋 Classification Report:")
    log(report)


def save_model(model: RandomForestClassifier) -> None:
    joblib.dump(model, MODEL_PATH)
    log(f"💾 Saved upgraded model: {MODEL_PATH}")


def save_confusion_matrix(y_test: pd.Series, y_pred: pd.Series) -> None:
    matrix = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(7, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal", "Anomaly"],
        yticklabels=["Normal", "Anomaly"],
    )
    plt.title("NetShield AI - Large Dataset Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=160)
    plt.close()
    log(f"🖼️ Saved confusion matrix image: {CONFUSION_MATRIX_PATH}")


def main() -> None:
    log("🚀 NetShield AI | Large-Scale Anomaly Model Training")
    log("=" * 64)

    try:
        frame = fetch_network_logs()
        if frame.empty:
            raise ValueError("❌ No rows found in network_logs table.")

        X, y = preprocess(frame)
        model, _X_test, y_test, y_pred = train_model(X, y)
        evaluate_model(y_test, y_pred)
        save_model(model)
        save_confusion_matrix(y_test, y_pred)
        log("\n✅ Large-scale training pipeline finished successfully.")
    except Exception as exc:
        log("\n🚨 Training pipeline failed.")
        log(str(exc))
        raise


if __name__ == "__main__":
    main()
