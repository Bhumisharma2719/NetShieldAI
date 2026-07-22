from pathlib import Path

import joblib
import pandas as pd


class ModelNotFoundError(FileNotFoundError):
    pass


class AnomalyPredictionService:
    def __init__(self) -> None:
        backend_dir = Path(__file__).resolve().parents[2]
        self.model_path = backend_dir / "ml_core" / "anomaly_model.pkl"
        self._model = None

    def load_model(self):
        if self._model is not None:
            return self._model

        if not self.model_path.exists():
            raise ModelNotFoundError(
                f"Model file not found at {self.model_path}. Run backend/ml_core/train_anomaly_model.py first."
            )

        self._model = joblib.load(self.model_path)
        return self._model

    def predict(self, packets: int, bytes_value: int) -> dict:
        model = self.load_model()
        features = pd.DataFrame([{"packets": packets, "bytes": bytes_value}])
        prediction = int(model.predict(features)[0])

        return {
            "prediction": prediction,
            "label": "Anomaly" if prediction == 1 else "Normal",
            "risk_score": self.calculate_risk_score(prediction, packets, bytes_value),
        }

    @staticmethod
    def calculate_risk_score(prediction: int, packets: int, bytes_value: int) -> float:
        packets = max(packets, 0)
        bytes_value = max(bytes_value, 0)

        packet_factor = min(packets / 2500, 1.0)
        byte_factor = min(bytes_value / 5_000_000, 1.0)
        traffic_factor = (packet_factor * 0.45) + (byte_factor * 0.55)

        if prediction == 1:
            return round(7.0 + (traffic_factor * 3.0), 2)

        return round(1.0 + (traffic_factor * 2.5), 2)


anomaly_service = AnomalyPredictionService()
