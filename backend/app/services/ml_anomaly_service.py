import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.ensemble import IsolationForest

from app.core.datetime_utils import diff_seconds

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "certutil.exe", "whoami.exe",
    "mimikatz.exe", "psexec.exe", "nc.exe", "vssadmin.exe"
}


class MLAnomalyService:
    """Unsupervised Anomaly Detection using Isolation Forest over 10-dimensional feature vectors."""

    _model: Optional[IsolationForest] = None

    @classmethod
    def get_model(cls) -> IsolationForest:
        if cls._model is None:
            # Seed a default baseline model on representative normal telemetry
            np.random.seed(42)
            # 10 features: [failed_logins, success_logins, login_freq, time_dev, new_dev, new_loc, xfer_vol, proc_nov, evt_freq, conn_freq]
            # Normal user distributions: 0-1 failed logins, 1-3 successes, low freq, 0 novelty, low transfer
            normal_samples = np.random.normal(
                loc=[0.1, 1.2, 0.5, 0.1, 0.0, 0.0, 1.0, 0.0, 2.0, 1.0],
                scale=[0.3, 0.5, 0.2, 0.1, 0.05, 0.05, 0.5, 0.05, 0.8, 0.5],
                size=(500, 10)
            )
            normal_samples = np.clip(normal_samples, 0, None)

            clf = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            clf.fit(normal_samples)
            cls._model = clf
        return cls._model

    @staticmethod
    def extract_feature_vector(
        event: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
        ueba_baseline: Optional[Dict[str, Any]] = None
    ) -> np.ndarray:
        """Construct the 10-dimensional normalized feature vector."""
        user = event.get("username")
        ts = event.get("timestamp")
        dev_id = event.get("device_id")
        loc = event.get("location")
        proc_name = (event.get("process_name") or "").lower()
        data_vol = event.get("data_volume") or 0

        # 1. failed_login_count in preceding 15m
        failed_logins = sum(
            1 for ev in recent_events
            if ev.get("event_type") == "AUTHENTICATION"
            and ev.get("status") == "FAILURE"
            and ev.get("username") == user
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 900)
        )
        if event.get("event_type") == "AUTHENTICATION" and event.get("status") == "FAILURE":
            failed_logins += 1

        # 2. successful_login_count in preceding 15m
        success_logins = sum(
            1 for ev in recent_events
            if ev.get("event_type") == "AUTHENTICATION"
            and ev.get("status") == "SUCCESS"
            and ev.get("username") == user
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 900)
        )
        if event.get("event_type") == "AUTHENTICATION" and event.get("status") == "SUCCESS":
            success_logins += 1

        # 3. login_frequency (per min in trailing 1h)
        total_auths_1h = sum(
            1 for ev in recent_events
            if ev.get("event_type") == "AUTHENTICATION"
            and ev.get("username") == user
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 3600)
        )
        login_freq = total_auths_1h / 60.0

        # 4. time_of_day_deviation [0.0 - 1.0]
        time_dev = 0.0
        if ts and ueba_baseline:
            histogram = ueba_baseline.get("active_hours_histogram", {})
            hour_count = histogram.get(str(ts.hour), 0)
            if hour_count == 0:
                time_dev = 1.0
            elif hour_count < 2:
                time_dev = 0.5

        # 5. new_device_indicator
        new_dev = 0.0
        if dev_id and ueba_baseline:
            known_devices = ueba_baseline.get("known_devices", [])
            if known_devices and dev_id not in known_devices:
                new_dev = 1.0

        # 6. new_location_indicator
        new_loc = 0.0
        if loc and ueba_baseline:
            known_locs = ueba_baseline.get("typical_locations", [])
            if known_locs and loc not in known_locs:
                new_loc = 1.0

        # 7. data_transfer_volume (scaled MB)
        xfer_vol_mb = data_vol / (1024.0 * 1024.0)

        # 8. process_novelty_score
        proc_novelty = 0.0
        if proc_name:
            if any(s in proc_name for s in SUSPICIOUS_PROCESSES):
                proc_novelty = 1.0
            elif ueba_baseline:
                known_procs = ueba_baseline.get("common_processes", [])
                if known_procs and proc_name not in known_procs:
                    proc_novelty = 0.7

        # 9. event_frequency in trailing 5m
        evt_freq_5m = sum(
            1 for ev in recent_events
            if (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 300)
        )

        # 10. connection_frequency in trailing 5m
        conn_freq_5m = sum(
            1 for ev in recent_events
            if ev.get("event_type") == "NETWORK_CONNECTION"
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 300)
        )

        return np.array([
            failed_logins,
            success_logins,
            login_freq,
            time_dev,
            new_dev,
            new_loc,
            xfer_vol_mb,
            proc_novelty,
            evt_freq_5m,
            conn_freq_5m
        ], dtype=float)

    @classmethod
    def evaluate_anomaly(
        cls,
        event: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
        ueba_baseline: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Score event against Isolation Forest and return explainable anomaly telemetry."""
        model = cls.get_model()
        vec = cls.extract_feature_vector(event, recent_events, ueba_baseline)
        
        # Decision function: lower values mean more anomalous
        raw_score = float(model.decision_function([vec])[0])
        # Map decision function roughly [-0.5, 0.5] to continuous [0, 100] anomaly score
        # where higher means more anomalous
        norm_score = float(np.clip((0.2 - raw_score) * 150.0, 0.0, 100.0))

        # Contributing feature explanations
        contributions = {}
        feature_names = [
            "failed_login_count", "successful_login_count", "login_frequency",
            "time_of_day_deviation", "new_device_indicator", "new_location_indicator",
            "data_transfer_volume", "process_novelty_score", "event_frequency", "connection_frequency"
        ]
        extreme_features = []
        for i, name in enumerate(feature_names):
            val = float(vec[i])
            contributions[name] = val
            if i in [0, 4, 5, 7] and val >= 1.0:
                extreme_features.append(name)
            elif i == 6 and val > 50.0:
                extreme_features.append(name)

        # Evidence quality classification
        if len(extreme_features) >= 3 or norm_score >= 80.0:
            evidence_quality = "HIGH"
            confidence = min(95.0, 60.0 + len(extreme_features) * 10.0)
        elif len(extreme_features) >= 1 or norm_score >= 50.0:
            evidence_quality = "MEDIUM"
            confidence = 65.0
        else:
            evidence_quality = "LOW"
            confidence = 40.0

        explanation = (
            f"Isolation Forest computed anomaly score {norm_score:.1f}/100 with {evidence_quality} evidence quality. "
            f"Key driving indicators: {', '.join(extreme_features) if extreme_features else 'subtle statistical multi-variable shift'}."
        )

        return {
            "anomaly_score": round(norm_score, 1),
            "confidence": round(confidence, 1),
            "evidence_quality": evidence_quality,
            "label": "POTENTIAL ANOMALY",
            "contributing_features": contributions,
            "extreme_features": extreme_features,
            "explanation": explanation
        }
