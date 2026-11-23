"""Isolation Forest analysis for File Vault activity logs.

Input rows should contain: id, actor_key, actor_user_id, ip_hash, file_id,
created_at, event and result. Only pseudonymous actor/IP fingerprints are
stored for unauthenticated events; no raw IP addresses or passwords are used.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import math
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

WINDOW_MINUTES = 15
MIN_WINDOWS_FOR_MODEL = 3


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _floor_window(value: datetime, minutes: int = WINDOW_MINUTES) -> datetime:
    minute = (value.minute // minutes) * minutes
    return value.replace(minute=minute, second=0, microsecond=0)


def _event_kind(event: str, result: str) -> str:
    event = (event or "").upper()
    result = (result or "").upper()
    if "LOGIN" in event and result in {"DENIED", "FAILED"}:
        return "failed_login"
    if event in {"DOWNLOAD", "OWNER_DOWNLOAD"} and result == "SUCCESS":
        return "download"
    if result in {"DENIED", "FAILED"} or event in {"ACCESS_DENIED", "PASSWORD_CHECK"} and result == "DENIED":
        return "denied"
    if event in {"VIEW", "ACCESS"}:
        return "view"
    if event in {"ENCRYPT", "UPLOAD"}:
        return "upload"
    if "LINK" in event:
        return "link"
    return "other"


def _build_windows(rows: Iterable[dict]):
    groups: dict[tuple[str, datetime], list[dict]] = defaultdict(list)
    for row in rows:
        created = _parse_dt(row["created_at"])
        actor = row.get("actor_key") or "legacy:unknown"
        bucket = _floor_window(created)
        item = dict(row)
        item["_dt"] = created
        item["_kind"] = _event_kind(item.get("event", ""), item.get("result", ""))
        groups[(actor, bucket)].append(item)

    windows = []
    for (actor, bucket), events in groups.items():
        events.sort(key=lambda item: item["_dt"])
        kinds = Counter(item["_kind"] for item in events)
        file_ids = {item.get("file_id") for item in events if item.get("file_id")}
        ip_hashes = {item.get("ip_hash") for item in events if item.get("ip_hash")}
        hours = [item["_dt"].hour for item in events]
        after_hours = sum(1 for hour in hours if hour < 6 or hour >= 22)

        # Maximum event burst in any rolling five-minute interval.
        peak_5m = 0
        left = 0
        for right, current in enumerate(events):
            while current["_dt"] - events[left]["_dt"] > timedelta(minutes=5):
                left += 1
            peak_5m = max(peak_5m, right - left + 1)

        features = {
            "total_events": len(events),
            "failed_logins": kinds["failed_login"],
            "downloads": kinds["download"],
            "denied_events": kinds["denied"] + kinds["failed_login"],
            "views": kinds["view"],
            "uploads": kinds["upload"],
            "link_events": kinds["link"],
            "unique_files": len(file_ids),
            "unique_ip_fingerprints": len(ip_hashes),
            "after_hours_events": after_hours,
            "peak_events_5m": peak_5m,
            "hour_sin": math.sin(2 * math.pi * bucket.hour / 24),
            "hour_cos": math.cos(2 * math.pi * bucket.hour / 24),
        }
        windows.append({
            "actor_key": actor,
            "window_start": bucket,
            "window_end": bucket + timedelta(minutes=WINDOW_MINUTES),
            "events": events,
            "features": features,
            "first_event": events[0],
        })
    windows.sort(key=lambda item: item["window_start"])
    return windows


def _rule_findings(features: dict) -> list[tuple[str, str, str]]:
    """Return (category, severity, evidence) using transparent safeguards."""
    findings = []
    failed = features["failed_logins"]
    downloads = features["downloads"]
    denied = features["denied_events"]
    total = features["total_events"]
    unique_files = features["unique_files"]
    peak = features["peak_events_5m"]

    if failed >= 2:
        severity = "Critical" if failed >= 6 else "High" if failed >= 4 else "Medium" if failed >= 3 else "Low"
        findings.append(("Repeated failed logins", severity, f"{failed} failed login attempt{'s' if failed > 1 else ''} in 15 minutes"))
    if downloads >= 5:
        severity = "Critical" if downloads >= 15 else "High" if downloads >= 10 else "Medium"
        findings.append(("Excessive downloads", severity, f"{downloads} successful downloads in 15 minutes"))
    if denied >= 2:
        severity = "Critical" if denied >= 6 else "High" if denied >= 4 else "Medium" if denied >= 3 else "Low"
        findings.append(("Repeated denied access", severity, f"{denied} denied or failed action{'s' if denied > 1 else ''} in 15 minutes"))
    if peak >= 10 or total >= 20:
        severity = "Critical" if peak >= 20 or total >= 40 else "High" if peak >= 14 or total >= 28 else "Medium"
        findings.append(("High-frequency activity", severity, f"{total} events in this 15-minute window; peak of {peak} in five minutes"))
    if unique_files >= 4:
        severity = "High" if unique_files >= 8 else "Medium"
        findings.append(("Abnormal file-access pattern", severity, f"Activity involved {unique_files} different files in 15 minutes"))
    if features["unique_ip_fingerprints"] >= 3 and total >= 4:
        findings.append(("Multiple network origins", "Medium", f"Activity used {features['unique_ip_fingerprints']} network fingerprints in 15 minutes"))
    if features["after_hours_events"] >= 4 and total >= 5:
        findings.append(("Unusual access time", "Low", f"{features['after_hours_events']} events occurred between 10 PM and 6 AM UTC"))
    return findings


def detect_anomalies(rows: Iterable[dict], contamination: float = 0.10) -> dict:
    """Run Isolation Forest on actor/15-minute profiles and merge rule signals.

    The model is fitted only when there are at least three profile windows.
    Transparent behaviour thresholds still operate for smaller datasets, so a
    fresh/demo database can show deterministic rule alerts without pretending
    the ML model had enough baseline data.
    """
    windows = _build_windows(rows)
    if not windows:
        return {
            "windows": 0,
            "model_trained": False,
            "model_message": "No activity logs are available in the selected period.",
            "results": [],
        }

    feature_names = [
        "total_events", "failed_logins", "downloads", "denied_events", "views",
        "uploads", "link_events", "unique_files", "unique_ip_fingerprints",
        "after_hours_events", "peak_events_5m", "hour_sin", "hour_cos",
    ]
    matrix = np.asarray([[window["features"][key] for key in feature_names] for window in windows], dtype=float)
    model_trained = len(windows) >= MIN_WINDOWS_FOR_MODEL
    predictions = np.ones(len(windows), dtype=int)
    scores = np.zeros(len(windows), dtype=float)
    model_message = f"Need at least {MIN_WINDOWS_FOR_MODEL} distinct actor/time windows before Isolation Forest can establish a baseline. Behaviour thresholds remain active."

    if model_trained:
        model = IsolationForest(
            n_estimators=200,
            contamination=min(max(float(contamination), 0.01), 0.25),
            random_state=42,
            max_samples="auto",
        )
        predictions = model.fit_predict(matrix)
        raw = -model.decision_function(matrix)
        order = np.argsort(np.argsort(raw, kind="mergesort"), kind="mergesort")
        if len(raw) > 1:
            scores = order / float(len(raw) - 1)
        else:
            scores = np.zeros(len(raw), dtype=float)
        model_message = f"Isolation Forest trained on {len(windows)} actor/time windows using {len(rows)} activity events."

    results = []
    for index, window in enumerate(windows):
        rule_findings = _rule_findings(window["features"])
        model_flag = bool(model_trained and predictions[index] == -1)
        if not rule_findings and not model_flag:
            continue

        if rule_findings:
            category, severity, evidence = max(
                rule_findings,
                key=lambda finding: {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[finding[1]],
            )
            all_evidence = [finding[2] for finding in rule_findings]
            source = "Isolation Forest + behaviour rules" if model_flag else "Behaviour rules"
            summary = "; ".join(all_evidence)
            rule_score = max({"Low": .55, "Medium": .68, "High": .82, "Critical": .95}[item[1]] for item in rule_findings)
            score = max(float(scores[index]), rule_score)
        else:
            category = "Unusual activity pattern"
            severity = "Medium" if scores[index] < .80 else "High"
            summary = "Isolation Forest identified this activity window as an outlier compared with the observed baseline."
            source = "Isolation Forest"
            score = max(.55, float(scores[index]))
            all_evidence = [summary]

        actor_key = window["actor_key"]
        actor_user_id = None
        if actor_key.startswith("user:"):
            try:
                actor_user_id = int(actor_key.split(":", 1)[1])
            except ValueError:
                actor_user_id = None
        actor_label = "Unidentified visitor"
        if actor_user_id:
            actor_label = f"User #{actor_user_id}"
        elif actor_key.startswith("ip:"):
            actor_label = "Visitor · " + actor_key[-8:]
        elif actor_key.startswith("login:"):
            actor_label = "Login source · " + actor_key[-8:]
        elif actor_key.startswith("legacy:"):
            actor_label = "Older activity · " + actor_key.split(":", 1)[1][:18]

        feature_values = window["features"]
        results.append({
            "actor_key": actor_key,
            "actor_user_id": actor_user_id,
            "actor_label": actor_label,
            "window_start": window["window_start"].isoformat(timespec="seconds"),
            "window_end": window["window_end"].isoformat(timespec="seconds"),
            "event_count": feature_values["total_events"],
            "failed_logins": feature_values["failed_logins"],
            "downloads": feature_values["downloads"],
            "denied_events": feature_values["denied_events"],
            "unique_files": feature_values["unique_files"],
            "anomaly_score": round(min(max(score, 0.0), 1.0), 3),
            "source": source,
            "category": category,
            "severity": severity,
            "summary": summary,
            "evidence": all_evidence,
        })

    results.sort(key=lambda item: (item["anomaly_score"], item["window_start"]), reverse=True)
    return {
        "windows": len(windows),
        "model_trained": model_trained,
        "model_message": model_message,
        "results": results,
    }
