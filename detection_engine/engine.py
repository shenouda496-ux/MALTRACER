"""
engine.py  (detection_engine)
──────────────────────────────
DetectionEngine — applies rules, scores the event, classifies the
threat, then hands off to ContainmentEngine immediately.
"""

import uuid
from datetime import datetime

from detection_engine.rule_engine   import RuleEngine
from detection_engine.rule_parser   import load_rules
from detection_engine.scoring       import ScoringModel
from detection_engine.classifier    import ThreatClassifier

from containment.containment_engine import ContainmentEngine
from logging_system.logger          import get_logger
from utils.resources                import resource_path

logger = get_logger(__name__)


class DetectionEngine:

    def __init__(self):
        self.rule_engine  = RuleEngine()
        self.scoring      = ScoringModel()
        self.classifier   = ThreatClassifier()

        self.rules = []
        # resource_path resolves correctly both from source and from a
        # PyInstaller bundle (where rules are added as datas under the same
        # detection_engine/rules/ relative path).
        rules_dir = resource_path("detection_engine", "rules")
        self.rules += load_rules(str(rules_dir / "network.rules"))
        self.rules += load_rules(str(rules_dir / "process.rules"))
        self.rules += load_rules(str(rules_dir / "file.rules"))

        self.containment = ContainmentEngine()

        logger.info(
            f"[ENGINE] DetectionEngine ready. "
            f"rules_loaded={len(self.rules)}"
        )

    def process_event(self, event: dict) -> dict:

        if "incident_id" not in event:
            event["incident_id"] = self._new_incident_id()

        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat()

        # ── Rule matching ─────────────────────────────────────
        matched = self.rule_engine.match(event, self.rules)

        # ── Scoring ───────────────────────────────────────────
        score = self.scoring.calculate(matched) if matched else 0
        level = self.classifier.classify(score)

        event["risk_score"]   = score
        event["threat_level"] = level

        if "threat_category" not in event:
            event["threat_category"] = self._infer_category(matched, score)

        log_level = {
            "HIGH":   logger.warning,
            "MEDIUM": logger.info,
            "LOW":    logger.debug,
        }.get(level, logger.debug)

        log_level(
            f"[ENGINE] Event scored. "
            f"incident={event['incident_id']} "
            f"source={event.get('source', 'unknown')} "
            f"score={score} level={level} "
            f"pid={event.get('pid')} "
            f"file={event.get('file_path')} "
            f"ip={event.get('remote_ip')}"
        )

        self.containment.handle(event)

        return event

    def _new_incident_id(self) -> str:
        return f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

    def _infer_category(self, matched: list, score: int) -> str:
        if not matched:
            return "Unknown"
        names = [r.get("name", "") for r in matched]
        if any("network" in n.lower() for n in names):
            return "Network anomaly"
        if any("process" in n.lower() for n in names):
            return "Process anomaly"
        if any("file" in n.lower() for n in names):
            return "File anomaly"
        return "Unknown"