"""The trigger types core ships (docs/ALERT_AUTOMATION.md, *Triggers*)."""

from typing import Optional

from pydantic import Field, field_validator
from sqlalchemy import func, select, text

from saq.alert_automation.rules import AlertAutomationTrigger, Candidate, TriggerConfig
from saq.configuration.config import get_config
from saq.database.model import Alert, ExternalRemediationCheck
from saq.database.private_session import private_transaction
from saq.remediation.external.types import CheckResult


class ExternalRemediationConfirmedConfig(TriggerConfig):
    probe: str = Field(..., description="the name of the external_remediation_probe_* whose confirmations fire the rule")
    max_age_hours: int = Field(default=120, gt=0, description="only confirmations updated within this many hours (by the database's clock) fire the rule")

    @field_validator("probe")
    @classmethod
    def _probe_exists(cls, value: str) -> str:
        # raises ValueError when no external_remediation_probe_* block has this name
        get_config().get_external_remediation_probe_config(value)
        return value


class ExternalRemediationConfirmedTrigger(AlertAutomationTrigger):
    """An alert one of whose external_remediation_check rows from the configured probe is
    CONFIRMED and was updated within max_age_hours. One confirmed delivery is enough. A check row
    whose alert has no alerts row yet (the probe's module often confirms before the alert exists)
    matches nothing until it has one."""

    config_class = ExternalRemediationConfirmedConfig
    template_fields = frozenset({"probe", "observable", "event_time"})

    def _confirmed(self):
        config: ExternalRemediationConfirmedConfig = self.config
        return (ExternalRemediationCheck.probe_name == config.probe,
                ExternalRemediationCheck.result == CheckResult.CONFIRMED.value,
                # max_age_hours is validated as an int
                ExternalRemediationCheck.update_time >= func.DATE_SUB(
                    func.NOW(), text(f"INTERVAL {int(config.max_age_hours)} HOUR")))

    def candidates(self, after: Optional[str], limit: int) -> list[Candidate]:
        conditions = list(self._confirmed())
        if after is not None:
            conditions.append(ExternalRemediationCheck.alert_uuid > after)

        with private_transaction() as session:
            alert_uuids = list(session.execute(
                select(ExternalRemediationCheck.alert_uuid)
                .join(Alert, Alert.uuid == ExternalRemediationCheck.alert_uuid)
                .where(*conditions)
                .group_by(ExternalRemediationCheck.alert_uuid)
                .order_by(ExternalRemediationCheck.alert_uuid)
                .limit(limit)).scalars())
            if not alert_uuids:
                return []

            confirmations: dict[str, list[dict]] = {alert_uuid: [] for alert_uuid in alert_uuids}
            for check_id, alert_uuid, observable_type, observable_value, update_time in session.execute(
                    select(ExternalRemediationCheck.id, ExternalRemediationCheck.alert_uuid,
                           ExternalRemediationCheck.observable_type, ExternalRemediationCheck.observable_value,
                           ExternalRemediationCheck.update_time)
                    .where(*self._confirmed(), ExternalRemediationCheck.alert_uuid.in_(alert_uuids))
                    .order_by(ExternalRemediationCheck.id)):
                confirmations[alert_uuid].append({
                    "check_id": check_id, "observable_type": observable_type, "observable_value": observable_value,
                    "confirmed_at": update_time.isoformat() if update_time else None})

        return [Candidate(alert_uuid, {"probe": self.config.probe, "confirmations": confirmations[alert_uuid]})
                for alert_uuid in alert_uuids]

    def still_holds(self, alert_uuids: list[str]) -> set[str]:
        if not alert_uuids:
            return set()

        with private_transaction() as session:
            return set(session.execute(
                select(ExternalRemediationCheck.alert_uuid).distinct()
                .where(*self._confirmed(), ExternalRemediationCheck.alert_uuid.in_(alert_uuids))).scalars())

    def template_values(self, evidence: dict) -> dict[str, str]:
        confirmations = evidence.get("confirmations", [])
        times = [c["confirmed_at"] for c in confirmations if c.get("confirmed_at")]
        return {
            "probe": evidence.get("probe", self.config.probe),
            "observable": ", ".join(sorted({c["observable_value"] for c in confirmations})),
            "event_time": max(times) if times else "an unknown time",
        }

    def evidence_observables(self, evidence: dict) -> list[tuple[str, str]]:
        return [(c["observable_type"], c["observable_value"]) for c in evidence.get("confirmations", [])]
