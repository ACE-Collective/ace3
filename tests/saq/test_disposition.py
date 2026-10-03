"""Alert dispositions: the configured list, its validation, and its classification
(saq/disposition.py, the dispositions: and disposition_classification: config blocks)."""

import copy
import logging
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from saq.configuration.config import get_config, get_engine_config
from saq.configuration.schema import ACEConfig, DispositionConfig, REMOVED_DISPOSITION_CONFIG_KEYS
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE, DISPOSITION_OPEN
from saq.database.model import Event
from saq.disposition import (
    DEFAULT_DISPOSITION_CSS,
    DISPOSITION_CLASS_FP,
    DISPOSITION_CLASS_TP,
    get_disposition_class,
    get_disposition_css,
    get_disposition_rank,
    get_dispositions,
    get_selectable_dispositions,
    initialize_dispositions,
    is_selectable_disposition,
    is_valid_disposition,
)

pytestmark = pytest.mark.unit


def _config_data() -> dict:
    """A copy of the loaded configuration's raw data, to validate with one thing changed."""
    return copy.deepcopy(get_config().raw._data)


class TestTheList:
    def test_the_modal_order_is_unchanged(self):
        """The dispositions block is in the order the modals have always shown: OPEN first, then
        the order of the old VALID_DISPOSITIONS constant."""
        assert list(get_dispositions()) == [
            "OPEN", "FALSE_POSITIVE", "IGNORE", "UNKNOWN", "REVIEWED", "GRAYWARE",
            "POLICY_VIOLATION", "RECONNAISSANCE", "WEAPONIZATION", "DELIVERY", "EXPLOITATION",
            "INSTALLATION", "COMMAND_AND_CONTROL", "EXFIL", "DAMAGE",
        ]

    @pytest.mark.parametrize("removed", [
        "AUTHORIZED", "DATA_CONTROL", "INSIDER_DATA_CONTROL", "INSIDER_DATA_EXFIL",
        "APPROVED_BUSINESS", "APPROVED_PERSONAL",
    ])
    def test_the_six_unused_dispositions_are_gone(self, removed):
        assert not is_valid_disposition(removed)

    def test_settings(self):
        delivery = get_dispositions()[DISPOSITION_DELIVERY]
        assert delivery == {"rank": 100, "css": "danger", "show_save_to_event": True, "analyst_selectable": True}
        assert get_disposition_rank(DISPOSITION_DELIVERY) == 100
        assert get_disposition_css(DISPOSITION_FALSE_POSITIVE) == "success"

    def test_a_value_that_is_not_configured(self):
        """An alert can still carry a disposition that was removed from the configuration."""
        assert get_disposition_rank("AUTHORIZED") is None
        assert get_disposition_css("AUTHORIZED") == DEFAULT_DISPOSITION_CSS
        assert get_disposition_class("AUTHORIZED") is None
        assert not is_selectable_disposition("AUTHORIZED")
        assert not is_selectable_disposition(None)

    def test_selectable(self, monkeypatch):
        assert is_selectable_disposition(DISPOSITION_OPEN)
        monkeypatch.setitem(get_config().dispositions, "GRAYWARE",
                            DispositionConfig(rank=60, css="secondary", analyst_selectable=False))

        assert is_valid_disposition("GRAYWARE")
        assert not is_selectable_disposition("GRAYWARE")
        assert "GRAYWARE" in get_dispositions()
        assert "GRAYWARE" not in get_selectable_dispositions()
        # the order of the rest is kept
        assert list(get_selectable_dispositions())[:3] == ["OPEN", "FALSE_POSITIVE", "IGNORE"]


class TestClassification:
    def test_the_agreed_map(self):
        """docs/SVS.md, Part 1: GRAYWARE, POLICY_VIOLATION and every kill-chain disposition are
        tp; FALSE_POSITIVE is fp; OPEN, IGNORE, UNKNOWN and REVIEWED are unclassified."""
        tp = {"GRAYWARE", "POLICY_VIOLATION", "RECONNAISSANCE", "WEAPONIZATION", "DELIVERY",
              "EXPLOITATION", "INSTALLATION", "COMMAND_AND_CONTROL", "EXFIL", "DAMAGE"}
        for disposition in get_dispositions():
            expected = (DISPOSITION_CLASS_TP if disposition in tp
                        else DISPOSITION_CLASS_FP if disposition == DISPOSITION_FALSE_POSITIVE
                        else None)
            assert get_disposition_class(disposition) == expected, disposition

    def test_an_unknown_disposition_in_the_map_fails_validation(self):
        data = _config_data()
        data["disposition_classification"]["DELIVERYY"] = "tp"
        with pytest.raises(ValidationError, match="DELIVERYY"):
            ACEConfig.model_validate(data)

    def test_only_tp_and_fp(self):
        data = _config_data()
        data["disposition_classification"]["IGNORE"] = "benign"
        with pytest.raises(ValidationError):
            ACEConfig.model_validate(data)


class TestValidation:
    @pytest.mark.parametrize("key", REMOVED_DISPOSITION_CONFIG_KEYS)
    def test_a_removed_key_fails_instead_of_being_ignored(self, key):
        """A site overlay still setting an old per-disposition map would otherwise lose its
        customization silently: ACEConfig does not reject unknown keys in general."""
        data = _config_data()
        data[key] = {"DELIVERY": True}
        with pytest.raises(ValidationError, match="dispositions:"):
            ACEConfig.model_validate(data)

    def test_a_disposition_needs_rank_and_css(self):
        data = _config_data()
        data["dispositions"]["NEW_ONE"] = {"rank": 5}
        with pytest.raises(ValidationError):
            ACEConfig.model_validate(data)

    def test_unknown_settings_fail(self):
        data = _config_data()
        data["dispositions"]["DELIVERY"]["colour"] = "red"
        with pytest.raises(ValidationError):
            ACEConfig.model_validate(data)

    def test_names_are_upper_case(self):
        data = _config_data()
        data["dispositions"]["delivery_lower"] = {"rank": 5, "css": "light"}
        with pytest.raises(ValidationError, match="upper case"):
            ACEConfig.model_validate(data)

    def test_a_new_disposition_is_selectable_by_default(self):
        data = _config_data()
        data["dispositions"]["NEW_ONE"] = {"rank": 5, "css": "light"}
        config = ACEConfig.model_validate(data)
        assert config.dispositions["NEW_ONE"].analyst_selectable is True
        assert config.dispositions["NEW_ONE"].show_save_to_event is False
        assert list(config.dispositions)[-1] == "NEW_ONE"


class TestInitialize:
    def test_logs_the_classification_at_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            initialize_dispositions()

        (record,) = [r for r in caplog.records if r.getMessage() == "disposition classification in effect"]
        assert record.levelno == logging.WARNING
        assert record.disposition_classification == dict(get_config().disposition_classification)

    def test_a_typo_in_stop_analysis_on_dispositions_fails(self, monkeypatch):
        engine_config = get_engine_config()
        monkeypatch.setattr(engine_config, "stop_analysis_on_dispositions",
                            ["FALSE_POSITIVE", "FALSE_POSTIVE"])
        with pytest.raises(ValueError, match="FALSE_POSTIVE"):
            initialize_dispositions()


class _RollUpEvent:
    """Event's roll-up properties over plain alert mappings, with no session or mapper."""

    disposition = Event.disposition
    disposition_rank = Event.disposition_rank

    def __init__(self, dispositions):
        self.alert_mappings = [
            SimpleNamespace(alert=SimpleNamespace(disposition=disposition), event_id=1)
            for disposition in dispositions
        ]


class TestEventRollUp:
    @staticmethod
    def _event(*dispositions) -> _RollUpEvent:
        return _RollUpEvent(dispositions)

    def test_the_highest_rank_wins(self):
        event = self._event("FALSE_POSITIVE", "DELIVERY", "RECONNAISSANCE")
        assert event.disposition == "DELIVERY"
        assert event.disposition_rank == 100

    def test_a_disposition_that_is_no_longer_configured_never_wins(self):
        """It used to raise KeyError inside a bare except, and disposition_rank had no guard."""
        event = self._event("AUTHORIZED", "FALSE_POSITIVE")
        assert event.disposition == "FALSE_POSITIVE"

        only_removed = self._event("AUTHORIZED")
        assert only_removed.disposition == DISPOSITION_OPEN
        assert only_removed.disposition_rank == 0
