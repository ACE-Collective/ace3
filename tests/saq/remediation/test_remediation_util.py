import pytest

from saq.constants import F_TEST
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction
from saq.remediation.util import cancel_remediation, delete_remediations, retry_remediation


@pytest.mark.integration
def test_delete_remediations_multiple():
    """test deleting multiple remediations"""
    # create multiple remediations
    target1 = RemediationTarget("custom", F_TEST, "test_value_20")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_config().global_settings.automation_user_id
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_21")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_config().global_settings.automation_user_id
    )

    # delete both
    count = delete_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify both are gone
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        assert remediation is None


@pytest.mark.integration
def test_cancel_remediation_unknown_id():
    assert cancel_remediation(999999) is False


@pytest.mark.integration
def test_retry_remediation_unknown_id():
    assert retry_remediation(999999) is False
