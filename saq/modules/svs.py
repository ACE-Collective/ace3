"""The analysis modules of the Signature Validation System (docs/SVS.md)."""

import logging

from sqlalchemy import select

from saq.cas import get_cas
from saq.cas.errors import PoolNotFound
from saq.configuration.config import get_config
from saq.constants import AnalysisExecutionResult
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.detection_verdicts.effective import unreviewed_run_condition
from saq.disposition import get_disposition_class
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.svs.capture import candidates_from_root, capture


class YaraSampleCapture(AnalysisModule):
    """Captures every file a YARA rule matched on an alert dispositioned tp or fp into the
    svs_samples pool (docs/SVS_SAMPLES.md).

    It runs in dispositioned mode, where both disposition writers requeue the alert, and does its
    work in post-analysis: it analyzes no observable and changes nothing in the tree. Post-analysis
    runs at the end of every pass, so every later dispositioned pass (a disposition changed from
    REVIEWED to FALSE_POSITIVE, a review correction) runs it again, and capture is idempotent."""

    def verify_environment(self):
        pool = get_config().svs.samples.pool
        if pool not in get_config().cas.pools:
            logging.error("svs_yara_sample_capture: cas pool %s is not configured - nothing will be captured", pool)

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        root = self.get_root()
        row = get_db().execute(
            select(Alert.disposition, unreviewed_run_condition(Alert).label("unreviewed"))
            .where(Alert.uuid == root.uuid)).first()

        if row is None:
            logging.debug("%s has no alert row - nothing to capture", root)
            return AnalysisExecutionResult.COMPLETED

        # alerts of a test run that is not Reviewed teach nothing (docs/SVS.md, Part 2)
        if get_disposition_class(row.disposition) is None or row.unreviewed:
            return AnalysisExecutionResult.COMPLETED

        candidates = candidates_from_root(root)
        if not candidates:
            return AnalysisExecutionResult.COMPLETED

        pool_name = get_config().svs.samples.pool
        try:
            pool = get_cas().pool(pool_name)
        except PoolNotFound:
            logging.error("cas pool %s is not configured - %s yara samples of %s are not captured",
                          pool_name, len(candidates), root)
            return AnalysisExecutionResult.COMPLETED

        for candidate in candidates:
            try:
                capture(pool, root.uuid, candidate)
            except Exception as e:
                # one capture must never stop the others
                logging.error("unable to capture svs sample %s of %s: %s", candidate, root, e,
                              extra={"alert_uuid": root.uuid, "sha256": candidate.sha256,
                                     "rule_uuid": candidate.rule_uuid})
                report_exception()

        return AnalysisExecutionResult.COMPLETED
