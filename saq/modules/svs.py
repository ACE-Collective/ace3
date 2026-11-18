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
from saq.modules import AnalysisModule
from saq.signatures.builtin import SVS_MARKER_MISMATCH, get_builtin_signature_version
from saq.svs.attribution import alert_event_time, attribution_open, evaluate
from saq.svs.capture import candidates_from_root, capture
from saq.svs.constants import TAG_MAINTENANCE, TAG_MARKER_MISMATCH, TAG_SVS_TEST, SVSStatus


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
                logging.exception("unable to capture svs sample %s of %s: %s", candidate, root, e,
                              extra={"alert_uuid": root.uuid, "sha256": candidate.sha256,
                                     "rule_uuid": candidate.rule_uuid})

        return AnalysisExecutionResult.COMPLETED


class SVSAlertTagger(AnalysisModule):
    """Marks what SVS attribution makes of an alert (docs/SVS_RUNS.md, *Attribution*) in its tree:
    the svs_test tag on an alert whose every detection is attributed to a test run, the
    svs:marker_mismatch tag plus a detection on one carrying a marker that doesn't match its run,
    and the svs:maintenance tag on one in a test host's maintenance window.

    The svs_marker alert router judges alerts but never changes the tree [FR-3], so this module
    does that part. It runs in correlation mode, in post-analysis, which comes before the router's
    POST_ANALYSIS stage in the same pass, and it evaluates the alert the same way the router does
    rather than reading the router's rows, which would lag a pass: a hunt alert gets only one.
    Tags and detections are idempotent, and a mismatch is never taken back. svs_test is removed
    when the alert stops being fully attributed."""

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        root = self.get_root()
        if not attribution_open():
            return AnalysisExecutionResult.COMPLETED

        inserted_at = get_db().execute(select(Alert.insert_date).where(Alert.uuid == root.uuid)).scalar()
        if inserted_at is None:
            logging.debug("%s has no alert row - not tagged for svs", root)
            return AnalysisExecutionResult.COMPLETED

        evaluation = evaluate(root, *alert_event_time(root, inserted_at))

        if evaluation.status == SVSStatus.MISMATCH:
            root.add_tag(TAG_MARKER_MISMATCH)
            for judgement in evaluation.mismatches:
                root.add_detection_point(
                    f"SVS test run marker {judgement.marker} does not match its run: {judgement.result.value}",
                    details={"marker": judgement.marker, "result": judgement.result.value},
                    signature_uuid=SVS_MARKER_MISMATCH.uuid,
                    signature_version=get_builtin_signature_version())

        if evaluation.routed:
            root.add_tag(TAG_SVS_TEST)
        elif root.has_tag(TAG_SVS_TEST):
            root.remove_tag(TAG_SVS_TEST)

        if evaluation.maintenance is not None:
            root.add_tag(TAG_MAINTENANCE)
        elif root.has_tag(TAG_MAINTENANCE):
            root.remove_tag(TAG_MAINTENANCE)

        return AnalysisExecutionResult.COMPLETED
