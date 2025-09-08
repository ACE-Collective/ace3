from datetime import datetime, timedelta
import logging
import os
import shutil
import time

from saq.analysis.root import RootAnalysis
from saq.configuration.config import (
    get_config,
    get_config_value_as_boolean,
    get_config_value_as_list,
)
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    CONFIG_ENGINE,
    CONFIG_ENGINE_STOP_ANALYSIS_ON_ANY_ALERT_DISPOSITION,
    CONFIG_ENGINE_STOP_ANALYSIS_ON_DISPOSITIONS,
    DISPOSITION_OPEN,
    G_FORCED_ALERTS,
    G_MODULE_STATS_DIR,
)
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.database.retry import execute_with_retry
from saq.database.util.alert import ALERT
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.errors import AnalysisTimeoutError
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.environment import g, g_boolean
from saq.error import report_exception
from saq.util import storage_dir_from_uuid


class AnalysisOrchestrator:
    """
    Orchestrates the complete analysis lifecycle for work items.
    
    This class is responsible for:
    - Processing work items and managing their lifecycle
    - Checking alert disposition and handling correlation mode
    - Detecting when analysis completes and managing mode transitions
    - Creating alerts when detections are found
    - Managing storage directory relocation for alerts
    - Cleaning up completed analysis
    - Syncing alerts to the database
    """

    def __init__(
        self,
        configuration_manager: ConfigurationManager,
        analysis_executor: AnalysisExecutor,
        workload_manager,
        lock_manager
    ):
        """
        Initialize the AnalysisOrchestrator.

        Args:
            analysis_executor: The AnalysisExecutor to use for core analysis
            workload_manager: Manager for workload operations
            lock_manager: Manager for lock operations
            non_detectable_modes: List of analysis modes that don't generate alerts
        """
        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config
        self.analysis_executor = analysis_executor
        self.workload_manager = workload_manager
        self.lock_manager = lock_manager

    def orchestrate_analysis(self, execution_context: EngineExecutionContext) -> bool:
        """
        Orchestrate the complete analysis lifecycle for a work item.
        
        Args:
            execution_context: The execution context containing analysis state
            
        Returns:
            True if analysis was successful, False if there was an error
        """
        try:
            # process the work item and set up the root analysis
            self._process_work_item(execution_context)
            
            if execution_context.root is None:
                logging.warning(f"unable to process work item {execution_context.work_item} (root was None)")
                return False

            logging.debug(f"analyzing {execution_context.root} in analysis_mode {execution_context.root.analysis_mode}")

            # Check for alert disposition before analysis
            if self._check_disposition(execution_context):
                return True

            # Perform the actual analysis
            self._execute_analysis(execution_context)

            # Handle post-analysis logic: detection handling, mode changes, cleanup
            self._handle_post_analysis_logic(execution_context)

            return True

        except Exception as e:
            logging.error(f"error orchestrating analysis for {execution_context.work_item}: {e}")
            report_exception()
            return False

    def _process_work_item(self, execution_context: EngineExecutionContext) -> bool:
        """Process the work item and set up the root analysis."""
        work_item = execution_context.work_item

        # FUTURE: here is where we would likely request the root analysis to
        # sync to the local system

        # both RootAnalysis and DelayedAnalysisRequest define storage_dir
        if not work_item.storage_dir or not os.path.isdir(work_item.storage_dir):
            logging.warning(
                f"storage directory {work_item.storage_dir} missing - already processed?"
            )
            return False

        if isinstance(work_item, DelayedAnalysisRequest):
            work_item.load(self.configuration_manager)
            # reset the delay flag for this analysis
            if work_item.analysis:
                work_item.analysis.delayed = False

        elif isinstance(work_item, RootAnalysis):
            # the analysis mode set in the workload may not match what is currently saved with this analysis
            # for example, when an analyst sets the disposition of the alert, it gets added back into the
            # workload in DISPOSITIONED mode even though the analysis_mode saved with the alert is CORRELATION
            current_analysis_mode = execution_context.root.analysis_mode
            execution_context.root.load()
            # NOTE in the case of transfers from another node, current_analysis_mode will be None
            if (
                current_analysis_mode is not None
                and execution_context.root.analysis_mode != current_analysis_mode
            ):
                logging.debug(
                    f"changing analysis mode for {execution_context.root} from {execution_context.root.analysis_mode} "
                    f"to workload value of {current_analysis_mode}"
                )
                execution_context.root.override_analysis_mode(current_analysis_mode)

        logging.info(
            f"processing {execution_context.root.description} mode {execution_context.root.analysis_mode} ({execution_context.root.uuid})"
        )

    def _check_disposition(self, execution_context: EngineExecutionContext) -> bool:
        """
        Check if analysis should be skipped due to alert disposition.
        
        Returns:
            True if analysis should be skipped, False otherwise
        """
        # if we're not in alert mode then it doesn't matter
        if execution_context.root.analysis_mode != ANALYSIS_MODE_CORRELATION:
            return False

        try:
            # XXX why is this needed?
            get_db().close()

            # Get the two different stop analysis setting values
            stop_analysis_on_any_alert_disposition = get_config_value_as_boolean(
                CONFIG_ENGINE,
                CONFIG_ENGINE_STOP_ANALYSIS_ON_ANY_ALERT_DISPOSITION,
                default=False,
            )
            stop_analysis_on_dispositions = get_config_value_as_list(
                CONFIG_ENGINE, CONFIG_ENGINE_STOP_ANALYSIS_ON_DISPOSITIONS
            )

            # Check to see if we need to stop analysis based on the settings
            disposition = (
                get_db()
                .query(Alert.disposition)
                .filter(Alert.uuid == execution_context.root.uuid)
                .scalar()
            )
            
            if (
                disposition is not None
                and stop_analysis_on_any_alert_disposition
                and disposition != DISPOSITION_OPEN
            ):
                logging.info(
                    f"skipping analysis on dispositioned alert {execution_context.root} disposition {disposition}"
                )
                return True
            elif disposition in stop_analysis_on_dispositions:
                logging.info(
                    f"skipping analysis on {disposition} dispositioned alert {execution_context.root}"
                )
                return True
            elif disposition:
                logging.debug(
                    f"alert {execution_context.root} dispositioned as {disposition} but continuing analysis"
                )

        except Exception as e:
            logging.error(f"unable to check for disposition of {execution_context.work_item}: {e}")

        return False

    def _execute_analysis(self, execution_context: EngineExecutionContext):
        """Execute the actual analysis using the AnalysisExecutor."""
        start_time = time.time()

        try:
            # use the AnalysisExecutor to perform the core analysis
            context = self.analysis_executor.execute(execution_context.work_item)

            elapsed_time = time.time() - start_time

            logging.info(f"completed analysis {execution_context.work_item} in {elapsed_time:.2f} seconds")

            # save all the changes we've made
            execution_context.root.save()

            # record the execution statistics
            context.record_execution_statistics(elapsed_time, g(G_MODULE_STATS_DIR))

        except Exception as e:
            elapsed_time = time.time() - start_time

            # log timeouts as warnings if configured
            if isinstance(e, AnalysisTimeoutError):
                logging.warning(f"analysis failed on {execution_context.root}: {e}")
            #else:
                #logging.error(f"analysis failed on {execution_context.root}: {e}")

            try:
                # just try to save what we've got thus far
                execution_context.root.save()
            except Exception as save_error:
                logging.error(f"unable to save failed analysis {execution_context.root}: {save_error}")

            # clear any outstanding delayed analysis requests
            try:
                self.workload_manager.clear_delayed_analysis_requests(execution_context.root)
            except Exception as clear_error:
                logging.error(f"unable to clear delayed analysis requests for {execution_context.root}: {clear_error}")

            # Re-raise the exception for the caller to handle
            raise

    def _handle_post_analysis_logic(self, execution_context: EngineExecutionContext):
        """Handle post-analysis logic including detection handling, mode changes, and cleanup."""
        
        # check for outstanding work and handle detection points
        self._check_outstanding_work_and_handle_detections(execution_context)
        
        # handle analysis mode changes
        self._handle_analysis_mode_changes(execution_context)
        
        # handle cleanup if analysis mode supports it
        self._handle_cleanup(execution_context)

    def _check_outstanding_work_and_handle_detections(self, execution_context: EngineExecutionContext):
        """Check for outstanding work and handle detection points if no work remains."""
        
        try:
            with get_db_connection() as db:
                cursor = db.cursor()

                if self.lock_manager.lock_uuid is None:
                    logging.warning(f"missing lock_uuid when processing {execution_context.work_item}")

                # check for outstanding work
                has_outstanding_work = self._check_for_outstanding_work(cursor, execution_context)

                if not has_outstanding_work:
                    # Handle detection points
                    self._handle_detection_points(execution_context)

        except Exception as e:
            logging.error(f"trouble checking finished status of {execution_context.root}: {e}")
            report_exception()

    def _check_for_outstanding_work(self, cursor, execution_context: EngineExecutionContext) -> bool:
        """
        Check if there is any outstanding work for this analysis.
        
        Returns:
            True if there is outstanding work, False otherwise
        """
        # first check workload and locks
        cursor.execute(
            """SELECT uuid FROM workload WHERE uuid = %s AND analysis_mode != %s
                     UNION SELECT uuid FROM locks WHERE uuid = %s AND lock_uuid != %s
                     LIMIT 1
                     """,
            (
                execution_context.root.uuid,
                execution_context.root.original_analysis_mode,
                execution_context.root.uuid,
                self.lock_manager.lock_uuid,
            ),
        )

        row = cursor.fetchone()
        if row is not None:
            return True

        # check delayed analysis requests
        query = "SELECT uuid FROM delayed_analysis WHERE uuid = %s"
        params = [execution_context.root.uuid]
        
        if isinstance(execution_context.work_item, DelayedAnalysisRequest):
            query += " AND id != %s"
            params.append(execution_context.work_item.database_id)

        cursor.execute(query, tuple(params))
        row = cursor.fetchone()
        
        return row is not None

    def _handle_detection_points(self, execution_context: EngineExecutionContext):
        """Handle detection points when no outstanding work remains."""
        
        # is this work item in a non-detectable analysis mode?
        if execution_context.root.analysis_mode in self.config.non_detectable_modes:
            return

        # has this analysis been whitelisted?
        if not g_boolean(G_FORCED_ALERTS) and execution_context.root.whitelisted:
            logging.info(f"{execution_context.root} has been whitelisted")
            return

        if (execution_context.root.has_detections() or g_boolean(G_FORCED_ALERTS)) and self.config.alerting_enabled:
            reason = f"{len(execution_context.root.all_detection_points)} detection points" if execution_context.root.has_detections() else "forced alerts enabled"
            logging.info(
                f"{execution_context.root} has {reason} - changing mode to {ANALYSIS_MODE_CORRELATION}"
            )
            execution_context.root.analysis_mode = ANALYSIS_MODE_CORRELATION

    def _handle_analysis_mode_changes(self, execution_context: EngineExecutionContext):
        """Handle analysis mode changes and their consequences."""
        
        # did the analysis mode change?
        if execution_context.root.analysis_mode != execution_context.root.original_analysis_mode:
            logging.info(
                f"analysis mode for {execution_context.root} changed from {execution_context.root.original_analysis_mode} to {execution_context.root.analysis_mode}"
            )

            # did this analysis become an alert?
            if execution_context.root.analysis_mode == ANALYSIS_MODE_CORRELATION:
                self._convert_to_alert(execution_context)
            
            # Schedule the analysis for the new mode
            try:
                logging.info(f"scheduling analysis of {execution_context.root} for {execution_context.root.analysis_mode}")
                execution_context.root.schedule()
            except Exception as e:
                logging.error(f"unable to add {execution_context.root} to workload: {e}")
                report_exception()

        elif execution_context.root.analysis_mode == ANALYSIS_MODE_CORRELATION:
            # if we are analyzing an alert, sync it to the database
            self._sync_alert_to_database(execution_context)

    def _convert_to_alert(self, execution_context: EngineExecutionContext):
        """Convert the analysis to an alert."""
        
        # save the change to the analysis mode
        execution_context.root.save()

        # is the current storage directory in a different directory than the alerts?
        target_dir = storage_dir_from_uuid(execution_context.root.uuid)
        if execution_context.root.storage_dir != target_dir:
            self._relocate_storage_directory(target_dir, execution_context)

        # Create the alert
        try:
            ALERT(execution_context.root)
        except Exception as e:
            logging.error(f"unable to create alert for {execution_context.root}: {e}")
            report_exception()

    def _relocate_storage_directory(self, target_dir: str, execution_context: EngineExecutionContext):
        """Relocate the storage directory for alerts."""
        
        if os.path.exists(target_dir):
            logging.error(f"target directory {target_dir} already exists")
        else:
            logging.info(f"moving {execution_context.root.storage_dir} to {target_dir}")
            try:
                #shutil.move(execution_context.root.storage_dir, target_dir)
                #execution_context.root.storage_dir = target_dir
                execution_context.root.move(target_dir)
            except Exception as e:
                logging.error(f"unable to move {execution_context.root.storage_dir} to {target_dir}: {e}")
                report_exception()

        # Update database entries to point to the new storage_dir
        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                sql = []
                params = []
                sql.append("UPDATE workload SET storage_dir = %s WHERE uuid = %s")
                params.append((execution_context.root.storage_dir, execution_context.root.uuid))
                sql.append("UPDATE delayed_analysis SET storage_dir = %s WHERE uuid = %s")
                params.append((execution_context.root.storage_dir, execution_context.root.uuid))
                execute_with_retry(db, cursor, sql, params, commit=True)
        except Exception as e:
            logging.error(
                f"unable to update workload/delayed_analysis tables with new storage_dir for {execution_context.root}: {e}"
            )
            report_exception()

    def _sync_alert_to_database(self, execution_context: EngineExecutionContext):
        """Sync the alert to the database."""
        
        session = None
        try:
            session = get_db()
            alert = session.query(Alert).filter(Alert.uuid == execution_context.root.uuid).first()
            if alert:
                alert.load()
                # do not rebuild the index if there are outstanding analysis requests
                alert.sync(build_index=not execution_context.root.delayed)
        except Exception as e:
            logging.error(f"unable to sync alert {execution_context.root}: {e}")
            report_exception()
        finally:
            if session:
                session.close()

    def _handle_cleanup(self, execution_context: EngineExecutionContext):
        """Handle cleanup if the analysis mode supports it."""
        
        # is this analysis_mode one that we want to clean up?
        if (
            execution_context.root.analysis_mode is not None
            and f"analysis_mode_{execution_context.root.analysis_mode}" in get_config()
            and get_config_value_as_boolean(f"analysis_mode_{execution_context.root.analysis_mode}", "cleanup")
        ):
            self._cleanup_if_no_outstanding_work(execution_context)

    def _cleanup_if_no_outstanding_work(self, execution_context: EngineExecutionContext):
        """Clean up the analysis if there is no outstanding work."""
        
        try:
            with get_db_connection() as db:
                cursor = db.cursor()

                if self.lock_manager.lock_uuid is None:
                    logging.warning(f"missing lock_uuid when processing {execution_context.root}")

                # Check for outstanding work
                has_outstanding_work = self._check_for_outstanding_work(cursor, execution_context)

                if not has_outstanding_work:
                    # OK then it's time to clean this one up
                    logging.debug(f"clearing {execution_context.root.storage_dir}")
                    try:
                        shutil.rmtree(execution_context.root.storage_dir)
                    except Exception as e:
                        logging.error(f"unable to clear {execution_context.root.storage_dir}: {e}")
                else:
                    logging.debug(f"not cleaning up {execution_context.root} (found outstanding work)")

        except Exception as e:
            logging.error(f"trouble checking finished status of {execution_context.root}: {e}")
            report_exception() 

    def _submit_alert_for_embedding_vectorization(self, execution_context: EngineExecutionContext):
        """Submit the alert for embedding vectorization."""
        from saq.llm.embedding.service import submit_embedding_task
        submit_embedding_task(execution_context.root.uuid)