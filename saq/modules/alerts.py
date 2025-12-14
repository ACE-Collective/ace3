# vim: sw=4:ts=4:et

import logging
from typing import Type, Optional
from pydantic import Field

from saq.configuration.config import get_engine_config
from saq.constants import DISPOSITION_OPEN
from saq.database import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.modules import AnalysisModule
from saq.modules.base_module import AnalysisExecutionResult
from saq.modules.config import AnalysisModuleConfig

class ACEAlertDispositionAnalyzerConfig(AnalysisModuleConfig):
    target_mode: Optional[str] = Field(default=None, description="The target analysis mode.")

class ACEDetectionAnalyzerConfig(AnalysisModuleConfig):
    target_mode: Optional[str] = Field(default=None, description="The target analysis mode to switch to when detections are found.")

class ACEAlertDispositionAnalyzer(AnalysisModule):
    """Cancels any further analysis if the disposition has been set by the analyst."""
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ACEAlertDispositionAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config.target_mode

    def execute_pre_analysis(self):
        self.check_disposition()

    def execute_threaded(self):
        self.check_disposition()

    def check_disposition(self):
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT disposition FROM alerts WHERE uuid = %s", (self.get_root().uuid,))
            row = c.fetchone()
            # did the alert vanish from the database?
            if row is None:
                logging.warning("alert {} seems to have vanished from the database".format(self.get_root().uuid))
                self.get_engine().cancel_analysis()

            # Get the two different stop analysis setting values
            stop_analysis_on_any_alert_disposition = get_engine_config().stop_analysis_on_any_alert_disposition
            stop_analysis_on_dispositions = get_engine_config().stop_analysis_on_dispositions

            # Check to see if we need to stop analysis based on the settings
            disposition = row[0]
            if stop_analysis_on_any_alert_disposition and disposition != DISPOSITION_OPEN:
                logging.info("alert {} has been dispositioned - canceling analysis".format(self.get_root().uuid))
                self.get_engine().cancel_analysis()
            elif disposition in stop_analysis_on_dispositions:
                logging.info("alert {} has been dispositioned as {} - canceling analysis".format(self.get_root().uuid, disposition))
                self.get_engine().cancel_analysis()
            elif disposition:
                logging.info(f"alert {self.get_root()} dispositioned as {disposition} but continuing analysis")

class ACEDetectionAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ACEDetectionAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config.target_mode

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        # do not alert on a root that has been whitelisted
        if not get_global_runtime_settings().forced_alerts and self.get_root().whitelisted:
            logging.debug("{} has been whitelisted".format(self.get_root()))
            return AnalysisExecutionResult.COMPLETED

        if get_global_runtime_settings().forced_alerts or self.get_root().has_detections():
            logging.info("{} has {} detection points - changing mode to {}".format(
                         self.get_root(), len(self.get_root().all_detection_points), self.target_mode))
            self.get_root().analysis_mode = self.target_mode

        return AnalysisExecutionResult.COMPLETED
