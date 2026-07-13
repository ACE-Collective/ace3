from typing import Optional, Union

from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest


class EngineExecutionContext:
    """Context object that holds all dependencies for engine execution."""
    
    def __init__(self, work_item: Union[RootAnalysis, DelayedAnalysisRequest]):
        """Initialize the execution context with a work item."""
        self.work_item: Union[RootAnalysis, DelayedAnalysisRequest] = work_item

        # we keep track of the total amount of time (in seconds) that each module takes
        # key = module.name, value = total_seconds
        self.total_analysis_time: dict = {}
        
        # this is set to True to cancel the analysis going on in the process() function
        self._cancel_analysis_flag: bool = False

        # set True when analysis was aborted (e.g. timeout / exception) and its outstanding
        # delayed-analysis requests were cleared, meaning root.delayed is now stale and no
        # follow-up pass will rebuild the observable index
        self.analysis_aborted: bool = False

    @property
    def root(self) -> RootAnalysis:
        """Returns the RootAnalysis object the current process is analyzing."""
        return self.work_item if isinstance(self.work_item, RootAnalysis) else self.work_item.root # pyright: ignore

    @property
    def delayed_analysis_request(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the DelayedAnalysisRequest object the current process is analyzing."""
        return self.work_item if isinstance(self.work_item, DelayedAnalysisRequest) else None
    
    @property
    def cancel_analysis_flag(self) -> bool:
        """Returns True if analysis has been cancelled."""
        return self._cancel_analysis_flag
    
    def cancel_analysis(self):
        """Sends a signal to cancel the analysis."""
        self._cancel_analysis_flag = True