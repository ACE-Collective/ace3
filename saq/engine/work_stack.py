import collections
from typing import Optional, Union

from saq.analysis.analysis import Analysis
from saq.analysis.dependency import AnalysisDependency
from saq.analysis.observable import Observable
from saq.modules.interfaces import AnalysisModuleInterface


class WorkTarget:
    """Utility class the defines what exactly we're working on at the moment."""

    def __init__(
        self,
        observable: Optional[Observable] = None,
        analysis: Optional[Analysis] = None,
        analysis_module: Optional[AnalysisModuleInterface] = None,
        dependency: Optional[AnalysisDependency] = None,
    ):
        self.observable = observable  # the observable to analyze
        self.analysis = analysis  # the analysis to analyze (not actually supported)
        self.analysis_module = (
            analysis_module  # the analysis module to use (or all of them if not set)
        )
        self.dependency = dependency  # the dependency we're trying to resolve

    def __str__(self):
        return "WorkTarget(obs:{},analyis:{},module:{},dep:{})".format(
            self.observable, self.analysis, self.analysis_module, self.dependency
        )

    def __repr__(self):
        return self.__str__()


class WorkStack:
    def __init__(self):
        self.tracker = set()  # observable uuids
        self.work = collections.deque()  # of WorkTarget objects

    def appendleft(self, item: WorkTarget):
        assert isinstance(item, WorkTarget)
        self.work.appendleft(item)

    def append(self, item: Union[WorkTarget, Observable, Analysis]):
        # are we already tracking this in the work stack?
        if isinstance(item, Observable):
            if item.uuid in self.tracker:
                return

        if isinstance(item, WorkTarget):
            self.work.append(item)
        elif isinstance(item, Observable):
            self.work.append(WorkTarget(observable=item))
            self.tracker.add(item.uuid)
        elif isinstance(item, Analysis):
            pass
        else:
            raise RuntimeError(
                "invalid work item type {} ({})".format(type(item), item)
            )

    def popleft(self) -> WorkTarget:
        result = self.work.popleft()
        if result.observable:
            try:
                self.tracker.remove(result.observable.uuid)
            except KeyError:
                pass  # will throw this when analyzing delayed analysis

        return result

    def __len__(self):
        return len(self.work)
