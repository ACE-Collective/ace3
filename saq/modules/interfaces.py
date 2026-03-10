"""
Interfaces/protocols for dependency injection in AnalysisModule system.
"""

from typing import Optional, Protocol, Type, runtime_checkable

from saq.analysis.analysis import Analysis
from saq.analysis.interfaces import RootAnalysisInterface
from saq.analysis.observable import Observable
from saq.engine.interface import EngineInterface
from saq.constants import AnalysisExecutionResult
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext

@runtime_checkable
class AnalysisCacheStrategyInterface(Protocol):
    """Protocol defining the interface for analysis caching strategies."""

    def get_cached_analysis(self, module: "AnalysisModuleInterface", observable: Observable) -> Optional[dict]:
        """Retrieve cached analysis data for the given module and observable.

        Args:
            module: The analysis module requesting cached data
            observable: The observable being analyzed

        Returns:
            Dictionary containing cached analysis data or None if not found/expired
        """
        ...

    def store_analysis(self, module: "AnalysisModuleInterface", observable: Observable, analysis_data: dict) -> bool:
        """Store analysis data in the cache.

        Args:
            module: The analysis module that produced the analysis
            observable: The observable that was analyzed
            analysis_data: Dictionary containing analysis details and observables

        Returns:
            True if successfully stored, False otherwise
        """
        ...

    def invalidate_cache(self, module: Optional["AnalysisModuleInterface"] = None, observable: Optional[Observable] = None) -> bool:
        """Invalidate cache entries.

        Args:
            module: If provided, invalidate only entries for this module
            observable: If provided, invalidate only entries for this observable

        Returns:
            True if invalidation was successful, False otherwise
        """
        ...


@runtime_checkable
class AnalysisModuleInterface(Protocol):
    """Protocol defining the interface for analysis modules."""

    @property
    def name(self) -> str:
        """Returns the name of the module."""
        ...

    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        """Returns the type of the Analysis-based class this AnalysisModule generates.  
           Returns None if this AnalysisModule does not generate an Analysis object."""
        ...

    def matches_module_spec(self, module_name: str, class_name: str, instance: Optional[str]) -> bool:
        """Returns True if this module matches the given module specification."""
        ...

    def get_module_path(self) -> str:
        """Returns the module path of this module."""
        ...
    
    # Configuration properties
    @property
    def config(self) -> AnalysisModuleConfig:
        """Get the configuration for this module."""
        ...

    @property
    def instance(self) -> Optional[str]:
        """Get the instance name from configuration."""
        ...
    
    @property
    def priority(self) -> int:
        """Get the module priority (lower numbers = higher priority)."""
        ...
    
    @property
    def automation_limit(self) -> Optional[int]:
        """Get the automation limit for this module."""
        ...
    
    @property
    def maximum_analysis_time(self) -> int:
        """Get the maximum analysis time in seconds."""
        ...

    @property
    def maintenance_frequency(self):
        """Returns how often to execute the maintenance function, in seconds, or None to disable (the default.)"""
        ...

    @property
    def semaphore_name(self) -> Optional[str]:
        ...

    def analyze(self, obj, final_analysis=False, delayed_analysis=False) -> AnalysisExecutionResult:
        """Analyze the given object.
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        ...
    
    # Analysis execution methods
    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        """Called to analyze Analysis or Observable objects. 
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        ...

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        """Called to continue analysis of an Observable object."""
        ...
    
    def execute_final_analysis(self, analysis) -> AnalysisExecutionResult:
        """Called to analyze Analysis or Observable objects after all other analysis has completed."""
        ...
    
    def execute_pre_analysis(self) -> None:
        """This is called once at the very beginning of analysis."""
        ...
    
    def execute_post_analysis(self) -> bool:
        """This is called after all analysis work has been performed."""
        ...
    
    # Control methods
    def should_analyze(self, obj) -> bool:
        """Put your custom 'should I analyze this?' logic in this function."""
        ...
    
    def accepts(self, obj) -> bool:
        """Returns True if this module can analyze the given object."""
        ...
    
    def cancel_analysis(self) -> None:
        """Cancel the current analysis."""
        ...

    # TODO this should probably be part of the context
    def is_canceled_analysis(self) -> bool:
        """Returns True if the current analysis has been canceled."""
        ...
    
    # Dependency injection methods
    def set_context(self, context: "AnalysisModuleContext") -> None:
        """Set the dependency injection context."""
        ...
    
    def get_engine(self) -> EngineInterface:
        """Get the engine interface from context."""
        ...
    
    def get_root(self) -> RootAnalysisInterface:
        """Get the root analysis interface from context."""
        ...
    
    # Lifecycle methods
    def verify_environment(self) -> None:
        """Verify that the environment is set up correctly for this module."""
        ...
    
    def cleanup(self) -> None:
        """Cleanup any resources used by this module."""
        ...

    # temporary hacks
    def module_as_string(self) -> str:
        """Return the underlying module as a string."""
        ...


        
