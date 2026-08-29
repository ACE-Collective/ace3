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

    def get_cached_analysis(self, observable, analysis_type: Type[Analysis], module_instance: Optional[str], version: int) -> Optional[dict]:
        """Retrieve cached analysis data for the given parameters.
        
        Args:
            observable: The observable being analyzed
            analysis_type: The type of analysis being cached
            module_instance: Optional instance name for the module
            version: Version number for cache invalidation
            
        Returns:
            Dictionary containing cached analysis data or None if not found/expired
        """
        ...

    def store_analysis(self, observable, analysis_type: Type[Analysis], module_instance: Optional[str], version: int, analysis_data: dict) -> bool:
        """Store analysis data in the cache.
        
        Args:
            observable: The observable being analyzed
            analysis_type: The type of analysis being cached
            module_instance: Optional instance name for the module
            version: Version number for cache invalidation
            analysis_data: Dictionary containing analysis details and observables
            
        Returns:
            True if successfully stored, False otherwise
        """
        ...

    def invalidate_cache(self, observable=None, analysis_type: Optional[Type[Analysis]] = None) -> bool:
        """Invalidate cache entries.
        
        Args:
            observable: If provided, invalidate only entries for this observable
            analysis_type: If provided, invalidate only entries for this analysis type
            
        Returns:
            True if invalidation was successful, False otherwise
        """
        ...

    def configure(self, **kwargs) -> None:
        """Configure the cache strategy with additional parameters."""
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

    def analyze(self, observable: Observable, final_analysis=False, delayed_analysis=False) -> AnalysisExecutionResult:
        """Analyze the given observable.
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        ...
    
    # Analysis execution methods
    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable.
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        ...

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        """Called to continue analysis of an Observable object."""
        ...
    
    def execute_final_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable after all other analysis has completed."""
        ...
    
    def execute_pre_analysis(self) -> None:
        """This is called once at the very beginning of analysis."""
        ...
    
    def execute_post_analysis(self) -> bool:
        """This is called after all analysis work has been performed."""
        ...

    def on_cache_hit(self, root, observable) -> None:
        """Called after a cached analysis has been replayed for this module."""
        ...

    # Control methods
    def should_analyze(self, observable: Observable) -> bool:
        """Put your custom 'should I analyze this?' logic in this function."""
        ...
    
    def accepts(self, observable: Observable) -> bool:
        """Returns True if this module can analyze the given observable."""
        ...

    def custom_requirement(self, observable: Observable) -> bool:
        """Additional check evaluated by the engine as the final gate before the
        module runs. May raise WaitForAnalysisException to wait on another analysis."""
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


        
