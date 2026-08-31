"""
Adapter classes that implement the dependency injection interfaces.
"""

import importlib
import logging
from datetime import timedelta
from typing import Optional, Type

from saq.analysis.analysis import Analysis
from saq.analysis.interfaces import RootAnalysisInterface
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.interfaces import AnalysisModuleInterface


class AnalysisModuleAdapter(AnalysisModuleInterface):
    """Adapter that wraps an AnalysisModule and implements the AnalysisModuleInterface Protocol.
    
    This adapter allows for dependency injection and abstraction of concrete AnalysisModule
    implementations, making it easier to test and maintain the code.
    """
    
    def __init__(self, module: AnalysisModule):
        """Initialize the adapter with a concrete AnalysisModule instance.
        
        Args:
            module: The concrete AnalysisModule instance to wrap
        """
        if not isinstance(module, AnalysisModule):
            raise TypeError("module must be an instance of AnalysisModule")
        
        self._module = module

    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        """Returns the type of the Analysis-based class this AnalysisModule generates.  
           Returns None if this AnalysisModule does not generate an Analysis object."""
        return self._module.generated_analysis_type

    def matches_module_spec(self, module_name: str, class_name: str, instance: Optional[str]) -> bool:
        """Returns True if this module matches the given module specification."""
        return self._module.__module__ == module_name and type(self._module).__name__ == class_name and self._module.instance == instance

    def get_module_path(self) -> str:
        """Returns the module path of this module."""
        return self._module.get_module_path()
    
    @property
    def config(self) -> AnalysisModuleConfig:
        """Get the configuration for this module."""
        return self._module.config

    @property
    def name(self) -> str:
        """Get the name of the module."""
        return self._module.name
    
    @property
    def instance(self) -> Optional[str]:
        """Get the instance name from configuration."""
        return self._module.instance
    
    @property
    def priority(self) -> int:
        """Get the module priority (lower numbers = higher priority)."""
        return self._module.priority
    
    @property
    def automation_limit(self) -> Optional[int]:
        """Get the automation limit for this module."""
        return self._module.automation_limit
    
    @property
    def maximum_analysis_time(self) -> int:
        """Get the maximum analysis time in seconds."""
        return self._module.maximum_analysis_time

    @property
    def maintenance_frequency(self) -> Optional[int]:
        """Returns how often to execute the maintenance function, in seconds, or None to disable (the default.)"""
        return self._module.maintenance_frequency

    @property
    def semaphore_name(self) -> Optional[str]:
        """Get the semaphore name for this module."""
        return self._module.semaphore_name

    @property
    def version(self) -> int:
        """Get the module version for cache validation."""
        return self._module.version

    @property
    def cache_ttl(self) -> Optional[timedelta]:
        """Get the cache TTL for this module. None disables caching."""
        return self._module.cache_ttl

    @property
    def extended_version(self) -> dict[str, str]:
        """Get dynamic inputs mixed into the cache key (rules hash, feed version, etc.)."""
        return self._module.extended_version

    # Analysis execution methods
    def analyze(self, observable: Observable, final_analysis=False, delayed_analysis=False) -> AnalysisExecutionResult:
        """Analyze the given observable.
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        return self._module.analyze(observable, final_analysis, delayed_analysis)

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable.
        Return COMPLETED if analysis executed successfully.
        Return INCOMPLETE if analysis should not occur for this target.
        """
        return self._module.execute_analysis(observable)

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        """Called to continue analysis of an Observable object."""
        return self._module.continue_analysis(observable, analysis)
    
    def execute_final_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable after all other analysis has completed."""
        return self._module.execute_final_analysis(observable)
    
    def execute_pre_analysis(self) -> None:
        """This is called once at the very beginning of analysis."""
        self._module.execute_pre_analysis()
    
    def execute_post_analysis(self) -> bool:
        """This is called after all analysis work has been performed."""
        return self._module.execute_post_analysis()

    def on_cache_hit(self, root, observable) -> None:
        """Called after a cached analysis has been replayed for this module."""
        self._module.on_cache_hit(root, observable)

    # Control methods
    def should_analyze(self, observable: Observable) -> bool:
        """Put your custom 'should I analyze this?' logic in this function."""
        return self._module.should_analyze(observable)
    
    def accepts(self, observable: Observable) -> bool:
        """Returns True if this module can analyze the given observable."""
        return self._module.accepts(observable)

    def custom_requirement(self, observable: Observable) -> bool:
        """Additional check evaluated by the engine as the final gate before the
        module runs. May raise WaitForAnalysisException to wait on another analysis."""
        return self._module.custom_requirement(observable)
    
    def cancel_analysis(self) -> None:
        """Cancel the current analysis."""
        self._module.cancel_analysis()

    def is_canceled_analysis(self) -> bool:
        """Returns True if the current analysis has been canceled."""
        return self._module.is_canceled_analysis()

    # Dependency injection methods
    def set_context(self, context: AnalysisModuleContext) -> None:
        """Set the dependency injection context."""
        self._module.set_context(context)
    
    def get_root(self) -> RootAnalysisInterface:
        """Get the root analysis interface from context."""
        return self._module.get_root()
    
    # Lifecycle methods
    def verify_environment(self) -> None:
        """Verify that the environment is set up correctly for this module."""
        self._module.verify_environment()
    
    def cleanup(self) -> None:
        """Cleanup any resources used by this module."""
        self._module.cleanup()

    # temporary hacks
    def module_as_string(self) -> str:
        """Return the underlying module as a string."""
        return str(type(self._module))
    
    # Delegation methods for accessing the underlying module
    @property
    def wrapped_module(self) -> AnalysisModule:
        """Get the wrapped AnalysisModule instance."""
        return self._module
    
    def __str__(self) -> str:
        """String representation of the adapter."""
        return f"AnalysisModuleAdapter({self._module})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the adapter."""
        return f"AnalysisModuleAdapter(module={self._module!r})"


def create_analysis_module_adapter(module: AnalysisModule) -> AnalysisModuleAdapter:
    """Factory function to create an AnalysisModuleAdapter.
    
    Args:
        module: The concrete AnalysisModule instance to wrap
        
    Returns:
        An AnalysisModuleAdapter instance that implements AnalysisModuleInterface
    """
    return AnalysisModuleAdapter(module)


def load_module_from_config(analysis_module_name: str) -> Optional[AnalysisModuleInterface]:
    """Loads an AnalysisModule by config section name with the provided context.
    Returns None on failure."""

    try:
        module_config = get_config().get_analysis_module_config(analysis_module_name)
    except ValueError as e:
        logging.error(f"analysis module config for {analysis_module_name} not found: {e}")
        return None

    python_module_name = module_config.python_module
    try:
        _module = importlib.import_module(python_module_name)
    except Exception as e:
        logging.error("unable to import module {}: {}".format(python_module_name, e))
        report_exception()
        return None

    python_class_name = module_config.python_class
    try:
        python_module_class = getattr(_module, python_class_name)
    except AttributeError:
        logging.error(
            "class {} does not exist in module {} in analysis module {}".format(
                python_class_name, python_module_name, analysis_module_name
            )
        )
        report_exception()
        return None

    #instance = module_config.instance

    try:
        logging.debug(
            "loading module {}".format(module_config)
        )
        # NOTE instance now comes from the config, it's no longer passed to the constructor
        return create_analysis_module_adapter(python_module_class(module_config))
    except Exception as e:
        logging.error(
            "unable to load analysis module {}: {}".format(
                module_config, e
            )
        )
        report_exception()
        return None