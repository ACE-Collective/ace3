"""
Configuration management for the analysis engine.
"""

import logging
from typing import Optional, Set, Union

from saq.configuration.config import get_analysis_module_config, get_config
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.module_loader import ModuleLoader
from saq.modules.interfaces import AnalysisModuleInterface


class ConfigurationManager:
    """Manages all configuration-related responsibilities for the analysis engine.
    
    This class is responsible for:
    - Loading and parsing analysis module configurations
    - Building analysis mode to module mappings
    - Handling module enablement/disablement
    - Managing locally enabled modules and manual mappings
    """
    
    def __init__(self, config: EngineConfiguration):
        """Initialize the configuration manager.
        
        Args:
            config: The engine configuration
        """
        self.config = config
        
        # Module storage
        self.analysis_modules: list[AnalysisModuleInterface] = []
        self.analysis_mode_mapping: dict[str, list[AnalysisModuleInterface]] = {}
        self.analysis_module_name_mapping: dict[str, AnalysisModuleInterface] = {}
        # module name -> list of resolved declared-dependency modules (see build_and_validate_dependency_graph)
        self.declared_dependency_mapping: dict[str, list[AnalysisModuleInterface]] = {}
        
        # Local overrides for testing
        self.locally_enabled_modules: list[str] = []
        self.locally_mapped_analysis_modes: dict[str, Set[str]] = {}
        
        # Initialize module loader
        self.module_loader = ModuleLoader(
            local_analysis_modes=self.config.local_analysis_modes,
            excluded_analysis_modes=self.config.excluded_analysis_modes,
            locally_enabled_modules=self.locally_enabled_modules,
            locally_mapped_analysis_modes=self.locally_mapped_analysis_modes
        )
        
        self._initialize_mappings()
    
    def _initialize_mappings(self):
        """Initialize the analysis mode mapping to default state."""
        self.analysis_modules.clear()
        self.analysis_mode_mapping = {self.config.default_analysis_mode: []}
        self.analysis_module_name_mapping.clear()
        self.declared_dependency_mapping.clear()
    
    def is_analysis_mode_supported(self, analysis_mode: str) -> bool:
        """Check if the given analysis mode is supported by this engine."""
        return self.module_loader.is_analysis_mode_supported(analysis_mode)

    def get_analysis_module_by_name(self, name: str) -> Optional[AnalysisModuleInterface]:
        """Get an analysis module by its name (config section name)."""
        return self.analysis_module_name_mapping.get(name)
    
    def enable_module(self, analysis_module_name: str, analysis_mode: Union[str, list[str], None] = None):
        """Enable a specific module for local testing.
        
        Args:
            analysis_module_name: Analysis module name
            analysis_mode: Analysis mode(s) to map the module to
        """
        if analysis_module_name in get_config().disabled_modules:
            logging.info(f"skipping disabled module {analysis_module_name}")
            return
        
        self.locally_enabled_modules.append(analysis_module_name)
        
        if analysis_mode is not None:
            if isinstance(analysis_mode, str):
                analysis_modes = (analysis_mode,)
            else:
                analysis_modes = analysis_mode
            
            for mode in analysis_modes:
                if mode not in self.locally_mapped_analysis_modes:
                    self.locally_mapped_analysis_modes[mode] = set()
                self.locally_mapped_analysis_modes[mode].add(analysis_module_name)
        
        # Update module loader with new local settings
        self.module_loader = ModuleLoader(
            local_analysis_modes=self.config.local_analysis_modes,
            excluded_analysis_modes=self.config.excluded_analysis_modes,
            locally_enabled_modules=self.locally_enabled_modules,
            locally_mapped_analysis_modes=self.locally_mapped_analysis_modes
        )
    
    def add_analysis_module(self,
                           analysis_module: AnalysisModuleInterface,
                           analysis_modes: Optional[list[str]] = None):
        """Add an analysis module to the configuration.
        
        Args:
            analysis_module: The module to add
            analysis_modes: list of analysis modes the module should run in
        """
        if not analysis_modes:
            logging.debug(
                f"no analysis modes specified for {analysis_module} -- use default {self.config.default_analysis_mode}"
            )
            analysis_modes = [self.config.default_analysis_mode]
        
        # Verify module environment
        try:
            analysis_module.verify_environment()
        except Exception as e:
            logging.exception(f"analysis module {analysis_module} failed environment verification: {e}")
            raise e
        
        # Get module configuration
        module_config = analysis_module.config

        #module_config = self._get_analysis_module_config(analysis_module)
        if module_config is None:
            logging.error(f"unable to find configuration for analysis module {analysis_module}")
            return

        analysis_module_name = module_config.name
        
        # Store the module
        self.analysis_modules.append(analysis_module)
        self.analysis_module_name_mapping[analysis_module_name] = analysis_module
        
        # Map to analysis modes
        for mode in analysis_modes:
            if mode not in self.analysis_mode_mapping:
                self.analysis_mode_mapping[mode] = []
            
            if analysis_module not in self.analysis_mode_mapping[mode]:
                self.analysis_mode_mapping[mode].append(analysis_module)
        
        logging.info(f"loaded analysis module {analysis_module} name {analysis_module_name}")
    
    def _get_analysis_module_config(self, module: AnalysisModuleInterface):
        """Get the configuration section for an analysis module."""
        return get_analysis_module_config(module.name)
    
    def load_modules(self) -> None:
        """Load all configured analysis modules and build the analysis mode mapping."""
        self._initialize_mappings()
        
        # Use module loader to get all loaded modules
        loaded_modules = self.module_loader.load_modules()
        
        # Add each loaded module to our configuration
        for section_name, (module, analysis_modes) in loaded_modules.items():
            self.add_analysis_module(module, analysis_modes)
        
        # Ensure all supported analysis modes have entries in the mapping, even if they have no modules
        for analysis_mode_config in get_config().analysis_modes:
            analysis_mode = analysis_mode_config.name
            if self.is_analysis_mode_supported(analysis_mode):
                if analysis_mode not in self.analysis_mode_mapping:
                    self.analysis_mode_mapping[analysis_mode] = []

        # resolve declared dependencies and validate the graph is acyclic (fail fast at startup)
        self.build_and_validate_dependency_graph()

    def build_and_validate_dependency_graph(self) -> None:
        """Resolve declared analysis-module dependencies and validate the graph is acyclic.

        Declared dependencies (the config `dependencies` list) reference other analysis
        modules by their config name. Each is resolved to the loaded module instance and
        cached in self.declared_dependency_mapping so the runtime seeding hook needs no
        re-resolution. Dependencies that cannot be resolved (disabled or absent in this
        engine's loaded set) are treated as vacuously satisfied (soft-skip) and only
        logged. A declared dependency cycle raises RuntimeError so the engine fails fast
        at startup rather than surfacing a circular dependency mid-analysis.
        """
        self.declared_dependency_mapping = {}

        for module in self.analysis_modules:
            resolved = []
            for dependency_name in module.config.dependencies:
                target = self.analysis_module_name_mapping.get(dependency_name)
                if target is None:
                    logging.warning(
                        "analysis module %s declares dependency on %s which is not loaded "
                        "(disabled or missing) -- treating as satisfied",
                        module.config.name, dependency_name,
                    )
                    continue

                resolved.append(target)

            self.declared_dependency_mapping[module.config.name] = resolved

        self._check_declared_dependency_cycles()

    def _check_declared_dependency_cycles(self) -> None:
        """Depth-First Search over the resolved declared-dependency graph, raising RuntimeError on a cycle."""
        # visit_state: unvisited (absent) -> 1 (on current path) -> 2 (fully explored)
        visit_state: dict[str, int] = {}

        def visit(name: str, path: list[str]) -> None:
            visit_state[name] = 1
            path.append(name)
            for target in self.declared_dependency_mapping.get(name, []):
                target_name = target.config.name
                if visit_state.get(target_name) == 1:
                    cycle = path[path.index(target_name):] + [target_name]
                    raise RuntimeError(
                        "CIRCULAR DEPENDENCY ERROR in declared analysis module dependencies: {}".format(
                            " -> ".join(cycle)
                        )
                    )
                if visit_state.get(target_name, 0) == 0:
                    visit(target_name, path)

            path.pop()
            visit_state[name] = 2

        for name in list(self.declared_dependency_mapping.keys()):
            if visit_state.get(name, 0) == 0:
                visit(name, [])

    def get_declared_dependencies(self, module_name: str) -> list[AnalysisModuleInterface]:
        """Returns the resolved declared-dependency modules for the given module name."""
        return self.declared_dependency_mapping.get(module_name, [])

    def get_analysis_modules_by_mode(self, analysis_mode: Optional[str]=None) -> list[AnalysisModuleInterface]:
        """Get analysis modules for a specific analysis mode, sorted by config section name."""
        if analysis_mode is None:
            result = self.analysis_mode_mapping[self.config.default_analysis_mode]
        else:
            try:
                result = self.analysis_mode_mapping[analysis_mode]
            except KeyError:
                logging.warning(f"invalid analysis mode {analysis_mode} - defaulting to {self.config.default_analysis_mode}")
                result = self.analysis_mode_mapping[self.config.default_analysis_mode]
        
        return sorted(result, key=lambda x: x.config.name)
    
    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled by its ID."""
        return self.get_analysis_module_by_name(module_name) is not None 
