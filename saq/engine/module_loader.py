"""
Module loading functionality for the analysis engine.

This module provides the ModuleLoader class that handles all
module loading responsibilities that were previously embedded
in the ConfigurationManager class, following the Single Responsibility Principle.
"""

import logging
from typing import Dict, List, Optional, Set

from saq.configuration.config import (
    get_config,
)
from saq.configuration.schema import AnalysisModeConfig
from saq.modules.adapter import load_module_from_config
from saq.modules.interfaces import AnalysisModuleInterface
from saq.error import report_exception


class ModuleLoader:
    """Handles loading analysis modules from configuration.
    
    This class is responsible for:
    - Finding all module sections that should be loaded
    - Building analysis mode to module section mappings
    - Loading individual modules from configuration
    - Determining which analysis modes modules should run in
    """
    
    def __init__(self, 
                 local_analysis_modes: List[str],
                 excluded_analysis_modes: List[str],
                 locally_enabled_modules: List[str],
                 locally_mapped_analysis_modes: Dict[str, Set[str]]):
        """Initialize the module loader.
        
        Args:
            local_analysis_modes: List of analysis modes supported locally
            excluded_analysis_modes: List of analysis modes to exclude
            locally_enabled_modules: List of modules enabled for local testing
            locally_mapped_analysis_modes: Local analysis mode mappings for testing
        """
        self.local_analysis_modes = local_analysis_modes
        self.excluded_analysis_modes = excluded_analysis_modes
        self.locally_enabled_modules = locally_enabled_modules
        self.locally_mapped_analysis_modes = locally_mapped_analysis_modes
    
    def load_modules(self) -> Dict[str, tuple[AnalysisModuleInterface, List[str]]]:
        """Load all configured analysis modules and return them with their analysis modes.
        
        Returns:
            Dict mapping section names to (module, analysis_modes) tuples
        """
        # Build analysis mode to module section mapping
        analysis_mode_section_names_map = self._build_analysis_mode_mapping()
        
        # Get all unique module sections to load
        analysis_module_sections = set()
        for mode_sections in analysis_mode_section_names_map.values():
            analysis_module_sections.update(mode_sections)
        
        # Add locally enabled modules
        analysis_module_sections.update(self.locally_enabled_modules)
        
        logging.debug(f"loading {len(analysis_module_sections)} analysis modules...")
        
        # Load each module
        loaded_modules = {}
        for section_name in analysis_module_sections:
            if not self._should_load_module(section_name):
                continue
            
            module = self._load_single_module(section_name)
            if module is None:
                continue
            
            # Determine which analysis modes this module runs in
            analysis_modes = []
            for mode, config_sections in analysis_mode_section_names_map.items():
                if section_name in config_sections:
                    analysis_modes.append(mode)
            
            loaded_modules[section_name] = (module, analysis_modes)
        
        logging.debug(f"finished loading {len(loaded_modules)} modules")
        return loaded_modules
    
    def is_analysis_mode_supported(self, analysis_mode: str) -> bool:
        """Check if the given analysis mode is supported."""
        if analysis_mode in self.excluded_analysis_modes:
            return False
        
        # TODO document this logic
        if not self.local_analysis_modes:
            return True
            
        return analysis_mode in self.local_analysis_modes
    
    def _build_analysis_mode_mapping(self) -> Dict[str, Set[str]]:
        """Build mapping of analysis modes to their module names."""
        analysis_mode_module_names_map: Dict[str, Set[str]] = {}

        unsupported_modes = []
        
        # Process each analysis mode configuration
        for analysis_mode_config in get_config().analysis_modes:
            analysis_mode = analysis_mode_config.name
            
            # Check if mode is supported
            if not self.is_analysis_mode_supported(analysis_mode):
                unsupported_modes.append(analysis_mode)
                continue
            
            # maps the analysis mode to the set of modules that should run in that mode
            analysis_mode_module_names_map[analysis_mode] = set()
            
            # each analysis mode has a list of module groups that should be included
            self._add_modules_from_groups(analysis_mode_config, analysis_mode_module_names_map)
            
            # as well as a list of individual modules that should be included
            self._add_individual_modules(analysis_mode_config, analysis_mode_module_names_map)
            
            # Add locally mapped modules
            self._add_locally_mapped_modules(analysis_mode_config, analysis_mode_module_names_map)
        
        if unsupported_modes:
            logging.info(
                f"analysis modes {','.join(unsupported_modes)} is not supported by the engine "
                f"(local analysis modes: {','.join(self.local_analysis_modes) if self.local_analysis_modes else 'none'}) "
                f"(excluded analysis modes: {','.join(self.excluded_analysis_modes) if self.excluded_analysis_modes else 'none'})"
            )

        return analysis_mode_module_names_map
    
    def _add_modules_from_groups(self, analysis_mode_config: AnalysisModeConfig, 
                                analysis_mode_module_names_map: Dict[str, Set[str]]):
        """Add modules from module groups to the analysis mode mapping."""
        for module_group_name in analysis_mode_config.module_groups:
            module_group_config = get_config().get_module_group_config(module_group_name)
            for module_name in module_group_config.modules:
                # make sure the module exists
                get_config().get_analysis_module_config(module_name)
                analysis_mode_module_names_map[analysis_mode_config.name].add(module_name)
    
    def _add_individual_modules(self, analysis_mode_config: AnalysisModeConfig,
                               analysis_mode_module_names_map: Dict[str, Set[str]]):
        """Add or remove individual modules for an analysis mode."""
        # add any enabled modules
        for key_name in analysis_mode_config.enabled_modules:
            # make sure the referenced module exists
            get_config().get_analysis_module_config(key_name)
            analysis_mode_module_names_map[analysis_mode_config.name].add(key_name)

        # and then remove any disabled modules
        for key_name in analysis_mode_config.disabled_modules:
            # make sure the referenced module exists
            get_config().get_analysis_module_config(key_name)
            analysis_mode_module_names_map[analysis_mode_config.name].discard(key_name)
    
    def _add_locally_mapped_modules(self, analysis_mode_config: AnalysisModeConfig, analysis_mode_module_names_map: Dict[str, Set[str]]):
        """Add locally mapped modules for testing."""
        assert isinstance(analysis_mode_config, AnalysisModeConfig)
        assert isinstance(analysis_mode_module_names_map, dict)

        if analysis_mode_config.name in self.locally_mapped_analysis_modes:
            for analysis_module_name in self.locally_mapped_analysis_modes[analysis_mode_config.name]:
                logging.debug(f"manual map for mode {analysis_mode_config.name} to {analysis_module_name}")
                analysis_mode_module_names_map[analysis_mode_config.name].add(analysis_module_name)
    
    def _should_load_module(self, analysis_module_name: str) -> bool:
        """Determine if a module should be loaded based on configuration."""
        if not self.locally_enabled_modules:
            module_config = get_config().get_analysis_module_config(analysis_module_name)
            # is this module disabled?
            if not module_config.enabled:
                logging.debug(f"{analysis_module_name} is disabled")
                return False
            
            # is this module disabled globally?
            if analysis_module_name in get_config().disabled_modules:
                logging.debug(f"analysis module {analysis_module_name} disabled (globally)")
                return False
        else:
            # Check local enablement
            if analysis_module_name not in self.locally_enabled_modules:
                return False
        
        return True
    
    def _load_single_module(self, analysis_module_name: str) -> Optional[AnalysisModuleInterface]:
        """Load a single analysis module from configuration."""
        try:
            analysis_module = load_module_from_config(analysis_module_name)
            if analysis_module is None:
                logging.warning(f"load_module({analysis_module_name}) failed to return a value - skipping")
                return None
            
            return analysis_module
            
        except Exception as e:
            logging.error(f"failed to load analysis module {analysis_module_name}: {e}")
            report_exception()
            return None 