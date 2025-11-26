"""
Engine configuration management.

This module provides the EngineConfiguration class that encapsulates all
configuration options needed for an Engine to operate.
"""

import logging
from multiprocessing import cpu_count
import os
import sys
from typing import Optional

from saq.configuration.config import (
    get_config,
    get_config_value,
    get_config_value_as_boolean,
    get_config_value_as_int,
    get_config_value_as_list,
    get_config_value_as_is,
)
from saq.constants import (
    ANALYSIS_MODE_ANALYSIS,
    CONFIG_ENGINE,
    CONFIG_ENGINE_ALERT_DISPOSITION_CHECK_FREQUENCY,
    CONFIG_ENGINE_ALERTING_ENABLED,
    CONFIG_ENGINE_ANALYSIS_POOLS,
    CONFIG_ENGINE_AUTO_REFRESH_FREQUENCY,
    CONFIG_ENGINE_COPY_ANALYSIS_ON_ERROR,
    CONFIG_ENGINE_COPY_TERMINATED_ANALYSIS_CAUSES,
    CONFIG_ENGINE_DEFAULT_ANALYSIS_MODE,
    CONFIG_ENGINE_EXCLUDED_ANALYSIS_MODES,
    CONFIG_ENGINE_LOCAL_ANALYSIS_MODES,
    CONFIG_ENGINE_NON_DETECTABLE_MODES,
    CONFIG_ENGINE_POOL_SIZE_LIMT,
    CONFIG_ENGINE_TARGET_NODES,
    CONFIG_ENGINE_WORK_DIR,
    CONFIG_GLOBAL,
    CONFIG_GLOBAL_MAXIMUM_ANALYSIS_TIME,
    CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_FAIL_TIME,
    CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_WARNING_TIME,
    CONFIG_GLOBAL_MEMORY_LIMIT_KILL,
    CONFIG_GLOBAL_MEMORY_LIMIT_WARNING,
    G_MODULE_STATS_DIR,
    G_SAQ_NODE,
    LockManagerType,
    WorkloadManagerType,
)
from saq.engine.enums import EngineType
from saq.environment import g, get_data_dir

def compute_pool_size(pool_size_specification: str|int) -> int:
    """A pool size can be specified as a number of workers, or a percentage of the total number of CPU cores.
    Percentages are rounded up to the nearest integer, with a minimum of 1 worker for any non-zero percentage.
    """
    if isinstance(pool_size_specification, int):
        return pool_size_specification

    if pool_size_specification.endswith("%"):
        percentage = int(pool_size_specification[:-1])
        if percentage == 0:
            return 0

        # use max(1, ...) to ensure at least 1 worker for any non-zero percentage
        return max(1, int(cpu_count() * percentage / 100))
    else:
        return int(pool_size_specification)

class EngineConfiguration:
    """Configuration container for Engine operation settings."""
    
    def __init__(
        self,
        local_analysis_modes: Optional[list[str]] = None,
        analysis_pools: Optional[dict[str, str|int]] = None,
        pool_size_limit: Optional[int] = None,
        copy_analysis_on_error: Optional[bool] = None,
        single_threaded_mode: bool = False,
        excluded_analysis_modes: Optional[list[str]] = None,
        target_nodes: Optional[list[str]] = None,
        default_analysis_mode: Optional[str] = None,
        analysis_mode_priority: Optional[str] = None,
        engine_type: EngineType = EngineType.DISTRIBUTED,
    ):
        """Initialize engine configuration.
        
        Args:
            local_analysis_modes: list of analysis modes this engine supports
            analysis_pools: dict mapping analysis mode to pool size
            pool_size_limit: Maximum size of analysis pool if no pools defined
            copy_analysis_on_error: Whether to save copy of RootAnalysis on error
            single_threaded_mode: Whether to run in single-threaded mode for debugging
            excluded_analysis_modes: list of analysis modes this engine does NOT support
            target_nodes: list of target nodes for this engine
            default_analysis_mode: Default analysis mode for invalid analysis modes
            analysis_mode_priority: Analysis mode this worker is primary for
            lock_manager_type: Type of lock manager to use
            workload_manager_type: Type of workload manager to use
            service_config: Service configuration dict
        """
        # Validate input parameters
        self._validate_parameters(
            local_analysis_modes, analysis_pools, pool_size_limit, copy_analysis_on_error,
            single_threaded_mode, excluded_analysis_modes, target_nodes, default_analysis_mode,
            analysis_mode_priority, engine_type
        )
        
        # Basic engine settings
        self.single_threaded_mode = single_threaded_mode
        self.engine_type = engine_type
        self.lock_manager_type = LockManagerType.DISTRIBUTED if engine_type == EngineType.DISTRIBUTED else LockManagerType.LOCAL
        self.workload_manager_type = WorkloadManagerType.DATABASE if engine_type == EngineType.DISTRIBUTED else WorkloadManagerType.MEMORY
        
        # Analysis mode configuration
        self.default_analysis_mode = self._get_default_analysis_mode(default_analysis_mode)
        self.local_analysis_modes = self._get_local_analysis_modes(local_analysis_modes)
        self.excluded_analysis_modes = self._get_excluded_analysis_modes(excluded_analysis_modes)
        self.analysis_mode_priority = analysis_mode_priority
        self.non_detectable_modes = self._get_non_detectable_modes()
        
        # Validate analysis mode configuration
        self._validate_analysis_mode_configuration()
        
        # Analysis pool configuration
        self.analysis_pools = self._get_analysis_pools(analysis_pools)
        self.pool_size_limit = self._get_pool_size_limit(pool_size_limit)
        
        # Time-related configuration
        self.maximum_cumulative_analysis_warning_time = get_config_value_as_int(
            CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_WARNING_TIME
        )
        self.maximum_cumulative_analysis_fail_time = get_config_value_as_int(
            CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_FAIL_TIME
        )
        self.maximum_analysis_time = get_config_value_as_int(
            CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_ANALYSIS_TIME
        )
        self.alert_disposition_check_frequency = get_config_value_as_int(
            CONFIG_ENGINE, CONFIG_ENGINE_ALERT_DISPOSITION_CHECK_FREQUENCY, default=5
        )
        self.auto_refresh_frequency = get_config_value_as_int(
            CONFIG_ENGINE, CONFIG_ENGINE_AUTO_REFRESH_FREQUENCY
        )
        
        # Directory configuration
        self.work_dir = get_config_value(CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR)
        self.stats_dir = os.path.join(g(G_MODULE_STATS_DIR), "ace")
        self.runtime_dir = os.path.join(get_data_dir(), "var", "engine", "ace")
        
        # Feature flags
        self.copy_analysis_on_error = self._get_copy_analysis_on_error(copy_analysis_on_error)
        self.copy_terminated_analysis_causes = get_config_value_as_boolean(
            CONFIG_ENGINE, CONFIG_ENGINE_COPY_TERMINATED_ANALYSIS_CAUSES
        )
        self.alerting_enabled = get_config_value_as_boolean(
            CONFIG_ENGINE, CONFIG_ENGINE_ALERTING_ENABLED, default=True
        )
        
        # Node configuration
        if target_nodes is not None:
            self.target_nodes = target_nodes
        else:
            self.target_nodes = get_config_value_as_list(
                CONFIG_ENGINE,
                CONFIG_ENGINE_TARGET_NODES,
                default=[],
                include_empty=False,
            )

        # translate the special value of LOCAL to whatever the local node is
        self.target_nodes = [
            g(G_SAQ_NODE) if node == "LOCAL" else node for node in self.target_nodes
        ]

        if self.target_nodes:
            logging.debug(
                f"target nodes for {g(G_SAQ_NODE)} is limited to {self.target_nodes}"
            )
        
        # Observable exclusions (initialized empty)
        self.observable_exclusions = {}  # key = o_type, value = [] of values

        # engine limits
        self.memory_limit_kill = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_MEMORY_LIMIT_KILL) * 1024 * 1024
        self.memory_limit_warning = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_MEMORY_LIMIT_WARNING) * 1024 * 1024
    
    def _validate_parameters(
        self, local_analysis_modes, analysis_pools, pool_size_limit, copy_analysis_on_error,
        single_threaded_mode, excluded_analysis_modes, target_nodes, default_analysis_mode,
        analysis_mode_priority, engine_type
    ):
        """Validate input parameters."""
        assert local_analysis_modes is None or isinstance(local_analysis_modes, list), \
            "local_analysis_modes must be a list"
        assert analysis_pools is None or isinstance(analysis_pools, dict), \
            "analysis_pools must be a dict"
        assert pool_size_limit is None or (isinstance(pool_size_limit, int) and pool_size_limit > 0), \
            "pool_size_limit must be an integer greater than 0"
        assert copy_analysis_on_error is None or isinstance(copy_analysis_on_error, bool), \
            "copy_analysis_on_error must be a boolean"
        assert isinstance(single_threaded_mode, bool), \
            "single_threaded_mode must be a boolean"
        assert excluded_analysis_modes is None or isinstance(excluded_analysis_modes, list), \
            "excluded_analysis_modes must be a list"
        assert target_nodes is None or isinstance(target_nodes, list), \
            "target_nodes must be a list"
        assert default_analysis_mode is None or isinstance(default_analysis_mode, str), \
            "default_analysis_mode must be a string"
        assert analysis_mode_priority is None or isinstance(analysis_mode_priority, str), \
            "analysis_mode_priority must be a string"
        assert engine_type in EngineType, \
            "engine_type must be a valid EngineType"
    
    def _get_default_analysis_mode(self, default_analysis_mode: Optional[str]) -> str:
        """Get the default analysis mode."""
        if default_analysis_mode:
            result = default_analysis_mode
        else:
            result = get_config_value(
                CONFIG_ENGINE,
                CONFIG_ENGINE_DEFAULT_ANALYSIS_MODE,
                default=ANALYSIS_MODE_ANALYSIS,
            )
        
        # Validate the default analysis mode exists in config
        if "analysis_mode_{}".format(result) not in get_config():
            logging.error(
                "engine.default_analysis_mode value {} invalid (no such analysis mode defined)".format(result)
            )
        
        return result
    
    def _get_local_analysis_modes(self, local_analysis_modes: Optional[list[str]]) -> list[str]:
        """Get the local analysis modes."""
        if local_analysis_modes is not None:
            result = local_analysis_modes
        else:
            result = get_config_value_as_list(
                CONFIG_ENGINE,
                CONFIG_ENGINE_LOCAL_ANALYSIS_MODES,
                default=[],
                include_empty=False,
            )
        
        if result:
            logging.debug(f"analysis modes {','.join(result)} supported by this engine")
            
            # Ensure default analysis mode is included
            if self.default_analysis_mode not in result:
                result.append(self.default_analysis_mode)
                logging.debug(
                    f"added default analysis mode {self.default_analysis_mode} to list of supported modes"
                )
        
        return result
    
    def _get_excluded_analysis_modes(self, excluded_analysis_modes: Optional[list[str]]) -> list[str]:
        """Get the excluded analysis modes."""
        if excluded_analysis_modes is not None:
            result = excluded_analysis_modes
        else:
            result = get_config_value_as_list(
                CONFIG_ENGINE,
                CONFIG_ENGINE_EXCLUDED_ANALYSIS_MODES,
                default=[],
                include_empty=False,
            )
        
        if result:
            for mode in result:
                logging.debug(f"analysis mode {mode} is excluded from analysis by this engine")
        
        return result
    
    def _get_non_detectable_modes(self) -> list[str]:
        """Get the list of non-detectable analysis modes."""
        return get_config_value_as_list(
            CONFIG_ENGINE,
            CONFIG_ENGINE_NON_DETECTABLE_MODES,
            default=[],
            include_empty=False,
        )
    
    def _validate_analysis_mode_configuration(self):
        """Validate analysis mode configuration."""
        if self.excluded_analysis_modes and self.local_analysis_modes:
            logging.error("both excluded_analysis_modes and local_analysis_modes are enabled for the engine")
            logging.error("this is a misconfiguration error")
            sys.exit(1)
    
    def _filter_valid_analysis_pools(self, analysis_pools: dict[str, int]) -> dict[str, int]:
        """Filter the analysis pools to only include valid modes."""
        result = {}
        for analysis_mode, count in analysis_pools.items():
            # Validate that pool is for a supported mode
            if self.local_analysis_modes and analysis_mode not in self.local_analysis_modes:
                logging.error(
                    "attempted to add analysis pool for mode {} "
                    "which is not supported by this engine ({})".format(
                        analysis_mode, self.local_analysis_modes
                    )
                )
                continue

            result[analysis_mode] = count

        return result
    
    def _get_analysis_pools(self, analysis_pools: Optional[dict[str, str|int]]) -> dict[str, int]:
        """Get the analysis pools configuration."""
        if analysis_pools is None:
            analysis_pools = get_config_value_as_is(CONFIG_ENGINE, CONFIG_ENGINE_ANALYSIS_POOLS, {})

        result = {}
        for analysis_mode, value in analysis_pools.items():
            result[analysis_mode] = compute_pool_size(value)

        return self._filter_valid_analysis_pools(result)
    
    def _get_pool_size_limit(self, pool_size_limit: Optional[int]) -> Optional[int]:
        """Get the pool size limit."""
        if pool_size_limit is not None:
            return pool_size_limit
        
        return get_config_value_as_int(CONFIG_ENGINE, CONFIG_ENGINE_POOL_SIZE_LIMT)
    
    def _get_copy_analysis_on_error(self, copy_analysis_on_error: Optional[bool]) -> bool:
        """Get the copy analysis on error setting."""
        if copy_analysis_on_error is not None:
            return copy_analysis_on_error
        
        return get_config_value_as_boolean(CONFIG_ENGINE, CONFIG_ENGINE_COPY_ANALYSIS_ON_ERROR)
    
    def add_analysis_pool(self, analysis_mode: str, count: int):
        """Add an analysis pool for the given mode and count."""
        # Validate that pool is for a supported mode
        if self.local_analysis_modes and analysis_mode not in self.local_analysis_modes:
            logging.error(
                "attempted to add analysis pool for mode {} "
                "which is not supported by this engine ({})".format(
                    analysis_mode, self.local_analysis_modes
                )
            )
            return
        
        self.analysis_pools[analysis_mode] = count
        logging.debug(f"added analysis pool mode {analysis_mode} count {count}")
    
    def ensure_directories_exist(self):
        """Ensure required directories exist."""
        for directory in [self.stats_dir, self.work_dir, self.runtime_dir]:
            if directory:
                os.makedirs(directory, exist_ok=True) 